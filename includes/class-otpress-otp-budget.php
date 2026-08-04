<?php
defined('ABSPATH') || exit;

/**
 * Spend guard for the paid OTP channels (Firebase SMS, WhatsApp Cloud API).
 *
 * Both cost real money per message, which makes them a standing invitation to
 * SMS pumping: an attacker cycles through thousands of numbers — often on
 * expensive destinations they profit from — and every request bills us. A
 * per-number cap does nothing against that, because each number is new.
 *
 * So the limits stack, cheapest signal first, and the global ceiling is the
 * one that actually guarantees the bill can't run away:
 *
 *   1. country       — only where we do business; elsewhere email only
 *   2. per number    — monthly allowance
 *   3. unverified    — codes requested but never used
 *   4. per IP        — daily
 *   5. per subnet    — daily (/24 v4, /48 v6), for rotating addresses
 *   6. global        — daily and monthly hard ceilings
 *
 * Nothing here blocks anyone from their account: a refusal routes them to the
 * free email code. Paying customers skip every per-identity limit — locking a
 * real customer out to save a fraction of a cent is a bad trade — but the
 * global ceiling still applies, because that one is the fuse.
 */
class OTPress_OTP_Budget {

    private const DEFAULTS = [
        'otp_monthly_allowance'   => 8,    // per phone number, per month
        'otp_daily_ip'            => 5,    // per IP, per day
        'otp_daily_subnet'        => 15,   // per /24 (v4) or /48 (v6), per day
        'otp_daily_global'        => 300,  // whole site, per day
        'otp_monthly_global'      => 5000, // whole site, per month
        'otp_max_unverified'      => 3,    // codes sent to a number with none used
    ];

    /**
     * Destinations where a paid code is not worth sending: satellite and
     * premium ranges that cost multiples of a normal message, plus the
     * countries most consistently reported as SMS-pumping targets — where
     * the fraud pays the local operator, so traffic is manufactured on
     * purpose. We have no meaningful order history in any of them.
     *
     * This is a starting list, not gospel: carrier rates move, so treat
     * `otpress_wa_cost_stats` (real billed messages reported by Meta's
     * webhook) as the source of truth and adjust with the filter below.
     */
    private const BLOCKED_DIAL_CODES = [
        // Satellite / premium ranges — the classic money pit
        '870', '875', '876', '877', '878', '879', // Inmarsat
        '881', '882', '883',                      // Iridium / global mobile
        '888', '979',                             // shared-cost / premium
        // Africa
        '252', '251', '249', '211', '235', '227', '223', '226', '224',
        '232', '231', '236', '243', '242', '241', '237', '234', '233',
        '225', '221', '220', '222', '229', '228', '263', '260', '265',
        '258', '261', '255', '256', '254', '250', '257', '244', '218',
        '269', '245', '238', '239', '240',
        // South and Central Asia
        '93', '92', '880', '94', '977', '95', '856', '855', '998',
        '992', '996', '993', '976',
        // Middle East (high-fraud OTP corridors)
        '967', '963', '964', '98', '970',
        // Caucasus
        '994', '374', '995',
    ];

    /**
     * May we spend a paid message on this number right now?
     *
     * @param string $phone   E.164 number.
     * @param string $channel 'sms' | 'whatsapp' (reported back for logging).
     * @return true|WP_Error  WP_Error carries code otpress_otp_budget.
     */
    public static function check(string $phone, string $channel = 'sms') {
        // The global ceilings are the fuse: they apply to everyone, always.
        if (self::limit('otp_daily_global') > 0
            && self::count('global_' . self::day()) >= self::limit('otp_daily_global')) {
            return self::refuse($phone, $channel, 'global_daily');
        }
        if (self::limit('otp_monthly_global') > 0
            && self::count('global_' . self::month()) >= self::limit('otp_monthly_global')) {
            return self::refuse($phone, $channel, 'global_monthly');
        }

        $user_id = self::resolve_user($phone);
        $paying  = $user_id && self::is_paying_customer($user_id);

        // A country we don't sell to never justifies a paid message, whoever
        // is asking.
        if (!self::country_allowed($phone)) {
            return self::refuse($phone, $channel, 'country', $user_id);
        }

        if ($paying) {
            return true;
        }

        if (self::limit('otp_monthly_allowance') > 0
            && self::count('num_' . self::month() . '_' . md5($phone)) >= self::limit('otp_monthly_allowance')) {
            return self::refuse($phone, $channel, 'number', $user_id);
        }

        // Codes sent to a number that never gets used are the signature of
        // pumping — the attacker only wants the message to be billed.
        if (self::limit('otp_max_unverified') > 0
            && self::count('unver_' . md5($phone)) >= self::limit('otp_max_unverified')) {
            return self::refuse($phone, $channel, 'unverified', $user_id);
        }

        $ip = self::client_ip();
        if ('' !== $ip) {
            if (self::limit('otp_daily_ip') > 0
                && self::count('ip_' . self::day() . '_' . md5($ip)) >= self::limit('otp_daily_ip')) {
                return self::refuse($phone, $channel, 'ip', $user_id);
            }
            $subnet = self::subnet($ip);
            if ('' !== $subnet && self::limit('otp_daily_subnet') > 0
                && self::count('net_' . self::day() . '_' . md5($subnet)) >= self::limit('otp_daily_subnet')) {
                return self::refuse($phone, $channel, 'subnet', $user_id);
            }
        }

        return true;
    }

    /** Count a paid send against every bucket it belongs to. */
    public static function record(string $phone): void {
        self::bump('global_' . self::day(), 2 * DAY_IN_SECONDS);
        self::bump('global_' . self::month(), 45 * DAY_IN_SECONDS);
        self::bump('num_' . self::month() . '_' . md5($phone), 45 * DAY_IN_SECONDS);
        self::bump('unver_' . md5($phone), 7 * DAY_IN_SECONDS);

        $ip = self::client_ip();
        if ('' !== $ip) {
            self::bump('ip_' . self::day() . '_' . md5($ip), 2 * DAY_IN_SECONDS);
            $subnet = self::subnet($ip);
            if ('' !== $subnet) {
                self::bump('net_' . self::day() . '_' . md5($subnet), 2 * DAY_IN_SECONDS);
            }
        }
    }

    /**
     * A code was actually used, so this number is a real person: clear its
     * unverified streak.
     */
    public static function record_verified(string $phone): void {
        delete_transient('otpress_budget_unver_' . md5($phone));
    }

    /** Paid sends used by this number this month (for the account UI). */
    public static function used(string $phone): int {
        return self::count('num_' . self::month() . '_' . md5($phone));
    }

    /** Everything spent site-wide today / this month. */
    public static function spent(): array {
        return [
            'today' => self::count('global_' . self::day()),
            'month' => self::count('global_' . self::month()),
            'limits' => [
                'today' => self::limit('otp_daily_global'),
                'month' => self::limit('otp_monthly_global'),
            ],
        ];
    }

    public static function allowance(): int {
        return self::limit('otp_monthly_allowance');
    }

    /**
     * A configured limit. Every one can be overridden with the matching
     * OTPRESS_* constant or filter; 0 disables that layer.
     */
    public static function limit(string $key): int {
        $configured = OTPress_Settings::get($key);
        $value = '' === $configured
            ? (self::DEFAULTS[$key] ?? 0)
            : (int) $configured;

        /**
         * Filter one of the OTP spend limits.
         *
         * @param int    $value
         * @param string $key
         */
        return (int) apply_filters('otpress_otp_limit', $value, $key);
    }

    /** Is a paid code allowed for this destination? */
    public static function country_allowed(string $phone): bool {
        return '' === self::blocked_prefix($phone);
    }

    /**
     * The blocked calling-code prefix this number matches, or '' when the
     * destination is fine. Longest prefix wins so a specific range beats a
     * broad one.
     */
    public static function blocked_prefix(string $phone): string {
        $codes = apply_filters('otpress_otp_blocked_dial_codes', self::BLOCKED_DIAL_CODES);
        if (empty($codes)) {
            return '';
        }
        $digits = ltrim(preg_replace('/\D/', '', $phone), '+');
        usort($codes, function ($a, $b) { return strlen($b) - strlen($a); });
        foreach ($codes as $code) {
            if (0 === strpos($digits, (string) $code)) {
                return (string) $code;
            }
        }
        return '';
    }

    /** Calling codes the front end should hide the paid tabs for. */
    public static function blocked_dial_codes(): array {
        return array_values(apply_filters('otpress_otp_blocked_dial_codes', self::BLOCKED_DIAL_CODES));
    }

    private static function refuse(string $phone, string $channel, string $reason, int $user_id = 0) {
        /**
         * Fires whenever a paid OTP is refused, so spikes can be watched.
         *
         * @param string $reason  country|number|unverified|ip|subnet|global_daily|global_monthly
         * @param string $phone
         * @param string $channel
         */
        do_action('otpress_otp_refused', $reason, $phone, $channel);

        return new WP_Error(
            'otpress_otp_budget',
            __('We could not send the code to your phone. Please use your email instead.', 'otpress'),
            [
                'status'  => 429,
                'channel' => $channel,
                'reason'  => $reason,
                'email'   => $user_id ? self::mask_email((string) get_userdata($user_id)->user_email) : '',
            ]
        );
    }

    /**
     * Has this account ever paid? Any completed order counts — the point is to
     * separate real customers from accounts that only consume codes.
     */
    private static function is_paying_customer(int $user_id): bool {
        if (!function_exists('wc_get_customer_order_count')) {
            return false;
        }
        if (wc_get_customer_order_count($user_id) > 0) {
            return true;
        }
        return function_exists('wc_get_customer_total_spent')
            && (float) wc_get_customer_total_spent($user_id) > 0;
    }

    private static function resolve_user(string $phone): int {
        if (!class_exists('OTPress_User_Mapper')) {
            return 0;
        }
        $user = OTPress_User_Mapper::find_by_phone($phone);
        return $user instanceof WP_User ? (int) $user->ID : 0;
    }

    /**
     * The visitor's address. Behind Cloudflare the socket address is always
     * Cloudflare's, so CF-Connecting-IP is the only useful one.
     */
    private static function client_ip(): string {
        foreach (['HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR'] as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = trim((string) $_SERVER[$key]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '';
    }

    /** /24 for IPv4, /48 for IPv6 — the block an attacker rotates within. */
    private static function subnet(string $ip): string {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $groups = explode(':', $ip);
            return implode(':', array_slice($groups, 0, 3)) . '::/48';
        }
        return '';
    }

    /** j***@example.com — enough to recognise, not enough to harvest. */
    private static function mask_email(string $email): string {
        $at = strpos($email, '@');
        if (false === $at || $at < 1) {
            return '';
        }
        return substr($email, 0, 1) . str_repeat('*', max(1, $at - 1)) . substr($email, $at);
    }

    private static function count(string $bucket): int {
        return (int) get_transient('otpress_budget_' . $bucket);
    }

    private static function bump(string $bucket, int $ttl): void {
        $key = 'otpress_budget_' . $bucket;
        set_transient($key, ((int) get_transient($key)) + 1, $ttl);
    }

    private static function day(): string {
        return gmdate('Y_m_d');
    }

    private static function month(): string {
        return gmdate('Y_m');
    }
}
