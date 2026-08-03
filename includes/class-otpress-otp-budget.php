<?php
defined('ABSPATH') || exit;

/**
 * Spend guard for the paid OTP channels (Firebase SMS, WhatsApp Cloud API).
 *
 * Both cost real money per message, and a small number of people can burn a
 * lot of them — retrying, farming codes, or just hoarding accounts. Past a
 * monthly allowance the paid channels are refused for that number and the
 * caller is told to use the free email code instead.
 *
 * Paying customers are never throttled: someone who has actually bought
 * something is worth far more than the few cents their codes cost, and
 * locking them out of their own account to save a message is a bad trade.
 */
class OTPress_OTP_Budget {

    /** Paid sends allowed per phone number per calendar month. */
    private const DEFAULT_ALLOWANCE = 8;

    /**
     * Is this number allowed one more paid OTP?
     *
     * @param string $phone   E.164 number.
     * @param string $channel 'sms' | 'whatsapp' (for the log only).
     * @return true|WP_Error  WP_Error carries code otpress_otp_budget.
     */
    public static function check(string $phone, string $channel = 'sms') {
        $allowance = self::allowance();
        if ($allowance <= 0) {
            return true; // guard disabled
        }

        $user_id = self::resolve_user($phone);
        if ($user_id && self::is_paying_customer($user_id)) {
            return true;
        }

        if (self::used($phone) < $allowance) {
            return true;
        }

        return new WP_Error(
            'otpress_otp_budget',
            __('We could not send the code to your phone. Please use your email instead.', 'otpress'),
            [
                'status'  => 429,
                'channel' => $channel,
                'email'   => $user_id ? self::mask_email((string) get_userdata($user_id)->user_email) : '',
            ]
        );
    }

    /** Count a paid send against this month's allowance. */
    public static function record(string $phone): void {
        $key = self::key($phone);
        $n   = (int) get_transient($key);
        // Expire at the end of next month so the counter self-cleans; the
        // month is part of the key, so a stale value can never leak forward.
        set_transient($key, $n + 1, 45 * DAY_IN_SECONDS);
    }

    /** Paid sends already used by this number this month. */
    public static function used(string $phone): int {
        return (int) get_transient(self::key($phone));
    }

    public static function allowance(): int {
        $configured = OTPress_Settings::get('otp_monthly_allowance');
        $allowance  = '' === $configured ? self::DEFAULT_ALLOWANCE : (int) $configured;

        /**
         * Filter the monthly paid-OTP allowance per phone number.
         * Return 0 to disable the guard entirely.
         *
         * @param int $allowance
         */
        return (int) apply_filters('otpress_otp_monthly_allowance', $allowance);
    }

    /**
     * Has this account ever paid? Any completed/processing order counts — the
     * point is to separate real customers from accounts that only ever consume
     * verification codes.
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

    /** The account that owns this phone number, if any. */
    private static function resolve_user(string $phone): int {
        if (!class_exists('OTPress_User_Mapper')) {
            return 0;
        }
        $user = OTPress_User_Mapper::find_by_phone($phone);
        return $user instanceof WP_User ? (int) $user->ID : 0;
    }

    /** j***@example.com — enough to recognise, not enough to harvest. */
    private static function mask_email(string $email): string {
        $at = strpos($email, '@');
        if (false === $at || $at < 1) {
            return '';
        }
        return substr($email, 0, 1) . str_repeat('*', max(1, $at - 1)) . substr($email, $at);
    }

    private static function key(string $phone): string {
        return 'otpress_budget_' . gmdate('Y_m') . '_' . md5($phone);
    }
}
