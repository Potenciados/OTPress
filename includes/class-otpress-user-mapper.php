<?php
defined('ABSPATH') || exit;

/**
 * Maps verified Firebase claims to a WordPress user, creating one when
 * allowed. Identity precedence:
 *
 *  1. Verified phone number (`phone_number` claim) matched against the
 *     configured usermeta keys — includes Digits meta in compat mode.
 *  2. Email, but ONLY when `email_verified` is true. An unverified email
 *     claim must never select an existing account: providers that do not
 *     verify email would otherwise allow account takeover by registering
 *     someone else's address.
 *  3. Otherwise a new customer account is created (if registration is open).
 */
class OTPress_User_Mapper {

    /**
     * @param array $claims Verified Firebase token claims.
     * @param array $profile Optional client-supplied profile hints (display name).
     * @return WP_User|WP_Error
     */
    public static function resolve(array $claims, array $profile = [], bool $auto_create = true) {
        $phone          = self::e164((string) ($claims['phone_number'] ?? ''));
        $email          = sanitize_email((string) ($claims['email'] ?? ''));
        $email_verified = !empty($claims['email_verified']);
        $sub            = (string) ($claims['sub'] ?? '');

        $user = null;

        // Explicitly linked Firebase identities win over heuristics.
        if ('' !== $sub) {
            $user = self::find_by_uid($sub);
        }
        if (!$user && '' !== $phone) {
            $user = self::find_by_phone($phone);
        }
        if (!$user && '' !== $email && $email_verified) {
            $user = get_user_by('email', $email);
        }
        if (!$user && '' !== $email && !$email_verified && email_exists($email)) {
            return new WP_Error('otpress_email_unverified', __('This email address must be verified before signing in with it.', 'otpress'));
        }

        /**
         * Filter the resolved user before creation is attempted. Return a
         * WP_User to short-circuit, or null to continue.
         *
         * @param WP_User|null $user
         * @param array        $claims
         */
        $user = apply_filters('otpress_resolve_user', $user, $claims);

        if (is_wp_error($user)) {
            return $user;
        }
        if ($user instanceof WP_User) {
            self::sync_meta($user->ID, $phone, $email, $email_verified, $sub);
            return $user;
        }

        if (!$auto_create) {
            return new WP_Error('otpress_no_match', __('No account matches these details.', 'otpress'));
        }

        if (!get_option('users_can_register') && !apply_filters('otpress_allow_registration', true, $claims)) {
            return new WP_Error('otpress_registration_closed', __('No account matches these details and registration is closed.', 'otpress'));
        }

        return self::create_user($phone, $email, $email_verified, $claims, $profile);
    }

    /**
     * Attach a verified Firebase identity (claims) to an existing user, so
     * future sign-ins with that provider resolve directly to this account.
     * Called after the user proved ownership of the account (email OTP).
     */
    public static function link_identity(int $user_id, array $claims): void {
        $phone = self::e164((string) ($claims['phone_number'] ?? ''));
        $email = sanitize_email((string) ($claims['email'] ?? ''));
        self::sync_meta($user_id, $phone, $email, !empty($claims['email_verified']), (string) ($claims['sub'] ?? ''));
    }

    private static function find_by_uid(string $sub): ?WP_User {
        $users = get_users([
            'meta_key'   => 'otpress_firebase_uid',
            'meta_value' => $sub,
            'number'     => 1,
            'fields'     => 'all',
        ]);
        return $users ? $users[0] : null;
    }

    private static function find_by_phone(string $phone): ?WP_User {
        global $wpdb;
        foreach (OTPress_Settings::phone_meta_keys() as $meta_key) {
            $user_id = $wpdb->get_var($wpdb->prepare(
                "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value = %s LIMIT 1",
                $meta_key,
                $phone
            ));
            if ($user_id) {
                $user = get_user_by('id', (int) $user_id);
                if ($user) {
                    return $user;
                }
            }
        }
        return null;
    }

    /**
     * @return WP_User|WP_Error
     */
    private static function create_user(string $phone, string $email, bool $email_verified, array $claims, array $profile) {
        $display = sanitize_text_field((string) ($profile['display_name'] ?? ($claims['name'] ?? '')));

        if ('' !== $email && $email_verified) {
            $base = sanitize_user(strstr($email, '@', true), true);
        } elseif ('' !== $phone) {
            $base = 'user' . preg_replace('/\D+/', '', $phone);
        } else {
            return new WP_Error('otpress_no_identity', __('The sign-in provider returned no usable identity.', 'otpress'));
        }

        $login = $base ?: 'user' . wp_generate_password(8, false, false);
        $i = 1;
        while (username_exists($login)) {
            $login = $base . '-' . (++$i);
        }

        $role = OTPress_Settings::get('default_role');
        $user_id = wp_insert_user([
            'user_login'   => $login,
            'user_pass'    => wp_generate_password(32),
            'user_email'   => ('' !== $email && $email_verified) ? $email : '',
            'display_name' => $display ?: $login,
            'first_name'   => $display,
            'role'         => $role ?: get_option('default_role', 'subscriber'),
        ]);

        if (is_wp_error($user_id)) {
            return $user_id;
        }

        self::sync_meta($user_id, $phone, $email, $email_verified, (string) ($claims['sub'] ?? ''));

        /**
         * Fires after OTPress creates a new user from a verified sign-in.
         *
         * @param int   $user_id
         * @param array $claims
         */
        do_action('otpress_user_created', $user_id, $claims);

        return get_user_by('id', $user_id);
    }

    /**
     * Keep phone/verification meta current, including Digits-compatible keys
     * so themes and plugins built against Digits keep reading correct data.
     */
    private static function sync_meta(int $user_id, string $phone, string $email, bool $email_verified, string $sub = ''): void {
        if ('' !== $sub) {
            $existing = get_user_meta($user_id, 'otpress_firebase_uid', false);
            if (!in_array($sub, (array) $existing, true)) {
                add_user_meta($user_id, 'otpress_firebase_uid', $sub);
            }
        }
        if ('' !== $phone) {
            update_user_meta($user_id, 'otpress_phone', $phone);
            if ('1' === OTPress_Settings::get('digits_compat')) {
                if (!get_user_meta($user_id, 'digits_phone', true)) {
                    update_user_meta($user_id, 'digits_phone', $phone);
                    update_user_meta($user_id, 'digits_phone_no', ltrim($phone, '+'));
                }
                if (function_exists('WC') && !get_user_meta($user_id, 'billing_phone', true)) {
                    update_user_meta($user_id, 'billing_phone', $phone);
                }
            }
        }
        if ('' !== $email && $email_verified) {
            update_user_meta($user_id, 'otpress_email_verified', $email);
        }
    }

    /**
     * Normalize to strict E.164 (+ followed by 8–15 digits) or empty string.
     */
    private static function e164(string $phone): string {
        $phone = preg_replace('/[^\d+]/', '', $phone);
        return preg_match('/^\+\d{8,15}$/', $phone) ? $phone : '';
    }
}
