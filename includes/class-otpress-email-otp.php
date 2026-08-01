<?php
defined('ABSPATH') || exit;

/**
 * Self-contained email OTP: six-digit codes delivered with wp_mail(), stored
 * as salted hashes in transients. No gateway, no third-party service.
 *
 * A successful verification proves inbox ownership, so the address is
 * treated as a verified email identity (same trust level as a Google
 * `email_verified` claim) when mapping to a WordPress user.
 */
class OTPress_Email_OTP {

    private const TTL          = 10 * MINUTE_IN_SECONDS;
    private const MAX_ATTEMPTS = 5;

    /**
     * Generate, store and send a code.
     *
     * @return true|WP_Error
     */
    public static function start(string $email) {
        $email = sanitize_email($email);
        if (!is_email($email)) {
            return new WP_Error('otpress_bad_email', __('Please enter a valid email address.', 'otpress'));
        }

        $code = (string) random_int(100000, 999999);

        set_transient(self::key($email), [
            'hash'     => self::hash($email, $code),
            'attempts' => 0,
            'created'  => time(),
        ], self::TTL);

        $subject = apply_filters(
            'otpress_email_otp_subject',
            __('Your verification code', 'otpress'),
            $email
        );
        $message = apply_filters(
            'otpress_email_otp_message',
            sprintf(
                /* translators: %s: six-digit verification code */
                __("Your verification code is: %s\n\nIt is valid for 10 minutes. If you did not request it, you can ignore this email.", 'otpress'),
                $code
            ),
            $code,
            $email
        );

        /**
         * Filter an HTML body for the OTP email. Return non-empty HTML (e.g.
         * rendered through the site's branded template system) and the email
         * is sent as text/html; otherwise the plain-text message is used.
         *
         * @param string $html    Empty string by default.
         * @param string $code    The six-digit code.
         * @param string $email   Recipient address.
         * @param string $subject Localized subject line.
         */
        $html    = apply_filters('otpress_email_otp_html', '', $code, $email, $subject);
        $body    = '' !== $html ? $html : $message;
        $headers = '' !== $html ? ['Content-Type: text/html; charset=UTF-8'] : [];

        if (!wp_mail($email, $subject, $body, $headers)) {
            delete_transient(self::key($email));
            return new WP_Error('otpress_mail_failed', __('We could not send the email. Please try again.', 'otpress'));
        }

        return true;
    }

    /**
     * Check a submitted code. Deletes the code on success; counts attempts
     * and burns the code after too many failures.
     *
     * @return true|WP_Error
     */
    public static function verify(string $email, string $code) {
        $email = sanitize_email($email);
        $code  = preg_replace('/\D+/', '', $code);
        $key   = self::key($email);
        $data  = get_transient($key);

        if (!is_array($data) || empty($data['hash'])) {
            return new WP_Error('otpress_code_expired', __('The code has expired. Please request a new one.', 'otpress'));
        }

        if (($data['attempts'] ?? 0) >= self::MAX_ATTEMPTS) {
            delete_transient($key);
            return new WP_Error('otpress_code_locked', __('Too many incorrect attempts. Please request a new code.', 'otpress'));
        }

        if (!hash_equals($data['hash'], self::hash($email, $code))) {
            $data['attempts'] = ($data['attempts'] ?? 0) + 1;
            $remaining        = max(1, ($data['created'] + self::TTL) - time());
            set_transient($key, $data, $remaining);
            return new WP_Error('otpress_code_invalid', __('Incorrect code. Please check and try again.', 'otpress'));
        }

        delete_transient($key);
        return true;
    }

    private static function key(string $email): string {
        return 'otpress_eotp_' . md5(strtolower($email));
    }

    private static function hash(string $email, string $code): string {
        return wp_hash(strtolower($email) . '|' . $code, 'nonce');
    }
}
