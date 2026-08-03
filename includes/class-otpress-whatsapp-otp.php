<?php
defined('ABSPATH') || exit;

/**
 * WhatsApp OTP via Meta's Cloud API: six-digit codes delivered with an
 * approved authentication template. Storage/verification mirrors the email
 * OTP engine (salted-hash transients, attempt caps). Enabled only when the
 * three settings are present: whatsapp_phone_number_id, whatsapp_token and
 * whatsapp_template.
 *
 * A successful verification proves possession of the phone number, so it is
 * treated as a verified phone identity for user mapping — same trust level
 * as a Firebase SMS verification.
 */
class OTPress_WhatsApp_OTP {

    private const TTL          = 10 * MINUTE_IN_SECONDS;
    private const MAX_ATTEMPTS = 5;

    /**
     * WhatsApp language codes we have approved template translations for.
     * Anything outside this list (e.g. Icelandic, which WhatsApp does not
     * support) falls back to English.
     */
    private const TEMPLATE_LANGS = [
        'es', 'en_US', 'ar', 'pt_BR', 'fr', 'ms', 'ja', 'de', 'tr', 'ko',
        'it', 'ca', 'sv', 'pl', 'nl', 'da', 'hr', 'fi', 'nb',
    ];

    public static function is_configured(): bool {
        return '' !== OTPress_Settings::get('whatsapp_phone_number_id')
            && '' !== OTPress_Settings::get('whatsapp_token')
            && '' !== self::template_name('login');
    }

    /**
     * Template for the context: a fresh number gets the account-verification
     * copy, a known one the login copy. Both are Meta's own authentication
     * templates, so their wording is already localized and approved.
     */
    public static function template_name(string $context = 'login'): string {
        $key = 'signup' === $context ? 'whatsapp_template_signup' : 'whatsapp_template_login';
        $name = OTPress_Settings::get($key);
        return '' !== $name ? $name : OTPress_Settings::get('whatsapp_template');
    }

    /**
     * Current site language as a WhatsApp template language code, falling back
     * to English when we have no approved translation for it.
     */
    public static function template_lang(): string {
        $locale = '';
        if (function_exists('pll_current_language')) {
            // Returns false outside a language context (cron, WP-CLI).
            $locale = (string) pll_current_language('locale');
        }
        if ('' === $locale) {
            $locale = get_locale();
        }

        // Locales whose WhatsApp code keeps the region, and the plain-language
        // codes for everything else (es_ES -> es, fr_FR -> fr, ...).
        static $explicit = ['en_US' => 'en_US', 'en_GB' => 'en_GB', 'pt_BR' => 'pt_BR', 'pt_PT' => 'pt_PT'];
        if (isset($explicit[$locale])) {
            $code = $explicit[$locale];
        } else {
            $code = strtolower(substr($locale, 0, 2));
            if ('en' === $code) {
                $code = 'en_US';
            }
        }

        if (!in_array($code, self::TEMPLATE_LANGS, true)) {
            $code = 'en_US';
        }
        return $code;
    }

    /**
     * @param string $phone E.164 phone number.
     * @return true|WP_Error
     */
    public static function start(string $phone, string $context = 'login') {
        if (!self::is_configured()) {
            return new WP_Error('otpress_wa_unavailable', __('WhatsApp sign-in is not available.', 'otpress'));
        }
        if (!preg_match('/^\+\d{8,15}$/', $phone)) {
            return new WP_Error('otpress_bad_phone', __('Please check the phone number.', 'otpress'));
        }

        $code = (string) random_int(100000, 999999);
        set_transient(self::key($phone), [
            'hash'     => self::hash($phone, $code),
            'attempts' => 0,
            'created'  => time(),
        ], self::TTL);

        $endpoint = sprintf(
            'https://graph.facebook.com/v20.0/%s/messages',
            rawurlencode(OTPress_Settings::get('whatsapp_phone_number_id'))
        );
        $payload = [
            'messaging_product' => 'whatsapp',
            'to'                => ltrim($phone, '+'),
            'type'              => 'template',
            'template'          => [
                'name'     => self::template_name($context),
                'language' => ['code' => self::template_lang()],
                'components' => [
                    [
                        'type'       => 'body',
                        'parameters' => [['type' => 'text', 'text' => $code]],
                    ],
                    [
                        // Authentication templates ship a copy-code button whose
                        // URL parameter is the code itself.
                        'type'       => 'button',
                        'sub_type'   => 'url',
                        'index'      => '0',
                        'parameters' => [['type' => 'text', 'text' => $code]],
                    ],
                ],
            ],
        ];

        $response = wp_remote_post($endpoint, [
            'timeout' => 15,
            'headers' => [
                'Authorization' => 'Bearer ' . OTPress_Settings::get('whatsapp_token'),
                'Content-Type'  => 'application/json',
            ],
            'body'    => wp_json_encode($payload),
        ]);

        $failed = is_wp_error($response)
            || 200 !== wp_remote_retrieve_response_code($response)
            || empty(json_decode(wp_remote_retrieve_body($response), true)['messages'][0]['id']);

        if ($failed) {
            delete_transient(self::key($phone));
            if (!is_wp_error($response)) {
                error_log('[otpress] WhatsApp send failed: ' . substr(wp_remote_retrieve_body($response), 0, 300));
            }
            return new WP_Error('otpress_wa_failed', __('We could not send the WhatsApp message. Please try again.', 'otpress'));
        }

        return true;
    }

    /**
     * @return true|WP_Error
     */
    public static function verify(string $phone, string $code) {
        $code = preg_replace('/\D+/', '', $code);
        $key  = self::key($phone);
        $data = get_transient($key);

        if (!is_array($data) || empty($data['hash'])) {
            return new WP_Error('otpress_code_expired', __('The code has expired. Please request a new one.', 'otpress'));
        }
        if (($data['attempts'] ?? 0) >= self::MAX_ATTEMPTS) {
            delete_transient($key);
            return new WP_Error('otpress_code_locked', __('Too many incorrect attempts. Please request a new code.', 'otpress'));
        }
        if (!hash_equals($data['hash'], self::hash($phone, $code))) {
            $data['attempts'] = ($data['attempts'] ?? 0) + 1;
            $remaining        = max(1, ($data['created'] + self::TTL) - time());
            set_transient($key, $data, $remaining);
            return new WP_Error('otpress_code_invalid', __('Incorrect code. Please check and try again.', 'otpress'));
        }

        delete_transient($key);
        return true;
    }

    private static function key(string $phone): string {
        return 'otpress_waotp_' . md5($phone);
    }

    private static function hash(string $phone, string $code): string {
        return wp_hash($phone . '|' . $code, 'nonce');
    }
}
