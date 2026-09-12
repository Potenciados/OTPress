<?php
defined('ABSPATH') || exit;

/**
 * Sending side of the WhatsApp Cloud API.
 *
 * Everything that talks to WhatsApp goes through here — login codes today,
 * order updates and campaigns later — so credentials, endpoint version and
 * error handling live in one place instead of being copied into whichever
 * feature happens to need a message.
 */
class WA_Client {

    private const API_VERSION = 'v20.0';

    /** Credentials, read from constants first so secrets can stay in .env. */
    public static function get(string $key, string $default = ''): string {
        $constant = 'WA_' . strtoupper($key);
        if (defined($constant) && '' !== (string) constant($constant)) {
            return (string) constant($constant);
        }
        // The credentials started life on the OTP plugin; keep reading those
        // so an existing install does not need its .env rewritten.
        $legacy = 'OTPRESS_WHATSAPP_' . strtoupper($key);
        if (defined($legacy) && '' !== (string) constant($legacy)) {
            return (string) constant($legacy);
        }
        $opts = get_option('wa_settings', []);
        if (isset($opts[$key]) && '' !== $opts[$key]) {
            return (string) $opts[$key];
        }
        // OTPress owns the settings after the shared WhatsApp service was
        // folded into this plugin; keep the old wa_settings fallback for
        // backwards compatibility during migration.
        $otpress_key = [
            'phone_number_id' => 'whatsapp_phone_number_id',
            'token'           => 'whatsapp_token',
            'verify_token'    => 'whatsapp_verify_token',
            'app_secret'      => 'whatsapp_app_secret',
            'relay_urls'      => 'whatsapp_relay_urls',
        ][$key] ?? '';
        if ($otpress_key !== '' && class_exists('OTPress_Settings')) {
            $value = (string) OTPress_Settings::get($otpress_key);
            return $value !== '' ? $value : $default;
        }
        return $default;
    }

    public static function is_configured(): bool {
        return '' !== self::get('phone_number_id') && '' !== self::get('token');
    }

    /**
     * Send an approved template.
     *
     * @param string $to         E.164 number (with or without '+').
     * @param string $template   Template name as approved in WhatsApp Manager.
     * @param string $lang       Template language code, e.g. 'es', 'pt_BR'.
     * @param array  $components Template components, already shaped for the API.
     * @return string|WP_Error   The message id on success.
     */
    public static function send_template(string $to, string $template, string $lang = 'es', array $components = []) {
        if (!self::is_configured()) {
            return new WP_Error('fy_wa_unconfigured', __('WhatsApp is not configured.', 'whatsapp'));
        }

        $payload = [
            'messaging_product' => 'whatsapp',
            'to'                => ltrim(preg_replace('/[^\d+]/', '', $to), '+'),
            'type'              => 'template',
            'template'          => [
                'name'     => $template,
                'language' => ['code' => $lang],
            ],
        ];
        if ($components) {
            $payload['template']['components'] = $components;
        }

        return self::request($payload);
    }

    /**
     * Components for an authentication template: the code goes in the body
     * and again in the copy-code button.
     */
    public static function auth_components(string $code): array {
        return [
            [
                'type'       => 'body',
                'parameters' => [['type' => 'text', 'text' => $code]],
            ],
            [
                'type'       => 'button',
                'sub_type'   => 'url',
                'index'      => '0',
                'parameters' => [['type' => 'text', 'text' => $code]],
            ],
        ];
    }

    /** @return string|WP_Error message id */
    private static function request(array $payload) {
        $endpoint = sprintf(
            'https://graph.facebook.com/%s/%s/messages',
            self::API_VERSION,
            rawurlencode(self::get('phone_number_id'))
        );

        $response = wp_remote_post($endpoint, [
            'timeout' => 15,
            'headers' => [
                'Authorization' => 'Bearer ' . self::get('token'),
                'Content-Type'  => 'application/json',
            ],
            'body'    => wp_json_encode($payload),
        ]);

        if (is_wp_error($response)) {
            return new WP_Error('fy_wa_transport', $response->get_error_message());
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 300 || isset($body['error'])) {
            $message = $body['error']['error_user_title']
                ?? $body['error']['message']
                ?? __('WhatsApp rejected the message.', 'whatsapp');
            return new WP_Error('fy_wa_api', (string) $message, ['status' => $code, 'response' => $body]);
        }

        $id = (string) ($body['messages'][0]['id'] ?? '');

        /**
         * Fires after a message is accepted by WhatsApp.
         *
         * @param string $id      Message id, for matching delivery callbacks.
         * @param string $to
         * @param array  $payload
         */
        do_action('wa_sent', $id, $payload['to'], $payload);

        return $id;
    }
}
