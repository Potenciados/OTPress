<?php
defined('ABSPATH') || exit;

/**
 * Delivery feedback from the WhatsApp Cloud API.
 *
 * The send call only tells us Meta accepted the message. Whether it was
 * actually delivered — or dropped, and why — arrives later on this webhook.
 * Without it a number that silently never receives codes looks identical to
 * one that does, so failures are recorded here and surfaced in the log.
 */
class OTPress_WhatsApp_Webhook {

    private const LOG_OPTION = 'otpress_wa_delivery_log';
    private const LOG_MAX    = 50;

    public static function register_routes(): void {
        register_rest_route('otpress/v1', '/whatsapp/webhook', [
            [
                // Meta's subscription handshake.
                'methods'             => 'GET',
                'callback'            => [self::class, 'verify'],
                'permission_callback' => '__return_true',
            ],
            [
                'methods'             => 'POST',
                'callback'            => [self::class, 'receive'],
                'permission_callback' => '__return_true',
            ],
        ]);
    }

    /** GET: echo hub.challenge when the verify token matches. */
    public static function verify(WP_REST_Request $request) {
        $token = OTPress_Settings::get('whatsapp_verify_token');
        if ('' === $token || (string) $request->get_param('hub_verify_token') !== $token) {
            return new WP_REST_Response('forbidden', 403);
        }
        // Meta expects the raw challenge, not JSON.
        return new WP_REST_Response((int) $request->get_param('hub_challenge'), 200);
    }

    /** POST: record delivery statuses and errors. */
    public static function receive(WP_REST_Request $request) {
        if (!self::signature_ok($request)) {
            return new WP_REST_Response('bad signature', 403);
        }

        // Meta allows one callback URL per app, but a WhatsApp number is
        // usually shared with a helpdesk (Chatwoot) that needs the same
        // events. Pass every payload straight through so both systems keep
        // working from a single subscription.
        self::relay($request);

        $body = $request->get_json_params();
        foreach (($body['entry'] ?? []) as $entry) {
            foreach (($entry['changes'] ?? []) as $change) {
                $value = $change['value'] ?? [];
                foreach (($value['statuses'] ?? []) as $status) {
                    // Meta reports what it actually billed for each message —
                    // the only trustworthy source of per-country cost, since
                    // published rate cards change every few months.
                    if (!empty($status['pricing'])) {
                        self::record_cost(
                            (string) ($status['recipient_id'] ?? ''),
                            (array) $status['pricing']
                        );
                    }

                    self::log([
                        'at'        => time(),
                        'to'        => (string) ($status['recipient_id'] ?? ''),
                        'status'    => (string) ($status['status'] ?? ''),
                        'pricing'   => (array) ($status['pricing'] ?? []),
                        'errors'    => array_map(function ($e) {
                            return [
                                'code'    => (int) ($e['code'] ?? 0),
                                'title'   => (string) ($e['title'] ?? ''),
                                'details' => (string) ($e['error_data']['details'] ?? ''),
                            ];
                        }, (array) ($status['errors'] ?? [])),
                    ]);

                    if ('failed' === ($status['status'] ?? '')) {
                        /**
                         * Fires when WhatsApp could not deliver a code, so the
                         * site can fall back or alert.
                         *
                         * @param string $recipient
                         * @param array  $errors
                         */
                        do_action('otpress_whatsapp_failed', (string) ($status['recipient_id'] ?? ''), (array) ($status['errors'] ?? []));
                    }
                }
            }
        }

        return new WP_REST_Response(['ok' => true], 200);
    }

    /**
     * Forward the payload, untouched, to anything else that needs these
     * events — normally the helpdesk inbox on the same WhatsApp number.
     *
     * The body is passed through byte for byte along with Meta's signature
     * headers, so a receiver that validates the signature still sees a valid
     * one. Delivery is fire-and-forget: Meta retries on a slow response, and
     * a helpdesk being down must not make us look unreachable.
     */
    private static function relay(WP_REST_Request $request): void {
        $targets = array_filter(array_map('trim', explode(',', OTPress_Settings::get('whatsapp_relay_urls'))));
        if (!$targets) {
            return;
        }

        $headers = ['Content-Type' => 'application/json'];
        foreach (['x_hub_signature_256' => 'X-Hub-Signature-256', 'x_hub_signature' => 'X-Hub-Signature'] as $in => $out) {
            $value = (string) $request->get_header($in);
            if ('' !== $value) {
                $headers[$out] = $value;
            }
        }

        $body = $request->get_body();
        foreach ($targets as $url) {
            if (!filter_var($url, FILTER_VALIDATE_URL)) {
                continue;
            }
            wp_remote_post($url, [
                'timeout'  => 5,
                'blocking' => false,
                'headers'  => $headers,
                'body'     => $body,
            ]);
        }
    }

    /**
     * Meta signs every payload with the app secret. Without a configured
     * secret we accept the call (the data is not sensitive and the endpoint
     * only writes to a log), but with one it must match.
     */
    private static function signature_ok(WP_REST_Request $request): bool {
        $secret = OTPress_Settings::get('whatsapp_app_secret');
        if ('' === $secret) {
            return true;
        }
        $header = (string) $request->get_header('x_hub_signature_256');
        if ('' === $header) {
            return false;
        }
        $expected = 'sha256=' . hash_hmac('sha256', $request->get_body(), $secret);
        return hash_equals($expected, $header);
    }

    /**
     * Accumulate billable messages per destination country, so the blocked
     * list can eventually be driven by what we are really charged instead of
     * a published rate card. Keyed by calling-code prefix of the recipient.
     */
    private static function record_cost(string $recipient, array $pricing): void {
        if (empty($pricing['billable'])) {
            return;
        }
        $stats = get_option('otpress_wa_cost_stats', []);
        $stats = is_array($stats) ? $stats : [];
        $key   = substr(preg_replace('/\D/', '', $recipient), 0, 3);
        if ('' === $key) {
            return;
        }
        if (!isset($stats[$key])) {
            $stats[$key] = ['messages' => 0, 'category' => ''];
        }
        $stats[$key]['messages']++;
        $stats[$key]['category'] = (string) ($pricing['category'] ?? '');
        update_option('otpress_wa_cost_stats', $stats, false);
    }

    /** Billable messages seen per destination prefix. */
    public static function cost_stats(): array {
        $stats = get_option('otpress_wa_cost_stats', []);
        return is_array($stats) ? $stats : [];
    }

    private static function log(array $entry): void {
        $log = get_option(self::LOG_OPTION, []);
        $log = is_array($log) ? $log : [];
        array_unshift($log, $entry);
        update_option(self::LOG_OPTION, array_slice($log, 0, self::LOG_MAX), false);
    }

    /** Most recent delivery events, newest first. */
    public static function recent(int $limit = 20): array {
        $log = get_option(self::LOG_OPTION, []);
        return array_slice(is_array($log) ? $log : [], 0, $limit);
    }
}
