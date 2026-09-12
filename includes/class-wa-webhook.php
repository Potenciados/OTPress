<?php
defined('ABSPATH') || exit;

/**
 * Receiving side of the WhatsApp Cloud API: https://…/wp-json/wa/v1/webhook
 *
 * Meta allows one callback URL per app, but a number is usually shared —
 * login codes here, customer conversations in a helpdesk, order updates
 * later. So this is the single subscription: it records what happened, hands
 * events to whatever is listening, and forwards the untouched payload to the
 * other systems that need it.
 *
 * Sending only tells us Meta accepted a message. Whether it arrived — and
 * why not — only shows up here, along with what Meta actually billed.
 */
class WA_Webhook {

    private const LOG_OPTION  = 'wa_delivery_log';
    private const COST_OPTION = 'wa_cost_stats';
    private const LOG_MAX     = 50;

    public static function register_routes(): void {
        register_rest_route('wa/v1', '/webhook', [
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
        $token = WA_Client::get('verify_token');
        if ('' === $token || !hash_equals($token, (string) $request->get_param('hub_verify_token'))) {
            return new WP_REST_Response('forbidden', 403);
        }
        // Meta expects the raw challenge, not JSON.
        return new WP_REST_Response((int) $request->get_param('hub_challenge'), 200);
    }

    /** POST: fan out, then record statuses, errors and billing. */
    public static function receive(WP_REST_Request $request) {
        if (!self::signature_ok($request)) {
            return new WP_REST_Response('bad signature', 403);
        }

        // Pass the payload on before doing anything with it, so a slow
        // consumer here never delays the helpdesk.
        self::relay($request);

        $body = $request->get_json_params();
        foreach (($body['entry'] ?? []) as $entry) {
            foreach (($entry['changes'] ?? []) as $change) {
                $value = $change['value'] ?? [];

                foreach (($value['statuses'] ?? []) as $status) {
                    if (!empty($status['pricing'])) {
                        self::record_cost((string) ($status['recipient_id'] ?? ''), (array) $status['pricing']);
                    }

                    $errors = array_map(function ($e) {
                        return [
                            'code'    => (int) ($e['code'] ?? 0),
                            'title'   => (string) ($e['title'] ?? ''),
                            'details' => (string) ($e['error_data']['details'] ?? ''),
                        ];
                    }, (array) ($status['errors'] ?? []));

                    self::log([
                        'at'      => time(),
                        // Without the message id, two messages to the same
                        // number are indistinguishable in the log — which is
                        // exactly when you need to tell them apart.
                        'id'      => (string) ($status['id'] ?? ''),
                        'to'      => (string) ($status['recipient_id'] ?? ''),
                        'status'  => (string) ($status['status'] ?? ''),
                        'pricing' => (array) ($status['pricing'] ?? []),
                        'errors'  => $errors,
                    ]);

                    /**
                     * Fires for every delivery status (sent, delivered, read,
                     * failed) so features can react to their own messages.
                     *
                     * @param string $status
                     * @param string $recipient
                     * @param array  $errors
                     */
                    do_action('wa_status', (string) ($status['status'] ?? ''), (string) ($status['recipient_id'] ?? ''), $errors);
                }

                // Inbound messages are the helpdesk's business, but expose
                // them so anything here can react too.
                foreach (($value['messages'] ?? []) as $message) {
                    do_action('wa_message', $message, $value);
                }
            }
        }

        return new WP_REST_Response(['ok' => true], 200);
    }

    /**
     * Forward the payload, untouched, to everything else subscribed to this
     * number. The body goes through byte for byte with Meta's signature
     * headers intact, so a receiver that validates the signature still sees a
     * valid one.
     *
     * The call waits for the response — briefly. Fire-and-forget is faster,
     * but it cannot tell a delivered relay from a silently dropped one, and a
     * helpdesk quietly missing customer messages is far worse than a couple of
     * seconds on our reply to Meta. Failures are recorded rather than thrown:
     * a downstream outage must not make us look unreachable, since Meta
     * degrades a subscription that keeps erroring.
     */
    private static function relay(WP_REST_Request $request): void {
        $targets = array_filter(array_map('trim', explode(',', WA_Client::get('relay_urls'))));
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

            $response = wp_remote_post($url, [
                'timeout' => 3,
                'headers' => $headers,
                'body'    => $body,
            ]);

            $code = is_wp_error($response) ? 0 : (int) wp_remote_retrieve_response_code($response);
            if ($code < 200 || $code > 299) {
                self::log([
                    'at'     => time(),
                    'status' => 'relay-failed',
                    'to'     => $url,
                    'errors' => [[
                        'code'    => $code,
                        'title'   => is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . $code,
                        'details' => '',
                    ]],
                ]);

                /**
                 * Fires when a downstream consumer did not accept a payload,
                 * so a missed helpdesk message can be noticed and replayed.
                 *
                 * @param string $url
                 * @param int    $code
                 * @param string $body
                 */
                do_action('wa_relay_failed', $url, $code, $body);
            }
        }
    }

    /**
     * Meta signs every payload with the app secret. Without a configured
     * secret we accept the call — the endpoint only writes to a log and
     * forwards — but with one it must match.
     */
    private static function signature_ok(WP_REST_Request $request): bool {
        $secret = WA_Client::get('app_secret');
        if ('' === $secret) {
            return true;
        }
        $header = (string) $request->get_header('x_hub_signature_256');
        if ('' === $header) {
            return false;
        }
        return hash_equals('sha256=' . hash_hmac('sha256', $request->get_body(), $secret), $header);
    }

    /**
     * Accumulate billable messages per destination prefix. Published rate
     * cards move every few months; what Meta actually charged does not.
     */
    private static function record_cost(string $recipient, array $pricing): void {
        if (empty($pricing['billable'])) {
            return;
        }
        $key = substr(preg_replace('/\D/', '', $recipient), 0, 3);
        if ('' === $key) {
            return;
        }
        $stats = get_option(self::COST_OPTION, []);
        $stats = is_array($stats) ? $stats : [];
        if (!isset($stats[$key])) {
            $stats[$key] = ['messages' => 0, 'category' => ''];
        }
        $stats[$key]['messages']++;
        $stats[$key]['category'] = (string) ($pricing['category'] ?? '');
        update_option(self::COST_OPTION, $stats, false);
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

    /** Billable messages seen per destination prefix. */
    public static function cost_stats(): array {
        $stats = get_option(self::COST_OPTION, []);
        return is_array($stats) ? $stats : [];
    }
}
