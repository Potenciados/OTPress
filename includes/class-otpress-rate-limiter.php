<?php
defined('ABSPATH') || exit;

/**
 * Small fixed-window rate limiter on transients (Redis/object-cache backed
 * where available). Windows are per action + client key.
 */
class OTPress_Rate_Limiter {

    /**
     * @return true|WP_Error
     */
    public static function check(string $action, int $limit, int $window_seconds) {
        $key   = 'otpress_rl_' . $action . '_' . md5(self::client_key());
        $count = (int) get_transient($key);

        if ($count >= $limit) {
            return new WP_Error(
                'otpress_rate_limited',
                __('Too many attempts. Please wait a few minutes and try again.', 'otpress'),
                ['status' => 429]
            );
        }

        // Fixed window: the expiry is set on first hit and left alone after.
        if (0 === $count) {
            set_transient($key, 1, $window_seconds);
        } else {
            $ttl = self::remaining_ttl($key, $window_seconds);
            set_transient($key, $count + 1, $ttl);
        }

        return true;
    }

    private static function remaining_ttl(string $key, int $fallback): int {
        $timeout = (int) get_option('_transient_timeout_' . $key);
        $remaining = $timeout > 0 ? $timeout - time() : $fallback;
        return max(1, min($remaining, $fallback));
    }

    private static function client_key(): string {
        // REMOTE_ADDR is the trustworthy value under default server setups;
        // sites behind a proxy/CDN should ensure their stack rewrites it
        // (e.g. Cloudflare's restore-original-ip) before relying on it.
        return (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    }
}
