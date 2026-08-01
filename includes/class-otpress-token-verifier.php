<?php
defined('ABSPATH') || exit;

/**
 * Verifies Firebase ID tokens per the documented rules for third-party
 * verification: RS256 signature against Google's published securetoken
 * certificates, plus iss/aud/exp/iat/sub/auth_time checks.
 *
 * https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
 */
class OTPress_Token_Verifier {

    private const CERTS_URL  = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
    private const CACHE_KEY  = 'otpress_google_certs';
    private const LEEWAY     = 60; // seconds of clock skew tolerance

    /**
     * @return array|WP_Error Verified claims on success.
     */
    public static function verify(string $id_token) {
        $project_id = OTPress_Settings::get('firebase_project_id');
        if ('' === $project_id) {
            return new WP_Error('otpress_config', 'Firebase project is not configured.');
        }

        $certs = self::get_certs();
        if (is_wp_error($certs)) {
            return $certs;
        }

        $claims = OTPress_JWT::decode_rs256($id_token, $certs);
        if (is_wp_error($claims)) {
            return $claims;
        }

        $now = time();
        $checks =
            ($claims['aud'] ?? null) === $project_id
            && ($claims['iss'] ?? null) === 'https://securetoken.google.com/' . $project_id
            && is_string($claims['sub'] ?? null) && '' !== $claims['sub']
            && is_numeric($claims['exp'] ?? null) && $claims['exp'] > $now - self::LEEWAY
            && is_numeric($claims['iat'] ?? null) && $claims['iat'] <= $now + self::LEEWAY
            && is_numeric($claims['auth_time'] ?? null) && $claims['auth_time'] <= $now + self::LEEWAY;

        if (!$checks) {
            return new WP_Error('otpress_token', 'Token failed validation.');
        }

        return $claims;
    }

    /**
     * Fetch Google's current signing certificates, cached per the response's
     * Cache-Control max-age as recommended by Firebase.
     *
     * @return array<string,string>|WP_Error kid => PEM certificate.
     */
    private static function get_certs() {
        $cached = get_transient(self::CACHE_KEY);
        if (is_array($cached) && $cached) {
            return $cached;
        }

        $response = wp_remote_get(self::CERTS_URL, ['timeout' => 10]);
        if (is_wp_error($response)) {
            return new WP_Error('otpress_certs', 'Could not reach the token verification service.');
        }
        if (200 !== wp_remote_retrieve_response_code($response)) {
            return new WP_Error('otpress_certs', 'Unexpected response from the token verification service.');
        }

        $certs = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($certs) || !$certs) {
            return new WP_Error('otpress_certs', 'Could not parse verification certificates.');
        }

        $ttl = 3600;
        $cache_control = wp_remote_retrieve_header($response, 'cache-control');
        if (is_string($cache_control) && preg_match('/max-age=(\d+)/', $cache_control, $m)) {
            $ttl = max(300, min((int) $m[1], DAY_IN_SECONDS));
        }
        set_transient(self::CACHE_KEY, $certs, $ttl);

        return $certs;
    }
}
