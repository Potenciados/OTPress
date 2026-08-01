<?php
defined('ABSPATH') || exit;

/**
 * Minimal, deliberately restrictive JWT decoder for Firebase ID tokens.
 *
 * Supports exactly one algorithm (RS256) against X.509 certificates published
 * by Google. This is not a general-purpose JWT library: rejecting everything
 * else (none, HS256, ES256, ...) by construction removes algorithm-confusion
 * attacks without carrying a dependency.
 */
class OTPress_JWT {

    /**
     * Decode and verify a JWS compact token against a map of kid => PEM X.509
     * certificates. Returns the payload claims array or WP_Error.
     *
     * @param string               $jwt   Compact JWS (header.payload.signature).
     * @param array<string,string> $certs kid => PEM certificate.
     * @return array|WP_Error
     */
    public static function decode_rs256(string $jwt, array $certs) {
        $parts = explode('.', $jwt);
        if (3 !== count($parts)) {
            return new WP_Error('otpress_jwt', 'Malformed token.');
        }
        [$header64, $payload64, $signature64] = $parts;

        $header    = json_decode(self::b64url_decode($header64), true);
        $payload   = json_decode(self::b64url_decode($payload64), true);
        $signature = self::b64url_decode($signature64);

        if (!is_array($header) || !is_array($payload) || '' === $signature) {
            return new WP_Error('otpress_jwt', 'Malformed token.');
        }
        if (($header['alg'] ?? '') !== 'RS256') {
            return new WP_Error('otpress_jwt', 'Unsupported algorithm.');
        }
        $kid = (string) ($header['kid'] ?? '');
        if ('' === $kid || !isset($certs[$kid])) {
            return new WP_Error('otpress_jwt', 'Unknown signing key.');
        }

        $public_key = openssl_pkey_get_public($certs[$kid]);
        if (false === $public_key) {
            return new WP_Error('otpress_jwt', 'Invalid signing certificate.');
        }

        $verified = openssl_verify($header64 . '.' . $payload64, $signature, $public_key, OPENSSL_ALGO_SHA256);
        if (1 !== $verified) {
            return new WP_Error('otpress_jwt', 'Signature verification failed.');
        }

        return $payload;
    }

    private static function b64url_decode(string $input): string {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($input, '-_', '+/'), true);
        return false === $decoded ? '' : $decoded;
    }
}
