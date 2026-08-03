<?php
defined('ABSPATH') || exit;

/**
 * Self-contained RFC 6238 TOTP (time-based one-time password) second factor.
 *
 * No Composer dependencies and no third-party service: the base32 codec and
 * the RFC 4226 HOTP primitive are implemented inline, and verification runs
 * SHA1 / 30-second / 6-digit codes compatible with Google Authenticator,
 * Authy, 1Password and every other standard authenticator app.
 *
 * The shared secret is generated with random_bytes() and persisted in
 * usermeta. When OpenSSL and a WordPress salt are available it is stored
 * encrypted-at-rest (AES-256-CBC keyed off AUTH_KEY); otherwise it falls
 * back to a base64 wrapper so the raw secret is never written verbatim.
 *
 * Enrollment also mints 8 single-use recovery codes; only their salted
 * wp_hash() is stored, so a database leak never exposes a usable code.
 * Comparisons use hash_equals() to stay constant-time.
 *
 * Usermeta keys written:
 *   otpress_totp_secret    — encrypted (or base64) shared secret, single value
 *   otpress_totp_enabled   — '1' once enrollment is confirmed, single value
 *   otpress_totp_recovery  — wp_hash() of each recovery code, multi-value
 */
class OTPress_TOTP {

    private const PERIOD    = 30;
    private const DIGITS    = 6;
    private const ALGO      = 'sha1';
    private const CIPHER    = 'aes-256-cbc';
    private const ENC_TAG   = 'otpenc:v1:';

    private const META_SECRET   = 'otpress_totp_secret';
    private const META_ENABLED  = 'otpress_totp_enabled';
    private const META_RECOVERY = 'otpress_totp_recovery';

    private const RECOVERY_COUNT = 8;

    /**
     * Generate a fresh base32 (RFC 4648, no padding) shared secret of 32
     * characters drawn from the A-Z2-7 alphabet, i.e. 160 bits of entropy.
     */
    public static function generate_secret(): string {
        // 20 raw bytes -> 32 base32 chars with no padding.
        return self::base32_encode(random_bytes(20));
    }

    /**
     * Build the otpauth://totp/ provisioning URI consumed by authenticator
     * apps (typically rendered as a QR code client-side).
     */
    public static function provisioning_uri(string $secret, string $account_label, string $issuer): string {
        $label = rawurlencode($issuer) . ':' . rawurlencode($account_label);
        $query = http_build_query([
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => self::DIGITS,
            'period'    => self::PERIOD,
        ], '', '&', PHP_QUERY_RFC3986);

        return 'otpauth://totp/' . $label . '?' . $query;
    }

    /**
     * Verify a submitted TOTP code against the secret, allowing ±$window
     * time-steps of clock drift. Rejects anything that is not exactly six
     * digits before doing any crypto work.
     */
    public static function verify(string $secret, string $code, int $window = 1): bool {
        $code = trim($code);
        if (!preg_match('/^\d{6}$/', $code)) {
            return false;
        }

        $key = self::base32_decode($secret);
        if ('' === $key) {
            return false;
        }

        $counter = (int) floor(time() / self::PERIOD);
        $window  = max(0, $window);

        $ok = false;
        // Iterate the whole window so timing does not leak the matching step.
        for ($i = -$window; $i <= $window; $i++) {
            $candidate = self::hotp($key, $counter + $i);
            if (hash_equals($candidate, $code)) {
                $ok = true;
            }
        }

        return $ok;
    }

    /**
     * Persist the shared secret (encrypted-at-rest when possible) and mark
     * the user as TOTP-enabled. Does not itself return recovery codes — call
     * generate_recovery_codes() for that.
     */
    public static function enroll(int $user_id, string $secret): void {
        update_user_meta($user_id, self::META_SECRET, self::encrypt($secret));
        update_user_meta($user_id, self::META_ENABLED, '1');
    }

    /**
     * Mint RECOVERY_COUNT single-use recovery codes, storing only their
     * salted hashes, and return the plaintext codes (formatted xxxx-xxxx) to
     * show the user exactly once.
     *
     * @return string[]
     */
    public static function generate_recovery_codes(int $user_id): array {
        delete_user_meta($user_id, self::META_RECOVERY);

        $codes = [];
        for ($i = 0; $i < self::RECOVERY_COUNT; $i++) {
            $code    = self::random_recovery_code();
            $codes[] = $code;
            // Multi-value usermeta: one row per hashed recovery code.
            add_user_meta($user_id, self::META_RECOVERY, self::hash_recovery($code));
        }

        return $codes;
    }

    public static function is_enabled(int $user_id): bool {
        return '1' === (string) get_user_meta($user_id, self::META_ENABLED, true);
    }

    /**
     * Fully disable TOTP for a user: clears the secret, the enabled flag and
     * every stored recovery code.
     */
    public static function disable(int $user_id): void {
        delete_user_meta($user_id, self::META_SECRET);
        delete_user_meta($user_id, self::META_ENABLED);
        delete_user_meta($user_id, self::META_RECOVERY);
    }

    /**
     * Verify a code for an enrolled user: first as a live TOTP against the
     * stored secret, then as a one-time recovery code (consumed on use).
     */
    public static function verify_for_user(int $user_id, string $code): bool {
        if (!self::is_enabled($user_id)) {
            return false;
        }

        $secret = self::decrypt((string) get_user_meta($user_id, self::META_SECRET, true));
        if ('' !== $secret && self::verify($secret, $code)) {
            return true;
        }

        return self::consume_recovery_code($user_id, $code);
    }

    // ---------------------------------------------------------------------
    // Recovery codes
    // ---------------------------------------------------------------------

    /**
     * Match a submitted recovery code against the stored hashes and, on a
     * hit, delete that single hash so the code cannot be reused.
     */
    private static function consume_recovery_code(int $user_id, string $code): bool {
        $code = strtolower(trim($code));
        if ('' === $code) {
            return false;
        }

        $target = self::hash_recovery($code);
        $hashes = get_user_meta($user_id, self::META_RECOVERY, false);
        if (!is_array($hashes)) {
            return false;
        }

        foreach ($hashes as $stored) {
            if (hash_equals((string) $stored, $target)) {
                delete_user_meta($user_id, self::META_RECOVERY, $stored);
                return true;
            }
        }

        return false;
    }

    private static function random_recovery_code(): string {
        // 8 lowercase base32 chars, split as xxxx-xxxx for readability.
        $raw = self::base32_encode(random_bytes(5)); // 8 chars
        $raw = strtolower(substr($raw, 0, 8));
        return substr($raw, 0, 4) . '-' . substr($raw, 4, 4);
    }

    private static function hash_recovery(string $code): string {
        return wp_hash('otpress_totp_recovery|' . strtolower(trim($code)), 'nonce');
    }

    // ---------------------------------------------------------------------
    // HOTP / RFC 4226
    // ---------------------------------------------------------------------

    /**
     * RFC 4226 HOTP: HMAC-SHA1 of the 8-byte big-endian counter, dynamically
     * truncated to a zero-padded 6-digit string.
     */
    private static function hotp(string $key, int $counter): string {
        $binCounter = pack('N*', 0) . pack('N*', $counter); // 64-bit big-endian
        $hash       = hash_hmac(self::ALGO, $binCounter, $key, true);

        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $part   = substr($hash, $offset, 4);
        $value  = unpack('N', $part)[1] & 0x7FFFFFFF;

        $otp = $value % (10 ** self::DIGITS);

        return str_pad((string) $otp, self::DIGITS, '0', STR_PAD_LEFT);
    }

    // ---------------------------------------------------------------------
    // Base32 (RFC 4648, no padding)
    // ---------------------------------------------------------------------

    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    private static function base32_encode(string $bytes): string {
        if ('' === $bytes) {
            return '';
        }

        $bits = '';
        foreach (str_split($bytes) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $out  .= self::ALPHABET[bindec($chunk)];
        }

        return $out;
    }

    private static function base32_decode(string $secret): string {
        $secret = strtoupper(trim($secret));
        $secret = str_replace('=', '', $secret);
        if ('' === $secret) {
            return '';
        }

        $bits = '';
        $len  = strlen($secret);
        for ($i = 0; $i < $len; $i++) {
            $pos = strpos(self::ALPHABET, $secret[$i]);
            if (false === $pos) {
                return ''; // invalid character -> reject the whole secret
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (8 === strlen($byte)) {
                $out .= chr(bindec($byte));
            }
        }

        return $out;
    }

    // ---------------------------------------------------------------------
    // Encryption at rest
    // ---------------------------------------------------------------------

    /**
     * Encrypt the secret with AES-256-CBC keyed off AUTH_KEY when OpenSSL is
     * available; otherwise fall back to a tagged base64 wrapper. The leading
     * ENC_TAG lets decrypt() tell the two apart.
     */
    private static function encrypt(string $plain): string {
        $key = self::encryption_key();
        if ('' !== $key && function_exists('openssl_encrypt')) {
            $iv     = random_bytes(16);
            $cipher = openssl_encrypt($plain, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
            if (false !== $cipher) {
                return self::ENC_TAG . base64_encode($iv . $cipher);
            }
        }

        // No key / no OpenSSL: never store the raw secret verbatim.
        return base64_encode($plain);
    }

    private static function decrypt(string $stored): string {
        if ('' === $stored) {
            return '';
        }

        if (0 === strpos($stored, self::ENC_TAG)) {
            $key = self::encryption_key();
            $raw = base64_decode(substr($stored, strlen(self::ENC_TAG)), true);
            if ('' === $key || false === $raw || strlen($raw) <= 16) {
                return '';
            }
            $iv     = substr($raw, 0, 16);
            $cipher = substr($raw, 16);
            $plain  = openssl_decrypt($cipher, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
            return false === $plain ? '' : $plain;
        }

        // Base64 fallback wrapper.
        $plain = base64_decode($stored, true);
        return false === $plain ? '' : $plain;
    }

    /**
     * Derive a 32-byte encryption key from the site's AUTH_KEY salt. Returns
     * an empty string when no usable salt is defined, which routes storage
     * through the base64 fallback.
     */
    private static function encryption_key(): string {
        if (defined('AUTH_KEY') && '' !== (string) AUTH_KEY) {
            return hash('sha256', (string) AUTH_KEY, true);
        }
        return '';
    }
}
