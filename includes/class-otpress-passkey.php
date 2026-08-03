<?php
defined('ABSPATH') || exit;

/**
 * Self-contained WebAuthn / FIDO2 passkey support.
 *
 * No Composer dependency and no third-party service: the CBOR walk
 * (OTPress_CBOR), the COSE-key-to-PEM conversion and every signature check are
 * implemented inline on top of OpenSSL. Only the two widely-supported
 * algorithms are accepted — ES256 (COSE -7, EC P-256) and RS256 (COSE -257) —
 * with attestation `none`, matching what browser platform authenticators emit.
 *
 * A credential is stored per row in multi-value usermeta (mirroring the TOTP
 * recovery-code layout): a small JSON record holding the base64url credential
 * id, its public key as PEM, the algorithm, the signature counter, transports,
 * a user-supplied friendly name and timestamps. Only public data is stored, so
 * a database leak never exposes anything usable for impersonation.
 *
 * Challenges live in short-lived transients: registration keyed by user id,
 * authentication keyed by a random handle handed to the client (so the same
 * flow serves both scoped and usernameless/discoverable sign-ins).
 *
 * Usermeta keys written:
 *   otpress_passkey — one JSON credential record per row, multi-value
 */
class OTPress_Passkey {

    private const RP_ID   = 'followersya.com';
    private const RP_NAME = 'FollowersYA';
    private const ORIGIN  = 'https://followersya.com';

    private const TIMEOUT = 60000;

    // COSE algorithm identifiers we accept.
    private const ALG_ES256 = -7;
    private const ALG_RS256 = -257;

    private const META_CRED = 'otpress_passkey';

    private const CHALLENGE_TTL = 300; // 5 minutes.

    // ---------------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------------

    /**
     * Build the publicKey options for navigator.credentials.create(). The
     * challenge is stashed (base64url) in a per-user transient and returned so
     * the browser can echo it back for verification.
     */
    public static function registration_options(WP_User $user): array {
        $challenge = self::random_challenge();
        // Store the base64url form so it compares directly against the
        // browser-echoed clientDataJSON.challenge in verify_client_data
        // (mirrors the authentication path, which also stores it encoded).
        set_transient(self::reg_key($user->ID), self::b64url_encode($challenge), self::CHALLENGE_TTL);

        $exclude = [];
        foreach (self::read_credentials($user->ID) as $cred) {
            $exclude[] = [
                'type'       => 'public-key',
                'id'         => $cred['id'],
                'transports' => $cred['transports'] ?? [],
            ];
        }

        return [
            'challenge' => self::b64url_encode($challenge),
            'rp'        => ['id' => self::RP_ID, 'name' => self::RP_NAME],
            'user'      => [
                'id'          => self::b64url_encode((string) $user->ID),
                'name'        => $user->user_email ?: $user->user_login,
                'displayName' => $user->display_name ?: $user->user_login,
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => self::ALG_ES256],
                ['type' => 'public-key', 'alg' => self::ALG_RS256],
            ],
            'authenticatorSelection' => [
                'residentKey'      => 'preferred',
                'userVerification'  => 'preferred',
            ],
            'attestation'       => 'none',
            'excludeCredentials' => $exclude,
            'timeout'           => self::TIMEOUT,
        ];
    }

    /**
     * Verify a registration response and persist the new credential.
     *
     * @param array  $clientData        Decoded clientDataJSON (assoc array).
     * @param string $attestationObject Raw CBOR attestationObject bytes.
     * @return true|WP_Error
     */
    public static function verify_registration(WP_User $user, array $clientData, string $attestationObject, string $friendlyName) {
        // 1. clientDataJSON checks.
        $challenge = get_transient(self::reg_key($user->ID));
        if (!is_string($challenge) || '' === $challenge) {
            return new WP_Error('otpress_passkey_expired', __('Passkey setup expired. Please start again.', 'otpress'), ['status' => 400]);
        }
        $client_err = self::verify_client_data($clientData, 'webauthn.create', $challenge);
        if (is_wp_error($client_err)) {
            return $client_err;
        }

        // 2. Parse the attestation object and pull out authenticatorData.
        try {
            $att = OTPress_CBOR::decode($attestationObject);
        } catch (Throwable $e) {
            return new WP_Error('otpress_passkey_malformed', __('Could not read the passkey response.', 'otpress'), ['status' => 400]);
        }
        if (!is_array($att) || !isset($att['authData']) || !is_string($att['authData'])) {
            return new WP_Error('otpress_passkey_malformed', __('Could not read the passkey response.', 'otpress'), ['status' => 400]);
        }

        $auth = self::parse_auth_data((string) $att['authData'], true);
        if (is_wp_error($auth)) {
            return $auth;
        }

        // 3. rpIdHash + user-presence.
        if (!hash_equals(hash('sha256', self::RP_ID, true), $auth['rpIdHash'])) {
            return new WP_Error('otpress_passkey_rpid', __('Passkey origin mismatch.', 'otpress'), ['status' => 400]);
        }
        if (!$auth['userPresent']) {
            return new WP_Error('otpress_passkey_up', __('Passkey user presence was not confirmed.', 'otpress'), ['status' => 400]);
        }
        if (empty($auth['credentialId']) || empty($auth['pem'])) {
            return new WP_Error('otpress_passkey_malformed', __('The passkey did not include a usable key.', 'otpress'), ['status' => 400]);
        }

        $cred_id_b64 = self::b64url_encode($auth['credentialId']);

        // Reject a credential id already registered anywhere.
        if (null !== self::find_credential($cred_id_b64)) {
            return new WP_Error('otpress_passkey_exists', __('This passkey is already registered.', 'otpress'), ['status' => 409]);
        }

        $name = sanitize_text_field($friendlyName);
        if ('' === $name) {
            $name = __('Passkey', 'otpress');
        }

        // wp_slash: update_metadata() runs wp_unslash() on the value, which
        // would strip the backslashes in the JSON-escaped PEM newlines ("\n"
        // → "n") and corrupt the stored public key. Pre-slashing survives it.
        add_user_meta($user->ID, self::META_CRED, wp_slash(wp_json_encode([
            'id'         => $cred_id_b64,
            'publicKey'  => $auth['pem'],
            'alg'        => $auth['alg'],
            'signCount'  => $auth['signCount'],
            'transports' => array_values(array_filter((array) (isset($att['transports']) ? $att['transports'] : []), 'is_string')),
            'aaguid'     => bin2hex($auth['aaguid']),
            'name'       => $name,
            'created_at' => time(),
            'last_used'  => 0,
        ])));

        delete_transient(self::reg_key($user->ID));
        return true;
    }

    // ---------------------------------------------------------------------
    // Authentication
    // ---------------------------------------------------------------------

    /**
     * Build the publicKey options for navigator.credentials.get(). When a user
     * is known the allowCredentials list is scoped to that account's keys;
     * otherwise it is left empty for a discoverable (usernameless) sign-in. The
     * challenge is stored under a random handle returned to the client.
     */
    public static function authentication_options(?WP_User $user = null): array {
        $challenge = self::random_challenge();
        $handle    = wp_generate_password(40, false, false);
        set_transient(self::auth_key($handle), self::b64url_encode($challenge), self::CHALLENGE_TTL);

        $allow = [];
        if ($user instanceof WP_User) {
            foreach (self::read_credentials($user->ID) as $cred) {
                $allow[] = [
                    'type'       => 'public-key',
                    'id'         => $cred['id'],
                    'transports' => $cred['transports'] ?? [],
                ];
            }
        }

        return [
            'challenge'        => self::b64url_encode($challenge),
            'handle'           => $handle,
            'rpId'             => self::RP_ID,
            'allowCredentials' => $allow,
            'userVerification' => 'preferred',
            'timeout'          => self::TIMEOUT,
        ];
    }

    /**
     * Verify an assertion. On success returns the owning WP_User.
     *
     * Expected $params (all base64url except `handle`):
     *   handle, credentialId, authenticatorData, clientDataJSON, signature
     *
     * @return WP_User|WP_Error
     */
    public static function verify_authentication(array $params) {
        $handle = (string) ($params['handle'] ?? '');
        $stored_challenge = preg_match('/^[A-Za-z0-9]{40}$/', $handle) ? get_transient(self::auth_key($handle)) : false;
        if (!is_string($stored_challenge) || '' === $stored_challenge) {
            return new WP_Error('otpress_passkey_expired', __('This sign-in attempt expired. Please try again.', 'otpress'), ['status' => 401]);
        }

        $cred_id_raw    = self::b64url_decode((string) ($params['credentialId'] ?? ''));
        $auth_data_raw  = self::b64url_decode((string) ($params['authenticatorData'] ?? ''));
        $client_raw     = self::b64url_decode((string) ($params['clientDataJSON'] ?? ''));
        $signature_raw  = self::b64url_decode((string) ($params['signature'] ?? ''));

        if ('' === $cred_id_raw || '' === $auth_data_raw || '' === $client_raw || '' === $signature_raw) {
            return new WP_Error('otpress_passkey_malformed', __('Incomplete passkey response.', 'otpress'), ['status' => 400]);
        }

        // 1. Locate the credential across all users by its id.
        $cred_id_b64 = self::b64url_encode($cred_id_raw);
        $match = self::find_credential($cred_id_b64);
        if (null === $match) {
            return new WP_Error('otpress_passkey_unknown', __('Unrecognised passkey.', 'otpress'), ['status' => 401]);
        }
        [$user_id, $cred, $meta_row] = $match;

        // 2. clientDataJSON.
        $clientData = json_decode($client_raw, true);
        if (!is_array($clientData)) {
            return new WP_Error('otpress_passkey_malformed', __('Could not read the passkey response.', 'otpress'), ['status' => 400]);
        }
        $client_err = self::verify_client_data($clientData, 'webauthn.get', $stored_challenge);
        if (is_wp_error($client_err)) {
            return $client_err;
        }

        // 3. authenticatorData: rpIdHash + user presence (no attested data here).
        $auth = self::parse_auth_data($auth_data_raw, false);
        if (is_wp_error($auth)) {
            return $auth;
        }
        if (!hash_equals(hash('sha256', self::RP_ID, true), $auth['rpIdHash'])) {
            return new WP_Error('otpress_passkey_rpid', __('Passkey origin mismatch.', 'otpress'), ['status' => 401]);
        }
        if (!$auth['userPresent']) {
            return new WP_Error('otpress_passkey_up', __('Passkey user presence was not confirmed.', 'otpress'), ['status' => 401]);
        }

        // 4. Signature over authenticatorData || SHA-256(clientDataJSON).
        $signed = $auth_data_raw . hash('sha256', $client_raw, true);
        if (!self::verify_signature((int) $cred['alg'], (string) $cred['publicKey'], $signed, $signature_raw)) {
            return new WP_Error('otpress_passkey_signature', __('Passkey verification failed.', 'otpress'), ['status' => 401]);
        }

        // 5. Signature counter: reject a regression when both are non-zero.
        $stored_count = (int) ($cred['signCount'] ?? 0);
        $new_count    = (int) $auth['signCount'];
        if ($new_count > 0 && $stored_count > 0 && $new_count <= $stored_count) {
            return new WP_Error('otpress_passkey_counter', __('Passkey replay detected. Please try again.', 'otpress'), ['status' => 401]);
        }

        // 6. Advance the counter + last-used, then rewrite the row in place.
        $cred['signCount'] = $new_count;
        $cred['last_used'] = time();
        update_user_meta($user_id, self::META_CRED, wp_slash(wp_json_encode($cred)), $meta_row);

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new WP_Error('otpress_passkey_unknown', __('Account not found.', 'otpress'), ['status' => 401]);
        }

        delete_transient(self::auth_key($handle));
        return $user;
    }

    // ---------------------------------------------------------------------
    // Management helpers
    // ---------------------------------------------------------------------

    public static function has_credentials(int $user_id): bool {
        return [] !== self::read_credentials($user_id);
    }

    /**
     * Public-safe view of a user's passkeys for the account UI.
     *
     * @return array<int,array{id:string,name:string,created_at:int,last_used:int}>
     */
    public static function list_credentials(int $user_id): array {
        $out = [];
        foreach (self::read_credentials($user_id) as $cred) {
            $out[] = [
                'id'         => (string) $cred['id'],
                'name'       => (string) ($cred['name'] ?? __('Passkey', 'otpress')),
                'created_at' => (int) ($cred['created_at'] ?? 0),
                'last_used'  => (int) ($cred['last_used'] ?? 0),
            ];
        }
        return $out;
    }

    /**
     * Delete one of the user's passkeys by its (base64url) credential id.
     *
     * @return true|WP_Error
     */
    public static function remove_credential(int $user_id, string $credId) {
        // Rebuild the whole meta key rather than delete-by-value: the stored
        // JSON carries newlines in the PEM, and delete_user_meta()'s exact
        // value match is unreliable for such multiline blobs. Drop every row,
        // then re-add the survivors (wp_slash keeps the PEM intact).
        $rows  = (array) get_user_meta($user_id, self::META_CRED, false);
        $keep  = [];
        $found = false;
        foreach ($rows as $row) {
            $cred = self::decode_row($row);
            if (is_array($cred) && hash_equals((string) ($cred['id'] ?? ''), $credId)) {
                $found = true;
                continue;
            }
            if (is_array($cred)) {
                $keep[] = $cred;
            }
        }
        if (!$found) {
            return new WP_Error('otpress_passkey_not_found', __('That passkey was not found.', 'otpress'), ['status' => 404]);
        }
        delete_user_meta($user_id, self::META_CRED);
        foreach ($keep as $cred) {
            add_user_meta($user_id, self::META_CRED, wp_slash(wp_json_encode($cred)));
        }
        return true;
    }

    /**
     * Rename one of the user's passkeys.
     *
     * @return true|WP_Error
     */
    public static function rename_credential(int $user_id, string $credId, string $name) {
        $clean = sanitize_text_field($name);
        if ('' === $clean) {
            return new WP_Error('otpress_passkey_bad_name', __('Please provide a name.', 'otpress'), ['status' => 400]);
        }
        // Rebuild the meta key (see remove_credential for why value-matching
        // an update in place is unreliable for the multiline PEM blob).
        $rows  = (array) get_user_meta($user_id, self::META_CRED, false);
        $creds = [];
        $found = false;
        foreach ($rows as $row) {
            $cred = self::decode_row($row);
            if (!is_array($cred)) {
                continue;
            }
            if (hash_equals((string) ($cred['id'] ?? ''), $credId)) {
                $cred['name'] = $clean;
                $found = true;
            }
            $creds[] = $cred;
        }
        if (!$found) {
            return new WP_Error('otpress_passkey_not_found', __('That passkey was not found.', 'otpress'), ['status' => 404]);
        }
        delete_user_meta($user_id, self::META_CRED);
        foreach ($creds as $cred) {
            add_user_meta($user_id, self::META_CRED, wp_slash(wp_json_encode($cred)));
        }
        return true;
    }

    // ---------------------------------------------------------------------
    // Internal: storage + lookup
    // ---------------------------------------------------------------------

    /**
     * Decode a user's stored credential records.
     *
     * @return array<int,array<string,mixed>>
     */
    private static function read_credentials(int $user_id): array {
        $out = [];
        foreach ((array) get_user_meta($user_id, self::META_CRED, false) as $row) {
            $cred = self::decode_row($row);
            if (is_array($cred) && !empty($cred['id'])) {
                $out[] = $cred;
            }
        }
        return $out;
    }

    private static function decode_row($row): ?array {
        if (is_array($row)) {
            return $row;
        }
        if (is_string($row)) {
            $d = json_decode($row, true);
            return is_array($d) ? $d : null;
        }
        return null;
    }

    /**
     * Find a credential by its base64url id across every user. Returns the
     * owning user id, the decoded credential and the exact stored meta row (so
     * the caller can update_user_meta() it in place).
     *
     * @return array{0:int,1:array<string,mixed>,2:string}|null
     */
    private static function find_credential(string $cred_id_b64): ?array {
        global $wpdb;
        // The id is embedded in the JSON row; narrow with a LIKE before an
        // exact, constant-time compare on each candidate.
        $like = '%' . $wpdb->esc_like('"id":"' . $cred_id_b64 . '"') . '%';
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value LIKE %s",
            self::META_CRED,
            $like
        ));
        foreach ((array) $rows as $r) {
            $cred = self::decode_row($r->meta_value);
            if (is_array($cred) && isset($cred['id']) && hash_equals((string) $cred['id'], $cred_id_b64)) {
                return [(int) $r->user_id, $cred, (string) $r->meta_value];
            }
        }
        return null;
    }

    private static function reg_key(int $user_id): string {
        return 'otpress_pk_reg_' . $user_id;
    }

    private static function auth_key(string $handle): string {
        return 'otpress_pk_auth_' . $handle;
    }

    private static function random_challenge(): string {
        return random_bytes(32);
    }

    // ---------------------------------------------------------------------
    // Internal: WebAuthn parsing + crypto
    // ---------------------------------------------------------------------

    /**
     * Common clientDataJSON validation: expected type, matching challenge
     * (compared as base64url) and exact origin.
     *
     * @return true|WP_Error
     */
    private static function verify_client_data(array $clientData, string $expected_type, string $expected_challenge_b64) {
        if (($clientData['type'] ?? '') !== $expected_type) {
            return new WP_Error('otpress_passkey_type', __('Unexpected passkey response type.', 'otpress'), ['status' => 400]);
        }
        // The browser encodes the challenge as base64url; the stored value is
        // already base64url, so a normalised constant-time compare is enough.
        $got = self::b64url_normalize((string) ($clientData['challenge'] ?? ''));
        if ('' === $got || !hash_equals($expected_challenge_b64, $got)) {
            return new WP_Error('otpress_passkey_challenge', __('Passkey challenge mismatch.', 'otpress'), ['status' => 400]);
        }
        if (($clientData['origin'] ?? '') !== self::ORIGIN) {
            return new WP_Error('otpress_passkey_origin', __('Passkey origin mismatch.', 'otpress'), ['status' => 400]);
        }
        return true;
    }

    /**
     * Parse authenticatorData. With $expect_attested the attestedCredentialData
     * (aaguid, credential id, COSE public key) is decoded and converted to PEM.
     *
     * @return array|WP_Error {
     *     rpIdHash:string, userPresent:bool, userVerified:bool, signCount:int,
     *     aaguid:string, credentialId:string, pem:string, alg:int
     * }
     */
    private static function parse_auth_data(string $data, bool $expect_attested) {
        if (strlen($data) < 37) {
            return new WP_Error('otpress_passkey_malformed', __('Malformed authenticator data.', 'otpress'), ['status' => 400]);
        }
        $rpIdHash  = substr($data, 0, 32);
        $flags     = ord($data[32]);
        $signCount = unpack('N', substr($data, 33, 4))[1];

        $result = [
            'rpIdHash'     => $rpIdHash,
            'userPresent'  => (bool) ($flags & 0x01),
            'userVerified' => (bool) ($flags & 0x04),
            'signCount'    => $signCount,
            'aaguid'       => '',
            'credentialId' => '',
            'pem'          => '',
            'alg'          => 0,
        ];

        $has_attested = (bool) ($flags & 0x40); // AT flag.
        if (!$expect_attested) {
            return $result;
        }
        if (!$has_attested) {
            return new WP_Error('otpress_passkey_malformed', __('Passkey attestation data missing.', 'otpress'), ['status' => 400]);
        }
        if (strlen($data) < 55) {
            return new WP_Error('otpress_passkey_malformed', __('Malformed authenticator data.', 'otpress'), ['status' => 400]);
        }

        $aaguid    = substr($data, 37, 16);
        $credLen   = unpack('n', substr($data, 53, 2))[1];
        if ($credLen < 1 || $credLen > 1023 || strlen($data) < 55 + $credLen) {
            return new WP_Error('otpress_passkey_malformed', __('Malformed credential data.', 'otpress'), ['status' => 400]);
        }
        $credId = substr($data, 55, $credLen);

        // The remainder is the COSE-encoded public key.
        $coseRaw = substr($data, 55 + $credLen);
        try {
            [$cose] = OTPress_CBOR::decode_first($coseRaw);
        } catch (Throwable $e) {
            return new WP_Error('otpress_passkey_malformed', __('Could not read the passkey public key.', 'otpress'), ['status' => 400]);
        }

        $pem = self::cose_to_pem(is_array($cose) ? $cose : []);
        if (is_wp_error($pem)) {
            return $pem;
        }

        $result['aaguid']       = $aaguid;
        $result['credentialId'] = $credId;
        $result['pem']          = $pem[0];
        $result['alg']          = $pem[1];
        return $result;
    }

    /**
     * Convert a COSE_Key map to a PEM-wrapped SubjectPublicKeyInfo, returning
     * [pem, alg]. Only EC2/P-256 (ES256) and RSA (RS256) are supported.
     *
     * @return array{0:string,1:int}|WP_Error
     */
    private static function cose_to_pem(array $cose) {
        $kty = isset($cose[1]) ? (int) $cose[1] : 0;
        $alg = isset($cose[3]) ? (int) $cose[3] : 0;

        if (2 === $kty) { // EC2
            if (self::ALG_ES256 !== $alg) {
                return new WP_Error('otpress_passkey_alg', __('Unsupported passkey algorithm.', 'otpress'), ['status' => 400]);
            }
            $crv = isset($cose[-1]) ? (int) $cose[-1] : 0;
            $x   = isset($cose[-2]) ? (string) $cose[-2] : '';
            $y   = isset($cose[-3]) ? (string) $cose[-3] : '';
            if (1 !== $crv || 32 !== strlen($x) || 32 !== strlen($y)) {
                return new WP_Error('otpress_passkey_key', __('Unsupported passkey key.', 'otpress'), ['status' => 400]);
            }
            return [self::ec_p256_pem($x, $y), self::ALG_ES256];
        }

        if (3 === $kty) { // RSA
            if (self::ALG_RS256 !== $alg) {
                return new WP_Error('otpress_passkey_alg', __('Unsupported passkey algorithm.', 'otpress'), ['status' => 400]);
            }
            $n = isset($cose[-1]) ? (string) $cose[-1] : '';
            $e = isset($cose[-2]) ? (string) $cose[-2] : '';
            if ('' === $n || '' === $e) {
                return new WP_Error('otpress_passkey_key', __('Unsupported passkey key.', 'otpress'), ['status' => 400]);
            }
            return [self::rsa_pem($n, $e), self::ALG_RS256];
        }

        return new WP_Error('otpress_passkey_key', __('Unsupported passkey key type.', 'otpress'), ['status' => 400]);
    }

    /**
     * Verify a WebAuthn assertion signature.
     *
     *  - ES256: the assertion signature is ASN.1 DER already; a raw 64-byte
     *    r||s form is also accepted and DER-encoded on the fly.
     *  - RS256: PKCS#1 v1.5 over SHA-256, verified directly.
     */
    private static function verify_signature(int $alg, string $pem, string $signed, string $signature): bool {
        if (!function_exists('openssl_verify')) {
            return false;
        }
        $key = openssl_pkey_get_public($pem);
        if (false === $key) {
            return false;
        }
        if (self::ALG_ES256 === $alg && 64 === strlen($signature)) {
            $signature = self::raw_ecdsa_to_der($signature);
        }
        $ok = openssl_verify($signed, $signature, $key, OPENSSL_ALGO_SHA256);
        return 1 === $ok;
    }

    // ---------------------------------------------------------------------
    // Internal: DER / PEM construction (hand-rolled, no phpseclib)
    // ---------------------------------------------------------------------

    /**
     * P-256 public key as PEM. The algorithm-identifier prefix for an
     * ecPublicKey / prime256v1 SubjectPublicKeyInfo is fixed; only the
     * uncompressed point (0x04 || x || y) varies.
     */
    private static function ec_p256_pem(string $x, string $y): string {
        $point = "\x04" . $x . $y; // uncompressed point, 65 bytes.
        $spki  = self::der_seq(
            self::der_seq(
                self::der_oid('1.2.840.10045.2.1') .   // id-ecPublicKey
                self::der_oid('1.2.840.10045.3.1.7')   // prime256v1 (P-256)
            ) .
            self::der_bitstring($point)
        );
        return self::pem($spki);
    }

    /**
     * RSA public key as PEM from raw big-endian modulus + exponent.
     */
    private static function rsa_pem(string $n, string $e): string {
        $rsaKey = self::der_seq(self::der_int($n) . self::der_int($e));
        $spki   = self::der_seq(
            self::der_seq(
                self::der_oid('1.2.840.113549.1.1.1') . // rsaEncryption
                "\x05\x00"                               // NULL parameters
            ) .
            self::der_bitstring($rsaKey)
        );
        return self::pem($spki);
    }

    private static function pem(string $der): string {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private static function der_len(int $len): string {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xFF) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function der_seq(string $contents): string {
        return "\x30" . self::der_len(strlen($contents)) . $contents;
    }

    private static function der_bitstring(string $contents): string {
        // 0x00 = number of unused bits in the final byte.
        return "\x03" . self::der_len(strlen($contents) + 1) . "\x00" . $contents;
    }

    /**
     * DER INTEGER from an unsigned big-endian byte string. Strips leading
     * zero padding, then re-adds a single 0x00 when the high bit is set so the
     * value stays positive.
     */
    private static function der_int(string $bytes): string {
        $bytes = ltrim($bytes, "\x00");
        if ('' === $bytes) {
            $bytes = "\x00";
        }
        if (0x80 & ord($bytes[0])) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::der_len(strlen($bytes)) . $bytes;
    }

    /**
     * DER OBJECT IDENTIFIER from a dotted string.
     */
    private static function der_oid(string $oid): string {
        $parts = array_map('intval', explode('.', $oid));
        $body  = chr(40 * $parts[0] + $parts[1]);
        $count = count($parts);
        for ($i = 2; $i < $count; $i++) {
            $body .= self::oid_base128($parts[$i]);
        }
        return "\x06" . self::der_len(strlen($body)) . $body;
    }

    private static function oid_base128(int $value): string {
        $out = chr($value & 0x7F);
        $value >>= 7;
        while ($value > 0) {
            $out = chr(0x80 | ($value & 0x7F)) . $out;
            $value >>= 7;
        }
        return $out;
    }

    /**
     * Convert a raw 64-byte ECDSA signature (r||s) to ASN.1 DER.
     */
    private static function raw_ecdsa_to_der(string $sig): string {
        $r = substr($sig, 0, 32);
        $s = substr($sig, 32, 32);
        return self::der_seq(self::der_int($r) . self::der_int($s));
    }

    // ---------------------------------------------------------------------
    // base64url
    // ---------------------------------------------------------------------

    /** Public base64url → binary decode for REST callers. */
    public static function from_b64url(string $txt): string {
        return self::b64url_decode($txt);
    }

    private static function b64url_encode(string $bin): string {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private static function b64url_decode(string $txt): string {
        $txt = self::b64url_normalize($txt);
        if ('' === $txt) {
            return '';
        }
        $padded = str_pad($txt, (int) (ceil(strlen($txt) / 4) * 4), '=', STR_PAD_RIGHT);
        $out    = base64_decode(strtr($padded, '-_', '+/'), true);
        return false === $out ? '' : $out;
    }

    /**
     * Normalise any base64/base64url input to unpadded base64url, or '' when
     * it contains characters outside the alphabet.
     */
    private static function b64url_normalize(string $txt): string {
        $txt = strtr(trim($txt), '+/', '-_');
        $txt = rtrim($txt, '=');
        return preg_match('/^[A-Za-z0-9\-_]*$/', $txt) ? $txt : '';
    }
}
