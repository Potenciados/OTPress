<?php
defined('ABSPATH') || exit;

/**
 * REST endpoints. All POST endpoints require the `X-OTPress: 1` header:
 * browsers only attach custom headers after a successful CORS preflight,
 * which cross-origin attackers cannot pass, so this doubles as login-CSRF
 * protection without depending on nonces (which go stale on pages served
 * from full-page edge caches).
 */
class OTPress_REST {

    private const NS = 'otpress/v1';

    public static function register_routes(): void {
        register_rest_route(self::NS, '/login/firebase', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'login_firebase'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => [
                'id_token'    => ['type' => 'string', 'default' => ''],
                'ticket'      => ['type' => 'string', 'default' => ''],
                'mode'        => ['type' => 'string', 'default' => '', 'enum' => ['', 'create']],
                'remember'    => ['type' => 'boolean', 'default' => true],
                'redirect_to' => ['type' => 'string', 'default' => ''],
                'profile'     => ['type' => 'object', 'default' => []],
            ],
        ]);

        register_rest_route(self::NS, '/login/password', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'login_password'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => [
                'identifier'      => ['type' => 'string', 'required' => true],
                'password'        => ['type' => 'string', 'required' => true],
                'challenge_token' => ['type' => 'string', 'default' => ''],
                'remember'    => ['type' => 'boolean', 'default' => true],
                'redirect_to' => ['type' => 'string', 'default' => ''],
            ],
        ]);

        register_rest_route(self::NS, '/email-otp/start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'email_otp_start'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => [
                'email'           => ['type' => 'string', 'required' => true],
                'challenge_token' => ['type' => 'string', 'default' => ''],
            ],
        ]);

        register_rest_route(self::NS, '/email-otp/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'email_otp_verify'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => [
                'email'       => ['type' => 'string', 'required' => true],
                'code'        => ['type' => 'string', 'required' => true],
                'link_ticket' => ['type' => 'string', 'default' => ''],
                'remember'    => ['type' => 'boolean', 'default' => true],
                'redirect_to' => ['type' => 'string', 'default' => ''],
                'profile'     => ['type' => 'object', 'default' => []],
            ],
        ]);

        register_rest_route(self::NS, '/whatsapp-otp/start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'whatsapp_otp_start'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => [
                'phone'           => ['type' => 'string', 'required' => true],
                'challenge_token' => ['type' => 'string', 'default' => ''],
            ],
        ]);

        register_rest_route(self::NS, '/otp/precheck', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'otp_precheck'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => ['phone' => ['type' => 'string', 'required' => true]],
        ]);

        register_rest_route(self::NS, '/whatsapp-otp/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'whatsapp_otp_verify'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => [
                'phone'       => ['type' => 'string', 'required' => true],
                'code'        => ['type' => 'string', 'required' => true],
                'link_ticket' => ['type' => 'string', 'default' => ''],
                'remember'    => ['type' => 'boolean', 'default' => true],
                'redirect_to' => ['type' => 'string', 'default' => ''],
                'profile'     => ['type' => 'object', 'default' => []],
            ],
        ]);

        register_rest_route(self::NS, '/logout', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'logout'],
            'permission_callback' => [self::class, 'guard'],
        ]);

        // Two-factor (TOTP).
        register_rest_route(self::NS, '/totp/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'totp_verify'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => ['ticket' => ['type' => 'string', 'required' => true], 'code' => ['type' => 'string', 'required' => true]],
        ]);
        register_rest_route(self::NS, '/totp/enroll/start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'totp_enroll_start'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);
        register_rest_route(self::NS, '/totp/enroll/confirm', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'totp_enroll_confirm'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['code' => ['type' => 'string', 'required' => true]],
        ]);
        register_rest_route(self::NS, '/totp/disable', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'totp_disable'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['code' => ['type' => 'string', 'required' => true]],
        ]);

        // Passkeys (WebAuthn).
        register_rest_route(self::NS, '/passkey/register/options', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'passkey_register_options'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);
        register_rest_route(self::NS, '/passkey/register/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'passkey_register_verify'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => [
                'clientDataJSON'    => ['type' => 'string', 'required' => true],
                'attestationObject' => ['type' => 'string', 'required' => true],
                'name'              => ['type' => 'string', 'default' => ''],
            ],
        ]);
        register_rest_route(self::NS, '/passkey/auth/options', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'passkey_auth_options'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => ['email' => ['type' => 'string', 'default' => '']],
        ]);
        register_rest_route(self::NS, '/passkey/auth/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'passkey_auth_verify'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => [
                'handle'            => ['type' => 'string', 'required' => true],
                'credentialId'      => ['type' => 'string', 'required' => true],
                'authenticatorData' => ['type' => 'string', 'required' => true],
                'clientDataJSON'    => ['type' => 'string', 'required' => true],
                'signature'         => ['type' => 'string', 'required' => true],
                'userHandle'        => ['type' => 'string', 'default' => ''],
                'remember'          => ['type' => 'boolean', 'default' => true],
                'redirect_to'       => ['type' => 'string', 'default' => ''],
            ],
        ]);
        register_rest_route(self::NS, '/passkey/list', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'passkey_list'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);
        register_rest_route(self::NS, '/passkey/remove', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'passkey_remove'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['id' => ['type' => 'string', 'required' => true]],
        ]);

        // Account connections (logged-in only).
        register_rest_route(self::NS, '/prompts/ack', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'prompts_ack'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);
        register_rest_route(self::NS, '/identities', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'identities_list'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);
        register_rest_route(self::NS, '/identities/link', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'identities_link'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['id_token' => ['type' => 'string', 'required' => true]],
        ]);
        register_rest_route(self::NS, '/identities/unlink', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'identities_unlink'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['sub' => ['type' => 'string', 'required' => true]],
        ]);

        // Change email — dual OTP (prove the current address, then the new one).
        register_rest_route(self::NS, '/email/change/start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'email_change_start'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);
        register_rest_route(self::NS, '/email/change/verify-current', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'email_change_verify_current'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['ticket' => ['type' => 'string', 'required' => true], 'code' => ['type' => 'string', 'required' => true]],
        ]);
        register_rest_route(self::NS, '/email/change/send-new', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'email_change_send_new'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['ticket' => ['type' => 'string', 'required' => true], 'email' => ['type' => 'string', 'required' => true]],
        ]);
        register_rest_route(self::NS, '/email/change/confirm', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'email_change_confirm'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['ticket' => ['type' => 'string', 'required' => true], 'code' => ['type' => 'string', 'required' => true]],
        ]);

        // Optional password (opt-in): OTP-gated set, plus disable.
        register_rest_route(self::NS, '/password/set/start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'password_set_start'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);
        register_rest_route(self::NS, '/password/set/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'password_set_verify'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['ticket' => ['type' => 'string', 'required' => true], 'code' => ['type' => 'string', 'required' => true]],
        ]);
        register_rest_route(self::NS, '/password/set/confirm', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'password_set_confirm'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['ticket' => ['type' => 'string', 'required' => true], 'password' => ['type' => 'string', 'required' => true]],
        ]);
        register_rest_route(self::NS, '/password/disable', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'password_disable'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);

        // Active sessions (WP session tokens): list + revoke.
        register_rest_route(self::NS, '/sessions', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'sessions_list'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);
        register_rest_route(self::NS, '/sessions/revoke', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'sessions_revoke'],
            'permission_callback' => [self::class, 'guard_logged_in'],
            'args'                => ['id' => ['type' => 'string', 'required' => true]],
        ]);
        register_rest_route(self::NS, '/sessions/revoke-others', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'sessions_revoke_others'],
            'permission_callback' => [self::class, 'guard_logged_in'],
        ]);
    }

    // ---------------------------------------------------------------------
    // Active sessions: read the raw session_tokens usermeta (keyed by hashed
    // verifier) so each can be listed and revoked individually.
    // ---------------------------------------------------------------------

    private static function current_session_key(): string {
        $token = wp_get_session_token();
        return '' !== $token ? hash('sha256', $token) : '';
    }

    public static function sessions_list(WP_REST_Request $request) {
        $uid      = get_current_user_id();
        $sessions = get_user_meta($uid, 'session_tokens', true);
        $sessions = is_array($sessions) ? $sessions : [];
        $current  = self::current_session_key();
        $out      = [];
        foreach ($sessions as $key => $s) {
            $out[] = [
                'id'         => (string) $key,
                'ip'         => isset($s['ip']) ? (string) $s['ip'] : '',
                'ua'         => isset($s['ua']) ? (string) $s['ua'] : '',
                'login'      => isset($s['login']) ? (int) $s['login'] : 0,
                'expiration' => isset($s['expiration']) ? (int) $s['expiration'] : 0,
                'current'    => '' !== $current && hash_equals((string) $key, $current),
            ];
        }
        // Current session first, then most-recent login.
        usort($out, function ($a, $b) {
            if ($a['current'] !== $b['current']) {
                return $a['current'] ? -1 : 1;
            }
            return $b['login'] <=> $a['login'];
        });
        return new WP_REST_Response(['ok' => true, 'sessions' => $out]);
    }

    public static function sessions_revoke(WP_REST_Request $request) {
        $uid = get_current_user_id();
        $id  = preg_replace('/[^a-f0-9]/', '', strtolower((string) $request->get_param('id')));
        if ('' === $id) {
            return self::error(new WP_Error('otpress_bad_session', __('Unknown session.', 'otpress')), 400);
        }
        if (hash_equals($id, self::current_session_key())) {
            return self::error(new WP_Error('otpress_current_session', __('Use log out to end the current session.', 'otpress')), 400);
        }
        // Let the theme log the ended session before it's gone.
        $all = get_user_meta($uid, 'session_tokens', true);
        if (is_array($all) && isset($all[$id])) {
            do_action('fy_session_ended', $uid, $all[$id], 'revoked');
        }
        $manager = WP_Session_Tokens::get_instance($uid);
        try {
            $m = new ReflectionMethod($manager, 'update_session');
            $m->setAccessible(true);
            $m->invoke($manager, $id, null); // null session = destroy
        } catch (\ReflectionException $e) {
            return self::error(new WP_Error('otpress_revoke_failed', __('Could not end that session.', 'otpress')), 500);
        }
        return new WP_REST_Response(['ok' => true]);
    }

    public static function sessions_revoke_others(WP_REST_Request $request) {
        $uid     = get_current_user_id();
        $current = self::current_session_key();
        $all     = get_user_meta($uid, 'session_tokens', true);
        if (is_array($all)) {
            foreach ($all as $key => $data) {
                if (!hash_equals((string) $key, $current)) {
                    do_action('fy_session_ended', $uid, $data, 'revoked');
                }
            }
        }
        $manager = WP_Session_Tokens::get_instance($uid);
        $manager->destroy_others(wp_get_session_token());
        return new WP_REST_Response(['ok' => true]);
    }

    // ---------------------------------------------------------------------
    // Optional password: OTP-gated so a hijacked session can't silently add
    // a password. set/start emails a code, set/verify proves it, set/confirm
    // stores the password and flips otpress_password_login on.
    // ---------------------------------------------------------------------

    private static function password_ticket(string $id): ?array {
        if (!preg_match('/^[A-Za-z0-9]{40}$/', $id)) {
            return null;
        }
        $t = get_transient('otpress_pwset_' . $id);
        if (!is_array($t) || (int) ($t['user_id'] ?? 0) !== get_current_user_id()) {
            return null;
        }
        return $t;
    }

    public static function password_set_start(WP_REST_Request $request) {
        $user = wp_get_current_user();
        if (!$user || !$user->user_email) {
            return self::error(new WP_Error('otpress_no_email', __('Your account has no email address.', 'otpress')), 400);
        }
        $sent = OTPress_Email_OTP::start($user->user_email);
        if (is_wp_error($sent)) {
            return self::error($sent, 400);
        }
        $id = wp_generate_password(40, false, false);
        set_transient('otpress_pwset_' . $id, ['user_id' => $user->ID, 'ok' => false], 15 * MINUTE_IN_SECONDS);
        return new WP_REST_Response(['ok' => true, 'ticket' => $id, 'email' => $user->user_email]);
    }

    public static function password_set_verify(WP_REST_Request $request) {
        $id = (string) $request->get_param('ticket');
        $t  = self::password_ticket($id);
        if (null === $t) {
            return self::error(new WP_Error('otpress_bad_ticket', __('This request expired. Please start again.', 'otpress')), 400);
        }
        $ok = OTPress_Email_OTP::verify(wp_get_current_user()->user_email, (string) $request->get_param('code'));
        if (is_wp_error($ok)) {
            return self::error($ok, 400);
        }
        $t['ok'] = true;
        set_transient('otpress_pwset_' . $id, $t, 15 * MINUTE_IN_SECONDS);
        return new WP_REST_Response(['ok' => true]);
    }

    public static function password_set_confirm(WP_REST_Request $request) {
        $id = (string) $request->get_param('ticket');
        $t  = self::password_ticket($id);
        if (null === $t || empty($t['ok'])) {
            return self::error(new WP_Error('otpress_bad_ticket', __('Please verify the code first.', 'otpress')), 400);
        }
        $password = (string) $request->get_param('password');
        if (strlen($password) < 8) {
            return self::error(new WP_Error('otpress_weak_password', __('Use at least 8 characters.', 'otpress')), 400);
        }
        $uid = get_current_user_id();
        // wp_set_password() destroys every session (including this one); re-issue
        // the auth cookie so the user stays logged in after setting it.
        wp_set_password($password, $uid);
        wp_set_auth_cookie($uid, true);
        update_user_meta($uid, 'otpress_password_login', '1');
        delete_transient('otpress_pwset_' . $id);
        return new WP_REST_Response(['ok' => true]);
    }

    public static function password_disable(WP_REST_Request $request) {
        $uid = get_current_user_id();
        // Scramble the stored hash so the old password can't be reused, and
        // turn password login back off. OTP/social/passkey remain.
        wp_set_password(wp_generate_password(64, true, true), $uid);
        wp_set_auth_cookie($uid, true);
        delete_user_meta($uid, 'otpress_password_login');
        return new WP_REST_Response(['ok' => true]);
    }

    // ---------------------------------------------------------------------
    // Change email (dual OTP): prove ownership of the current address, then
    // of the new one, before swapping user_email. Ticket carries the state.
    // ---------------------------------------------------------------------

    private static function email_change_ticket(string $id): ?array {
        if (!preg_match('/^[A-Za-z0-9]{40}$/', $id)) {
            return null;
        }
        $t = get_transient('otpress_emailchg_' . $id);
        if (!is_array($t) || (int) ($t['user_id'] ?? 0) !== get_current_user_id()) {
            return null;
        }
        return $t;
    }

    private static function email_change_save(string $id, array $t): void {
        set_transient('otpress_emailchg_' . $id, $t, 15 * MINUTE_IN_SECONDS);
    }

    public static function email_change_start(WP_REST_Request $request) {
        $user = wp_get_current_user();
        if (!$user || !$user->user_email) {
            return self::error(new WP_Error('otpress_no_email', __('Your account has no email address.', 'otpress')), 400);
        }
        $sent = OTPress_Email_OTP::start($user->user_email);
        if (is_wp_error($sent)) {
            return self::error($sent, 400);
        }
        $id = wp_generate_password(40, false, false);
        self::email_change_save($id, ['user_id' => $user->ID, 'current_ok' => false, 'new_email' => '']);
        return new WP_REST_Response(['ok' => true, 'ticket' => $id, 'email' => $user->user_email]);
    }

    public static function email_change_verify_current(WP_REST_Request $request) {
        $id = (string) $request->get_param('ticket');
        $t  = self::email_change_ticket($id);
        if (null === $t) {
            return self::error(new WP_Error('otpress_bad_ticket', __('This request expired. Please start again.', 'otpress')), 400);
        }
        $ok = OTPress_Email_OTP::verify(wp_get_current_user()->user_email, (string) $request->get_param('code'));
        if (is_wp_error($ok)) {
            return self::error($ok, 400);
        }
        $t['current_ok'] = true;
        self::email_change_save($id, $t);
        return new WP_REST_Response(['ok' => true]);
    }

    public static function email_change_send_new(WP_REST_Request $request) {
        $id = (string) $request->get_param('ticket');
        $t  = self::email_change_ticket($id);
        if (null === $t || empty($t['current_ok'])) {
            return self::error(new WP_Error('otpress_bad_ticket', __('Please verify your current email first.', 'otpress')), 400);
        }
        $new = sanitize_email((string) $request->get_param('email'));
        if (!is_email($new)) {
            return self::error(new WP_Error('otpress_bad_email', __('Please enter a valid email address.', 'otpress')), 400);
        }
        if (strtolower($new) === strtolower(wp_get_current_user()->user_email)) {
            return self::error(new WP_Error('otpress_same_email', __('That is already your email address.', 'otpress')), 400);
        }
        $existing = email_exists($new);
        if ($existing && (int) $existing !== get_current_user_id()) {
            return self::error(new WP_Error('otpress_email_taken', __('That email is already in use.', 'otpress')), 409);
        }
        $sent = OTPress_Email_OTP::start($new);
        if (is_wp_error($sent)) {
            return self::error($sent, 400);
        }
        $t['new_email'] = $new;
        self::email_change_save($id, $t);
        return new WP_REST_Response(['ok' => true, 'email' => $new]);
    }

    public static function email_change_confirm(WP_REST_Request $request) {
        $id = (string) $request->get_param('ticket');
        $t  = self::email_change_ticket($id);
        if (null === $t || empty($t['current_ok']) || empty($t['new_email'])) {
            return self::error(new WP_Error('otpress_bad_ticket', __('This request expired. Please start again.', 'otpress')), 400);
        }
        $new = (string) $t['new_email'];
        $ok  = OTPress_Email_OTP::verify($new, (string) $request->get_param('code'));
        if (is_wp_error($ok)) {
            return self::error($ok, 400);
        }
        // Re-check availability at the last moment (race window).
        $existing = email_exists($new);
        if ($existing && (int) $existing !== get_current_user_id()) {
            return self::error(new WP_Error('otpress_email_taken', __('That email is already in use.', 'otpress')), 409);
        }
        $res = wp_update_user(['ID' => get_current_user_id(), 'user_email' => $new]);
        if (is_wp_error($res)) {
            return self::error($res, 400);
        }
        update_user_meta(get_current_user_id(), 'otpress_email_verified', $new);
        delete_transient('otpress_emailchg_' . $id);
        return new WP_REST_Response(['ok' => true, 'email' => $new]);
    }

    /** Guard + require a validated logged-in cookie (REST-without-nonce = user 0). */
    public static function guard_logged_in(WP_REST_Request $request) {
        $g = self::guard($request);
        if (is_wp_error($g)) {
            return $g;
        }
        $uid = wp_validate_auth_cookie('', 'logged_in');
        if (!$uid) {
            return new WP_Error('otpress_forbidden', 'Not authenticated.', ['status' => 401]);
        }
        wp_set_current_user($uid);
        return true;
    }

    public static function identities_list() {
        return new WP_REST_Response([
            'ok'         => true,
            'identities' => OTPress_User_Mapper::get_identities(get_current_user_id()),
        ]);
    }

    public static function identities_link(WP_REST_Request $request) {
        $claims = OTPress_Token_Verifier::verify((string) $request['id_token']);
        if (is_wp_error($claims)) {
            return self::error($claims, 401);
        }
        $sub = (string) ($claims['sub'] ?? '');
        // Refuse if this identity is already attached to a DIFFERENT account.
        if ('' !== $sub) {
            $owner = get_users(['meta_key' => 'otpress_firebase_uid', 'meta_value' => $sub, 'number' => 1, 'fields' => 'ids']);
            if ($owner && (int) $owner[0] !== get_current_user_id()) {
                return new WP_Error('otpress_identity_taken', __('That account is already linked to another user.', 'otpress'), ['status' => 409]);
            }
        }
        OTPress_User_Mapper::link_identity(get_current_user_id(), $claims);
        return new WP_REST_Response(['ok' => true, 'identities' => OTPress_User_Mapper::get_identities(get_current_user_id())]);
    }

    public static function identities_unlink(WP_REST_Request $request) {
        $result = OTPress_User_Mapper::unlink_identity(get_current_user_id(), (string) $request['sub']);
        if (is_wp_error($result)) {
            return self::error($result, 400);
        }
        return new WP_REST_Response(['ok' => true, 'identities' => OTPress_User_Mapper::get_identities(get_current_user_id())]);
    }

    /**
     * Cloudflare Turnstile check. A no-op until a secret key is configured;
     * with one set, abuse-sensitive endpoints demand a valid token before
     * doing anything expensive (sending mail, hitting the password check).
     *
     * @return true|WP_Error
     */
    private static function verify_challenge(WP_REST_Request $request) {
        $secret = OTPress_Settings::get('turnstile_secret_key');
        if ('' === $secret) {
            return true;
        }
        // Authenticated sessions (validated cookie, not just the REST
        // context) skip the bot challenge: rate limits still apply and a
        // logged-in cookie is a stronger signal than a Turnstile token.
        if (wp_validate_auth_cookie('', 'logged_in')) {
            return true;
        }
        $token = (string) $request['challenge_token'];
        $error = new WP_Error('otpress_challenge', __('Security check failed. Please try again.', 'otpress'), ['status' => 403]);
        if ('' === $token) {
            return $error;
        }
        $response = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
            'timeout' => 10,
            'body'    => [
                'secret'   => $secret,
                'response' => $token,
                'remoteip' => (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
            ],
        ]);
        if (is_wp_error($response)) {
            return $error;
        }
        $body = json_decode(wp_remote_retrieve_body($response), true);
        return !empty($body['success']) ? true : $error;
    }

    public static function email_otp_start(WP_REST_Request $request) {
        $challenge = self::verify_challenge($request);
        if (is_wp_error($challenge)) {
            return $challenge;
        }

        $email = sanitize_email((string) $request['email']);

        $ip_limited = OTPress_Rate_Limiter::check('eotp_start_ip', 10, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($ip_limited)) {
            return $ip_limited;
        }
        $email_limited = OTPress_Rate_Limiter::check('eotp_start_email', 3, 10 * MINUTE_IN_SECONDS, strtolower($email));
        if (is_wp_error($email_limited)) {
            return $email_limited;
        }

        $sent = OTPress_Email_OTP::start($email);
        if (is_wp_error($sent)) {
            return self::error($sent, 400);
        }

        return new WP_REST_Response(['ok' => true]);
    }

    public static function email_otp_verify(WP_REST_Request $request) {
        $limited = OTPress_Rate_Limiter::check('eotp_verify', 10, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($limited)) {
            return $limited;
        }

        $email  = sanitize_email((string) $request['email']);
        $result = OTPress_Email_OTP::verify($email, (string) $request['code']);
        if (is_wp_error($result)) {
            return self::error($result, 401);
        }

        // Inbox ownership proven: treat as a verified email identity.
        $profile = is_array($request['profile']) ? $request['profile'] : [];
        $user    = OTPress_User_Mapper::resolve(
            ['email' => $email, 'email_verified' => true],
            $profile
        );
        if (is_wp_error($user)) {
            return self::error($user, 403);
        }

        $link_ticket = (string) $request['link_ticket'];
        if ('' !== $link_ticket) {
            $claims = self::ticket_claims($link_ticket);
            if (is_array($claims)) {
                // Inbox ownership of this account's email was just proven, so
                // permanently attach the federated identity to it.
                OTPress_User_Mapper::link_identity($user->ID, $claims);
                self::consume_ticket($link_ticket);
            }
        }

        return self::finish_login($user, (bool) $request['remember'], (string) $request['redirect_to']);
    }

    public static function whatsapp_otp_start(WP_REST_Request $request) {
        $challenge = self::verify_challenge($request);
        if (is_wp_error($challenge)) {
            return $challenge;
        }

        $phone = preg_replace('/[^\d+]/', '', (string) $request['phone']);

        $ip_limited = OTPress_Rate_Limiter::check('waotp_start_ip', 10, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($ip_limited)) {
            return $ip_limited;
        }
        $phone_limited = OTPress_Rate_Limiter::check('waotp_start_phone', 3, 10 * MINUTE_IN_SECONDS, $phone);
        if (is_wp_error($phone_limited)) {
            return $phone_limited;
        }

        // Paid channel: refuse past the monthly allowance (paying customers
        // are exempt) and point the caller at the free email code.
        $budget = OTPress_OTP_Budget::check($phone, 'whatsapp');
        if (is_wp_error($budget)) {
            return self::error($budget, 429);
        }

        // A number we already know is signing in; a new one is signing up.
        $known   = class_exists('OTPress_User_Mapper') && OTPress_User_Mapper::find_by_phone($phone);
        $context = $known ? 'login' : 'signup';

        $sent = OTPress_WhatsApp_OTP::start($phone, $context);
        if (is_wp_error($sent)) {
            return self::error($sent, 400);
        }
        OTPress_OTP_Budget::record($phone);

        return new WP_REST_Response(['ok' => true]);
    }

    /**
     * Spend check before the client starts a Firebase SMS verification.
     * Firebase sends that message from the browser, so this is the only place
     * we can refuse it — the WhatsApp path is gated server-side in its own
     * handler.
     */
    public static function otp_precheck(WP_REST_Request $request) {
        $phone  = preg_replace('/[^\d+]/', '', (string) $request['phone']);
        $budget = OTPress_OTP_Budget::check($phone, 'sms');
        if (is_wp_error($budget)) {
            return self::error($budget, 429);
        }
        OTPress_OTP_Budget::record($phone);
        return new WP_REST_Response(['ok' => true]);
    }

    public static function whatsapp_otp_verify(WP_REST_Request $request) {
        $limited = OTPress_Rate_Limiter::check('waotp_verify', 10, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($limited)) {
            return $limited;
        }

        $phone  = preg_replace('/[^\d+]/', '', (string) $request['phone']);
        $result = OTPress_WhatsApp_OTP::verify($phone, (string) $request['code']);
        if (is_wp_error($result)) {
            return self::error($result, 401);
        }

        // Possession of the number proven: verified phone identity, same
        // decision flow as federated sign-ins (link-choice when unmatched).
        $claims  = ['phone_number' => $phone];
        $profile = is_array($request['profile']) ? $request['profile'] : [];
        $user    = OTPress_User_Mapper::resolve($claims, $profile, false);

        if (is_wp_error($user) && 'otpress_no_match' === $user->get_error_code()) {
            return new WP_REST_Response([
                'ok'     => false,
                'code'   => 'otpress_link_choice',
                'ticket' => self::issue_link_ticket($claims),
                'email'  => '',
            ]);
        }
        if (is_wp_error($user)) {
            return self::error($user, 403);
        }

        $link_ticket = (string) $request['link_ticket'];
        if ('' !== $link_ticket) {
            $ticket_claims = self::ticket_claims($link_ticket);
            if (is_array($ticket_claims)) {
                OTPress_User_Mapper::link_identity($user->ID, $ticket_claims);
                self::consume_ticket($link_ticket);
            }
        }

        return self::finish_login($user, (bool) $request['remember'], (string) $request['redirect_to']);
    }

    /**
     * Complete a login, gating on 2FA: if the user has TOTP enabled, DON'T
     * grant the session — revert any partial auth, stash a short-lived
     * ticket, and tell the client a second factor is required.
     */
    private static function finish_login(WP_User $user, bool $remember, string $redirect) {
        if (class_exists('OTPress_TOTP') && OTPress_TOTP::is_enabled($user->ID)) {
            wp_clear_auth_cookie();
            wp_set_current_user(0);
            $id = wp_generate_password(40, false, false);
            set_transient('otpress_2fa_' . $id, [
                'user_id'  => $user->ID,
                'remember' => $remember,
                'redirect' => $redirect,
            ], 10 * MINUTE_IN_SECONDS);
            return new WP_REST_Response(['ok' => false, 'code' => 'otpress_2fa_required', 'ticket' => $id]);
        }
        otpress_establish_session($user, $remember);
        return self::success($user, $redirect);
    }

    public static function totp_verify(WP_REST_Request $request) {
        $limited = OTPress_Rate_Limiter::check('totp_verify', 10, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($limited)) {
            return $limited;
        }
        $id  = (string) $request['ticket'];
        $key = preg_match('/^[A-Za-z0-9]{40}$/', $id) ? 'otpress_2fa_' . $id : '';
        $data = $key ? get_transient($key) : false;
        if (!is_array($data) || empty($data['user_id'])) {
            return new WP_Error('otpress_2fa_expired', __('This sign-in attempt expired. Please try again.', 'otpress'), ['status' => 401]);
        }
        if (!OTPress_TOTP::verify_for_user((int) $data['user_id'], (string) $request['code'])) {
            return new WP_Error('otpress_2fa_invalid', __('Incorrect code. Please try again.', 'otpress'), ['status' => 401]);
        }
        delete_transient($key);
        $user = get_user_by('id', (int) $data['user_id']);
        if (!$user) {
            return new WP_Error('otpress_2fa_invalid', __('Account not found.', 'otpress'), ['status' => 401]);
        }
        otpress_establish_session($user, (bool) $data['remember']);
        return self::success($user, (string) $data['redirect']);
    }

    public static function totp_enroll_start() {
        $uid    = get_current_user_id();
        $secret = OTPress_TOTP::generate_secret();
        set_transient('otpress_totp_pending_' . $uid, $secret, 10 * MINUTE_IN_SECONDS);
        $user = wp_get_current_user();
        return new WP_REST_Response([
            'ok'     => true,
            'secret' => $secret,
            'uri'    => OTPress_TOTP::provisioning_uri($secret, $user->user_email ?: $user->user_login, get_bloginfo('name')),
        ]);
    }

    public static function totp_enroll_confirm(WP_REST_Request $request) {
        $uid    = get_current_user_id();
        $secret = get_transient('otpress_totp_pending_' . $uid);
        if (!is_string($secret) || '' === $secret) {
            return new WP_Error('otpress_totp_expired', __('Setup expired. Please start again.', 'otpress'), ['status' => 400]);
        }
        if (!OTPress_TOTP::verify($secret, (string) $request['code'])) {
            return new WP_Error('otpress_totp_invalid', __('Incorrect code. Please check and try again.', 'otpress'), ['status' => 400]);
        }
        OTPress_TOTP::enroll($uid, $secret);
        delete_transient('otpress_totp_pending_' . $uid);
        return new WP_REST_Response(['ok' => true, 'recovery_codes' => OTPress_TOTP::generate_recovery_codes($uid)]);
    }

    public static function totp_disable(WP_REST_Request $request) {
        $uid = get_current_user_id();
        if (!OTPress_TOTP::verify_for_user($uid, (string) $request['code'])) {
            return new WP_Error('otpress_totp_invalid', __('Incorrect code.', 'otpress'), ['status' => 400]);
        }
        OTPress_TOTP::disable($uid);
        return new WP_REST_Response(['ok' => true]);
    }

    // ---------------------------------------------------------------------
    // Passkeys (WebAuthn)
    // ---------------------------------------------------------------------

    public static function passkey_register_options() {
        $options = OTPress_Passkey::registration_options(wp_get_current_user());
        return new WP_REST_Response(['ok' => true, 'options' => $options]);
    }

    public static function passkey_register_verify(WP_REST_Request $request) {
        $client = json_decode(OTPress_Passkey::from_b64url((string) $request['clientDataJSON']), true);
        if (!is_array($client)) {
            return new WP_Error('otpress_passkey_malformed', __('Could not read the passkey response.', 'otpress'), ['status' => 400]);
        }
        $attestation = OTPress_Passkey::from_b64url((string) $request['attestationObject']);
        $result = OTPress_Passkey::verify_registration(wp_get_current_user(), $client, $attestation, (string) $request['name']);
        if (is_wp_error($result)) {
            return self::error($result, 400);
        }
        return new WP_REST_Response(['ok' => true, 'passkeys' => OTPress_Passkey::list_credentials(get_current_user_id())]);
    }

    public static function passkey_auth_options(WP_REST_Request $request) {
        $limited = OTPress_Rate_Limiter::check('passkey_auth', 20, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($limited)) {
            return $limited;
        }
        $user  = null;
        $email = sanitize_email((string) $request['email']);
        if ('' !== $email) {
            $found = get_user_by('email', $email);
            if ($found) {
                $user = $found;
            }
        }
        return new WP_REST_Response(['ok' => true, 'options' => OTPress_Passkey::authentication_options($user)]);
    }

    public static function passkey_auth_verify(WP_REST_Request $request) {
        $limited = OTPress_Rate_Limiter::check('passkey_verify', 20, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($limited)) {
            return $limited;
        }
        $user = OTPress_Passkey::verify_authentication([
            'handle'            => (string) $request['handle'],
            'credentialId'      => (string) $request['credentialId'],
            'authenticatorData' => (string) $request['authenticatorData'],
            'clientDataJSON'    => (string) $request['clientDataJSON'],
            'signature'         => (string) $request['signature'],
        ]);
        if (is_wp_error($user)) {
            return self::error($user, 401);
        }
        // Passkeys are already strong auth, but route through finish_login so
        // an enrolled TOTP factor still gates and session/redirect handling
        // matches every other login path.
        return self::finish_login($user, (bool) $request['remember'], (string) $request['redirect_to']);
    }

    public static function passkey_list() {
        return new WP_REST_Response(['ok' => true, 'passkeys' => OTPress_Passkey::list_credentials(get_current_user_id())]);
    }

    public static function passkey_remove(WP_REST_Request $request) {
        $result = OTPress_Passkey::remove_credential(get_current_user_id(), (string) $request['id']);
        if (is_wp_error($result)) {
            return self::error($result, 400);
        }
        return new WP_REST_Response(['ok' => true, 'passkeys' => OTPress_Passkey::list_credentials(get_current_user_id())]);
    }

    private static function issue_link_ticket(array $claims): string {
        $id = wp_generate_password(40, false, false);
        set_transient('otpress_link_' . $id, $claims, 10 * MINUTE_IN_SECONDS);
        return $id;
    }

    private static function ticket_claims(string $id): ?array {
        if (!preg_match('/^[A-Za-z0-9]{40}$/', $id)) {
            return null;
        }
        $claims = get_transient('otpress_link_' . $id);
        return is_array($claims) ? $claims : null;
    }

    private static function consume_ticket(string $id): void {
        delete_transient('otpress_link_' . $id);
    }

    /**
     * Password login is opt-in per user: usermeta `otpress_password_login`
     * enables it; administrators are always allowed so the back office can
     * never lock itself out. Everyone else gets the same generic failure as
     * a wrong password, so the flag's existence is not observable.
     */
    private static function password_allowed(WP_User $user): bool {
        $allowed = '1' === get_user_meta($user->ID, 'otpress_password_login', true)
            || user_can($user, 'manage_options');

        /**
         * Filter whether this user may log in with a password.
         *
         * @param bool    $allowed
         * @param WP_User $user
         */
        return (bool) apply_filters('otpress_password_login_allowed', $allowed, $user);
    }

    /**
     * Shared request guard: custom header + same-origin check.
     */
    public static function guard(WP_REST_Request $request) {
        if ('1' !== $request->get_header('x-otpress')) {
            return new WP_Error('otpress_forbidden', 'Missing request header.', ['status' => 403]);
        }
        $origin = $request->get_header('origin');
        if ($origin) {
            $origin_host = wp_parse_url($origin, PHP_URL_HOST);
            $site_host   = wp_parse_url(home_url(), PHP_URL_HOST);
            if ($origin_host && $site_host && !hash_equals($site_host, $origin_host)) {
                return new WP_Error('otpress_forbidden', 'Cross-origin request rejected.', ['status' => 403]);
            }
        }
        return true;
    }

    public static function login_firebase(WP_REST_Request $request) {
        $limited = OTPress_Rate_Limiter::check('firebase', 20, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($limited)) {
            return $limited;
        }

        $id_token = (string) $request['id_token'];
        $ticket   = (string) $request['ticket'];
        $mode     = (string) $request['mode'];

        if ('' !== $id_token) {
            $claims = OTPress_Token_Verifier::verify($id_token);
            if (is_wp_error($claims)) {
                return self::error($claims, 401);
            }
        } elseif ('' !== $ticket) {
            // A ticket carries claims from a token this endpoint already
            // verified moments ago (see the link-choice response below).
            $claims = self::ticket_claims($ticket);
            if (null === $claims) {
                return new WP_Error('otpress_ticket_expired', __('This sign-in attempt expired. Please try again.', 'otpress'), ['status' => 401]);
            }
        } else {
            return new WP_Error('otpress_bad_request', __('Missing credentials.', 'otpress'), ['status' => 400]);
        }

        $profile = is_array($request['profile']) ? $request['profile'] : [];
        $user    = OTPress_User_Mapper::resolve($claims, $profile, 'create' === $mode);

        if (is_wp_error($user) && 'otpress_no_match' === $user->get_error_code()) {
            // Nothing matched this identity. Instead of silently creating a
            // duplicate account, hand the client a short-lived ticket so the
            // user can choose: create fresh, or link to an existing account
            // by proving its email via OTP.
            return new WP_REST_Response([
                'ok'     => false,
                'code'   => 'otpress_link_choice',
                'ticket' => self::issue_link_ticket($claims),
                'email'  => sanitize_email((string) ($claims['email'] ?? '')),
            ]);
        }
        if (is_wp_error($user) && 'otpress_email_unverified' === $user->get_error_code()) {
            // Unverified provider email colliding with an existing account:
            // same remedy as no-match linking — prove the inbox via OTP.
            // Ship a ticket so the verify step attaches this identity too.
            return new WP_REST_Response([
                'ok'     => false,
                'code'   => 'otpress_email_unverified',
                'ticket' => self::issue_link_ticket($claims),
                'email'  => sanitize_email((string) ($claims['email'] ?? '')),
            ]);
        }
        if (is_wp_error($user)) {
            return self::error($user, 403);
        }
        if ('' !== $ticket) {
            self::consume_ticket($ticket);
        }

        return self::finish_login($user, (bool) $request['remember'], (string) $request['redirect_to']);
    }

    public static function login_password(WP_REST_Request $request) {
        $limited = OTPress_Rate_Limiter::check('password', 10, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($limited)) {
            return $limited;
        }

        $challenge = self::verify_challenge($request);
        if (is_wp_error($challenge)) {
            return $challenge;
        }

        $identifier = trim((string) $request['identifier']);
        $login      = $identifier;

        if (is_email($identifier)) {
            $user = get_user_by('email', $identifier);
            $login = $user ? $user->user_login : $identifier;
        } elseif (preg_match('/^\+?[\d\s\-()]{8,20}$/', $identifier)) {
            $phone = preg_replace('/[^\d+]/', '', $identifier);
            foreach (OTPress_Settings::phone_meta_keys() as $meta_key) {
                $found = get_users(['meta_key' => $meta_key, 'meta_value' => $phone, 'number' => 1, 'fields' => 'all']);
                if ($found) {
                    $login = $found[0]->user_login;
                    break;
                }
            }
        }

        $target = get_user_by('login', $login);
        if (!$target || !self::password_allowed($target)) {
            // Same generic message as a wrong password: no way to probe
            // whether an account exists or has password login enabled.
            return new WP_Error('otpress_bad_credentials', __('Incorrect login details.', 'otpress'), ['status' => 401]);
        }

        $user = wp_signon([
            'user_login'    => $login,
            'user_password' => (string) $request['password'],
            'remember'      => (bool) $request['remember'],
        ]);

        if (is_wp_error($user)) {
            // Deliberately generic: do not disclose which part was wrong.
            return new WP_Error('otpress_bad_credentials', __('Incorrect login details.', 'otpress'), ['status' => 401]);
        }

        wp_set_current_user($user->ID);

        return self::finish_login($user, (bool) $request['remember'], (string) $request['redirect_to']);
    }

    public static function logout() {
        // Cookie-authenticated REST requests without a nonce run as user 0,
        // so validate the logged-in cookie directly instead of relying on
        // is_user_logged_in().
        $user_id = wp_validate_auth_cookie('', 'logged_in');
        if ($user_id) {
            wp_set_current_user($user_id);
            wp_logout();
        }
        return new WP_REST_Response(['ok' => true, 'redirect' => home_url('/')]);
    }

    private static function success(WP_User $user, string $redirect_to): WP_REST_Response {
        $redirect = '' !== $redirect_to ? wp_validate_redirect($redirect_to, home_url('/')) : '';
        if ('' === $redirect) {
            $redirect = home_url('/');
        }
        /**
         * Filter the post-login redirect URL.
         *
         * @param string  $redirect
         * @param WP_User $user
         */
        $redirect = apply_filters('otpress_login_redirect', $redirect, $user);

        $payload = [
            'ok'       => true,
            'redirect' => $redirect,
            'user'     => ['display_name' => $user->display_name],
            'prompts'  => self::pending_prompts($user->ID),
        ];

        /**
         * Filter the whole successful-login response payload. Lets the theme
         * attach extra keys (e.g. an `onboarding` object for a just-created
         * account) without the plugin needing to know about them.
         *
         * @param array   $payload
         * @param WP_User $user
         */
        $payload = apply_filters('otpress_login_payload', $payload, $user);

        return new WP_REST_Response($payload);
    }

    /**
     * Proactive one-time invitations to surface right after login (2FA,
     * passkey). Each is offered at most once per user: the client shows it,
     * then POSTs /prompts/ack to set the "offered" flag regardless of the
     * user's choice, so it never reappears. Already-configured features are
     * skipped outright.
     */
    private static function pending_prompts(int $user_id): array {
        $prompts = [];
        if (class_exists('OTPress_TOTP')
            && !OTPress_TOTP::is_enabled($user_id)
            && '1' !== get_user_meta($user_id, 'otpress_2fa_offered', true)) {
            $prompts[] = '2fa';
        }
        if (class_exists('OTPress_Passkey')
            && !OTPress_Passkey::has_credentials($user_id)
            && '1' !== get_user_meta($user_id, 'otpress_passkey_offered', true)) {
            $prompts[] = 'passkey';
        }
        return $prompts;
    }

    /** Mark a proactive invitation as offered so it never shows again. */
    public static function prompts_ack(WP_REST_Request $request) {
        $name = preg_replace('/[^a-z0-9_]/', '', (string) $request->get_param('name'));
        $allowed = ['2fa', 'passkey'];
        if (!in_array($name, $allowed, true)) {
            return self::error(new WP_Error('otpress_bad_prompt', __('Unknown prompt.', 'otpress')), 400);
        }
        update_user_meta(get_current_user_id(), "otpress_{$name}_offered", '1');
        return new WP_REST_Response(['ok' => true]);
    }

    private static function error(WP_Error $error, int $status): WP_Error {
        $data = $error->get_error_data();
        if (!is_array($data) || empty($data['status'])) {
            $error->add_data(['status' => $status]);
        }
        return $error;
    }
}
