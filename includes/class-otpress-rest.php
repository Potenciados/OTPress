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

        register_rest_route(self::NS, '/logout', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'logout'],
            'permission_callback' => [self::class, 'guard'],
        ]);
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

        otpress_establish_session($user, (bool) $request['remember']);

        return self::success($user, (string) $request['redirect_to']);
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

        otpress_establish_session($user, (bool) $request['remember']);

        return self::success($user, (string) $request['redirect_to']);
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

        return self::success($user, (string) $request['redirect_to']);
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

        return new WP_REST_Response([
            'ok'       => true,
            'redirect' => $redirect,
            'user'     => ['display_name' => $user->display_name],
        ]);
    }

    private static function error(WP_Error $error, int $status): WP_Error {
        $data = $error->get_error_data();
        if (!is_array($data) || empty($data['status'])) {
            $error->add_data(['status' => $status]);
        }
        return $error;
    }
}
