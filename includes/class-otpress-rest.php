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
                'id_token'    => ['type' => 'string', 'required' => true],
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
                'identifier'  => ['type' => 'string', 'required' => true],
                'password'    => ['type' => 'string', 'required' => true],
                'remember'    => ['type' => 'boolean', 'default' => true],
                'redirect_to' => ['type' => 'string', 'default' => ''],
            ],
        ]);

        register_rest_route(self::NS, '/email-otp/start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'email_otp_start'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => [
                'email' => ['type' => 'string', 'required' => true],
            ],
        ]);

        register_rest_route(self::NS, '/email-otp/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'email_otp_verify'],
            'permission_callback' => [self::class, 'guard'],
            'args'                => [
                'email'       => ['type' => 'string', 'required' => true],
                'code'        => ['type' => 'string', 'required' => true],
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

    public static function email_otp_start(WP_REST_Request $request) {
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

        otpress_establish_session($user, (bool) $request['remember']);

        return self::success($user, (string) $request['redirect_to']);
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

        $claims = OTPress_Token_Verifier::verify((string) $request['id_token']);
        if (is_wp_error($claims)) {
            return self::error($claims, 401);
        }

        $profile = is_array($request['profile']) ? $request['profile'] : [];
        $user    = OTPress_User_Mapper::resolve($claims, $profile);
        if (is_wp_error($user)) {
            return self::error($user, 403);
        }

        otpress_establish_session($user, (bool) $request['remember']);

        return self::success($user, (string) $request['redirect_to']);
    }

    public static function login_password(WP_REST_Request $request) {
        $limited = OTPress_Rate_Limiter::check('password', 10, 10 * MINUTE_IN_SECONDS);
        if (is_wp_error($limited)) {
            return $limited;
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
