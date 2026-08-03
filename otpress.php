<?php
/**
 * Plugin Name:       OTPress
 * Plugin URI:        https://github.com/Potenciados/OTPress
 * Description:       Self-hosted, dependency-free authentication for WordPress & WooCommerce. Phone OTP, Google Sign-In and email link via Firebase Authentication, plus classic password login. A FOSS alternative to Digits with built-in migration.
 * Version:           0.14.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * Author:            OTPress Contributors
 * License:           PolyForm-Noncommercial-1.0.0
 * License URI:       https://polyformproject.org/licenses/noncommercial/1.0.0
 * Text Domain:       otpress
 */

defined('ABSPATH') || exit;

define('OTPRESS_VERSION', '0.14.0');
define('OTPRESS_FILE', __FILE__);
define('OTPRESS_DIR', plugin_dir_path(__FILE__));
define('OTPRESS_URL', plugin_dir_url(__FILE__));

require_once OTPRESS_DIR . 'includes/class-otpress-settings.php';
require_once OTPRESS_DIR . 'includes/class-otpress-jwt.php';
require_once OTPRESS_DIR . 'includes/class-otpress-token-verifier.php';
require_once OTPRESS_DIR . 'includes/class-otpress-user-mapper.php';
require_once OTPRESS_DIR . 'includes/class-otpress-email-otp.php';
require_once OTPRESS_DIR . 'includes/class-otpress-whatsapp-otp.php';
require_once OTPRESS_DIR . 'includes/class-otpress-rate-limiter.php';
require_once OTPRESS_DIR . 'includes/class-otpress-otp-budget.php';
require_once OTPRESS_DIR . 'includes/class-otpress-totp.php';
require_once OTPRESS_DIR . 'includes/class-otpress-cbor.php';
require_once OTPRESS_DIR . 'includes/class-otpress-passkey.php';
require_once OTPRESS_DIR . 'includes/class-otpress-rest.php';
require_once OTPRESS_DIR . 'includes/class-otpress-frontend.php';

add_action('rest_api_init', ['OTPress_REST', 'register_routes']);
add_action('init', ['OTPress_Frontend', 'register_assets']);
add_action('init', ['OTPress_Frontend', 'register_shortcode']);
add_action('admin_menu', ['OTPress_Settings', 'register_admin_page']);
add_action('admin_init', ['OTPress_Settings', 'register_settings']);

/**
 * Log a user in programmatically the way wp-login.php would: set the current
 * user, issue the auth cookie and fire `wp_login` so WooCommerce merges the
 * persistent cart and other plugins run their login hooks.
 */
function otpress_establish_session(WP_User $user, bool $remember = true): void {
    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID, $remember);
    do_action('wp_login', $user->user_login, $user);
}
