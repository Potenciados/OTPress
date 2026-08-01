<?php
defined('ABSPATH') || exit;

/**
 * Front-end integration. The JS module is registered but NOT auto-enqueued:
 * themes enqueue it on their auth screens and bind it to their own markup.
 * The [otpress_form] shortcode ships a minimal, class-hooked default form so
 * the plugin is usable standalone on sites without a custom theme.
 */
class OTPress_Frontend {

    public static function register_assets(): void {
        wp_register_script_module(
            'otpress',
            OTPRESS_URL . 'assets/js/otpress.js',
            [],
            OTPRESS_VERSION
        );
    }

    public static function register_shortcode(): void {
        add_shortcode('otpress_form', [self::class, 'render_shortcode']);
    }

    /**
     * Enqueue the module and print the boot config. Call from the theme (or
     * rely on the shortcode calling it).
     */
    public static function boot(): void {
        if (!OTPress_Settings::is_configured()) {
            return;
        }
        wp_enqueue_script_module('otpress');
        add_action('wp_footer', [self::class, 'print_config'], 5);
    }

    public static function print_config(): void {
        static $printed = false;
        if ($printed) {
            return;
        }
        $printed = true;

        $config = [
            'restUrl'  => esc_url_raw(rest_url('otpress/v1')),
            'firebase' => OTPress_Settings::firebase_config(),
            'i18n'     => [
                'genericError' => __('Something went wrong. Please try again.', 'otpress'),
                'codeSent'     => __('We sent you a verification code.', 'otpress'),
            ],
        ];
        printf(
            '<script id="otpress-config">window.OTPRESS = %s;</script>',
            wp_json_encode($config)
        );
    }

    public static function render_shortcode($atts = []): string {
        $atts = shortcode_atts(['redirect' => ''], $atts, 'otpress_form');
        self::boot();

        $redirect = esc_attr($atts['redirect']);
        ob_start();
        ?>
        <div class="otpress-form" data-otpress-form data-redirect="<?php echo $redirect; ?>">
            <form data-otpress-email novalidate>
                <label class="otpress-label"><?php esc_html_e('Email address', 'otpress'); ?>
                    <input class="otpress-input" type="email" name="email" autocomplete="email" required>
                </label>
                <button class="otpress-button" type="submit"><?php esc_html_e('Continue', 'otpress'); ?></button>
            </form>
            <form data-otpress-email-code hidden novalidate>
                <label class="otpress-label"><?php esc_html_e('Verification code', 'otpress'); ?>
                    <input class="otpress-input" inputmode="numeric" name="code" autocomplete="one-time-code" required>
                </label>
                <button class="otpress-button" type="submit"><?php esc_html_e('Verify', 'otpress'); ?></button>
            </form>
            <form data-otpress-password hidden novalidate>
                <label class="otpress-label"><?php esc_html_e('Email, username or phone', 'otpress'); ?>
                    <input class="otpress-input" type="text" name="identifier" autocomplete="username" required>
                </label>
                <label class="otpress-label"><?php esc_html_e('Password', 'otpress'); ?>
                    <input class="otpress-input" type="password" name="password" autocomplete="current-password" required>
                </label>
                <button class="otpress-button" type="submit"><?php esc_html_e('Sign in', 'otpress'); ?></button>
            </form>
            <button class="otpress-button otpress-button--google" type="button" data-otpress-google><?php esc_html_e('Continue with Google', 'otpress'); ?></button>
            <form data-otpress-phone novalidate>
                <label class="otpress-label"><?php esc_html_e('Phone number', 'otpress'); ?>
                    <input class="otpress-input" type="tel" name="phone" autocomplete="tel" placeholder="+34600000000" required>
                </label>
                <div data-otpress-recaptcha></div>
                <button class="otpress-button" type="submit"><?php esc_html_e('Send code', 'otpress'); ?></button>
            </form>
            <form data-otpress-code hidden novalidate>
                <label class="otpress-label"><?php esc_html_e('Verification code', 'otpress'); ?>
                    <input class="otpress-input" inputmode="numeric" name="code" autocomplete="one-time-code" required>
                </label>
                <button class="otpress-button" type="submit"><?php esc_html_e('Verify', 'otpress'); ?></button>
            </form>
            <p class="otpress-message" data-otpress-message role="status" aria-live="polite"></p>
        </div>
        <script type="module">
            import * as OTPress from '<?php echo esc_url(OTPRESS_URL . 'assets/js/otpress.js?v=' . OTPRESS_VERSION); ?>';
            OTPress.autobind();
        </script>
        <?php
        return (string) ob_get_clean();
    }
}
