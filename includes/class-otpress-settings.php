<?php
defined('ABSPATH') || exit;

/**
 * Settings access with constants-first resolution.
 *
 * Every key can be overridden with a PHP constant (e.g. in Bedrock's
 * config/application.php) named OTPRESS_<KEY_IN_UPPERCASE>. Otherwise the
 * value is read from the `otpress_settings` option, editable under
 * Settings → OTPress. The Firebase web config values (apiKey, authDomain,
 * projectId) are public by design — they identify the project, they do not
 * grant access.
 */
class OTPress_Settings {

    private const OPTION = 'otpress_settings';

    private const DEFAULTS = [
        'firebase_api_key'     => '',
        'firebase_auth_domain' => '',
        'firebase_project_id'  => '',
        // Look up users by Digits usermeta and write Digits-compatible meta
        // for new users, so existing Digits installs migrate transparently.
        'digits_compat'        => '1',
        // Comma-separated usermeta keys checked (in order) when mapping a
        // verified phone number to an existing user.
        'phone_meta_keys'      => 'otpress_phone,digits_phone',
        'default_role'         => '',
        // Cloudflare Turnstile (optional). When the secret is set, the
        // email-OTP start and password endpoints require a valid token.
        'turnstile_site_key'   => '',
        'turnstile_secret_key' => '',
        // WhatsApp OTP via Meta Cloud API (optional). All three required to
        // enable the channel: phone number id, permanent token, approved
        // authentication template name.
        'whatsapp_phone_number_id' => '',
        'whatsapp_token'           => '',
        'whatsapp_template'        => '',
        'whatsapp_template_lang'   => 'es',
        // Meta's own authentication templates: one for a first-time number,
        // one for a returning sign-in. Both are localized by WhatsApp.
        'whatsapp_template_signup' => 'verify_account',
        'whatsapp_template_login'  => 'login_code',
        // Paid OTPs (SMS/WhatsApp) allowed per number per month; 0 disables.
        'otp_monthly_allowance'    => '8',
        'otp_daily_ip'             => '5',
        'otp_daily_subnet'         => '15',
        'otp_daily_global'         => '300',
        'otp_monthly_global'       => '5000',
        'otp_max_unverified'       => '3',
        // Delivery webhook (Meta app dashboard -> WhatsApp -> Configuration).
        'whatsapp_verify_token'    => '',
        'whatsapp_app_secret'      => '',
    ];

    public static function get(string $key): string {
        $constant = 'OTPRESS_' . strtoupper($key);
        if (defined($constant)) {
            return (string) constant($constant);
        }
        $opts = get_option(self::OPTION, []);
        $value = isset($opts[$key]) ? (string) $opts[$key] : '';
        if ('' === $value && isset(self::DEFAULTS[$key])) {
            $value = self::DEFAULTS[$key];
        }
        return $value;
    }

    public static function firebase_config(): array {
        return [
            'apiKey'     => self::get('firebase_api_key'),
            'authDomain' => self::get('firebase_auth_domain'),
            'projectId'  => self::get('firebase_project_id'),
        ];
    }

    public static function is_configured(): bool {
        $cfg = self::firebase_config();
        return '' !== $cfg['apiKey'] && '' !== $cfg['projectId'];
    }

    public static function phone_meta_keys(): array {
        $keys = array_filter(array_map('trim', explode(',', self::get('phone_meta_keys'))));
        /**
         * Filter the usermeta keys used to match a verified phone number to
         * an existing user, checked in order.
         *
         * @param string[] $keys
         */
        return apply_filters('otpress_phone_meta_keys', $keys);
    }

    public static function register_admin_page(): void {
        add_options_page(
            'OTPress',
            'OTPress',
            'manage_options',
            'otpress',
            [self::class, 'render_admin_page']
        );
    }

    public static function register_settings(): void {
        register_setting('otpress', self::OPTION, [
            'type'              => 'array',
            'sanitize_callback' => [self::class, 'sanitize'],
        ]);
    }

    public static function sanitize($input): array {
        $out = [];
        foreach (array_keys(self::DEFAULTS) as $key) {
            $out[$key] = isset($input[$key]) ? sanitize_text_field((string) $input[$key]) : '';
        }
        return $out;
    }

    public static function render_admin_page(): void {
        $fields = [
            'firebase_api_key'     => 'Firebase API key',
            'firebase_auth_domain' => 'Firebase auth domain',
            'firebase_project_id'  => 'Firebase project ID',
            'phone_meta_keys'      => 'Phone usermeta keys (comma-separated)',
            'default_role'         => 'Role for new users (blank = site default)',
            'turnstile_site_key'   => 'Cloudflare Turnstile site key (optional)',
            'turnstile_secret_key' => 'Cloudflare Turnstile secret key (optional)',
            'whatsapp_phone_number_id' => 'WhatsApp phone number ID (optional)',
            'whatsapp_token'           => 'WhatsApp permanent token (optional)',
            'whatsapp_template'        => 'WhatsApp auth template name (optional)',
            'whatsapp_template_lang'   => 'WhatsApp template language code',
            'whatsapp_template_signup' => 'WhatsApp template for first-time numbers',
            'whatsapp_template_login'  => 'WhatsApp template for returning sign-ins',
            'otp_monthly_allowance'    => 'Paid OTPs per number per month (0 = unlimited)',
            'otp_daily_ip'             => 'Paid OTPs per IP per day',
            'otp_daily_subnet'         => 'Paid OTPs per subnet per day',
            'otp_daily_global'         => 'Paid OTPs site-wide per day (hard ceiling)',
            'otp_monthly_global'       => 'Paid OTPs site-wide per month (hard ceiling)',
            'otp_max_unverified'       => 'Unused codes before a number is cut off',
            'whatsapp_verify_token'    => 'WhatsApp webhook verify token',
            'whatsapp_app_secret'      => 'WhatsApp app secret (webhook signature)',
        ];
        ?>
        <div class="wrap">
            <h1>OTPress</h1>
            <form method="post" action="options.php">
                <?php settings_fields('otpress'); ?>
                <table class="form-table" role="presentation">
                    <?php foreach ($fields as $key => $label) :
                        $constant = 'OTPRESS_' . strtoupper($key);
                        $locked   = defined($constant); ?>
                        <tr>
                            <th scope="row"><label for="otpress-<?php echo esc_attr($key); ?>"><?php echo esc_html($label); ?></label></th>
                            <td>
                                <input name="<?php echo esc_attr(self::OPTION . '[' . $key . ']'); ?>"
                                       id="otpress-<?php echo esc_attr($key); ?>"
                                       type="text" class="regular-text"
                                       value="<?php echo esc_attr(self::get($key)); ?>"
                                       <?php disabled($locked); ?>>
                                <?php if ($locked) : ?><p class="description">Defined by constant <code><?php echo esc_html($constant); ?></code>.</p><?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    <tr>
                        <th scope="row">Digits compatibility</th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr(self::OPTION . '[digits_compat]'); ?>" value="1" <?php checked(self::get('digits_compat'), '1'); ?>>
                                Match and write Digits plugin usermeta so existing Digits users keep working
                            </label>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}
