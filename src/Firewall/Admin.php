<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

use DracoInsomnis\Input;
use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/** The owner's screen for the firewall. */
final class Admin
{
    public const SLUG = 'draco-insomnis-firewall';
    private const ACTION = 'draco_waf_admin';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu'], 12);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
    }

    public static function menu(): void
    {
        $title = __('Firewall', 'draco-insomnis');
        add_submenu_page(Brand::PARENT, $title, $title, 'manage_options', self::SLUG, [self::class, 'render']);
    }

    public static function save(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'draco-insomnis'), 403);
        }
        check_admin_referer(self::ACTION);
        update_option(Waf::OPTION_ENABLED, empty($_POST['enabled']) ? 'no' : 'yes');
        update_option(Waf::OPTION_MODE, Input::post('mode') === 'block' ? 'block' : 'log');
        foreach ([Waf::OPTION_HIDE_USERS => 'hide_users', Waf::OPTION_XMLRPC_OFF => 'xmlrpc_off', Waf::OPTION_LOGIN_LIMIT => 'login_limit'] as $option => $field) {
            update_option($option, empty($_POST[$field]) ? 'no' : 'yes');
        }
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=ok'));
        exit;
    }

    public static function render(): void
    {
        $on = get_option(Waf::OPTION_ENABLED, 'no') === 'yes';
        $mode = (string) get_option(Waf::OPTION_MODE, 'log');
        echo '<div class="wrap">';
        Brand::header(__('Firewall', 'draco-insomnis'));
        echo '<p>' . esc_html__('Stops requests with the shape of an attack (database injection, reading server files, running code, scripts in links) and the scanners that look for weak spots. People who can edit the site are never inspected.', 'draco-insomnis') . '</p>';
        if (Input::get('result') === 'ok') {
            echo '<div class="notice notice-success"><p>' . esc_html__('Changes saved.', 'draco-insomnis') . '</p></div>';
        }
        if (defined('DRACO_WAF_OFF') && DRACO_WAF_OFF) {
            echo '<div class="notice notice-warning"><p>' . esc_html__('DRACO_WAF_OFF is set in wp-config.php: the firewall is off. Remove that line once the problem is fixed.', 'draco-insomnis') . '</p></div>';
        }
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '">';
        $box = static function (string $name, bool $checked, string $label): void {
            echo '<p><label><input type="checkbox" name="' . esc_attr($name) . '" value="1" ' . checked($checked, true, false) . '> ' . esc_html($label) . '</label></p>';
        };
        $box('enabled', $on, __('Switch on the firewall', 'draco-insomnis'));
        echo '<p style="margin-left:24px">';
        echo '<label style="display:block;margin:4px 0"><input type="radio" name="mode" value="log" ' . checked($mode, 'log', false) . '> ' . esc_html__('Log only: write down what it would stop, without stopping anything (start here for a few days)', 'draco-insomnis') . '</label>';
        echo '<label style="display:block;margin:4px 0"><input type="radio" name="mode" value="block" ' . checked($mode, 'block', false) . '> ' . esc_html__('Block: stop those requests; five in 10 minutes put the address on the block list for 7 days', 'draco-insomnis') . '</label></p>';
        $box('hide_users', get_option(Waf::OPTION_HIDE_USERS, 'yes') === 'yes', __('Hide the list of user names from anonymous visitors (?author=1 and /wp-json/wp/v2/users), the first step of password attacks', 'draco-insomnis'));
        $box('login_limit', get_option(Waf::OPTION_LOGIN_LIMIT, 'yes') === 'yes', __('Limit failed logins: 10 in 10 minutes lock that address out of the login for 30 minutes', 'draco-insomnis'));
        $box('xmlrpc_off', get_option(Waf::OPTION_XMLRPC_OFF, 'no') === 'yes', __('Turn off XML-RPC completely (leave it on if you use Jetpack or the WordPress mobile app; its riskiest parts are always off)', 'draco-insomnis'));
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';

        $rules = [
            'waf_scanner' => __('scanner tool', 'draco-insomnis'), 'waf_probe' => __('looking for sensitive files', 'draco-insomnis'),
            'waf_sqli' => __('database injection', 'draco-insomnis'), 'waf_traversal' => __('reading server files', 'draco-insomnis'),
            'waf_code' => __('running code', 'draco-insomnis'), 'waf_xss' => __('script in the link', 'draco-insomnis'),
            'waf_multicall' => __('many passwords in one XML-RPC call', 'draco-insomnis'),
        ];
        echo '<h2>' . esc_html__('Recent attacks', 'draco-insomnis') . '</h2><p>' . esc_html__('Kept for 90 days. "Evidence" downloads everything from that address for an abuse report. In log-only mode they appear as "Would block".', 'draco-insomnis') . '</p>';
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('What', 'draco-insomnis') . '</th><th>' . esc_html__('Address requested', 'draco-insomnis') . '</th><th>' . esc_html__('Result', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        $rows = Store::recentWhere('waf:');
        foreach ($rows as $r) {
            $fields = json_decode((string) $r['fields'], true);
            $export = wp_nonce_url(admin_url('admin-post.php?action=draco_export&ip=' . rawurlencode((string) $r['ip'])), 'draco_export');
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td>' . esc_html((string) $r['ip']) . '</td><td>' . esc_html($rules[(string) $r['reasons']] ?? (string) $r['reasons']) . '</td><td><code>'
                . esc_html((string) (is_array($fields) ? ($fields['referer'] ?? '') : '')) . '</code></td><td>' . esc_html($r['verdict'] === 'bot' ? __('Blocked', 'draco-insomnis') : __('Would block', 'draco-insomnis')) . '</td><td><a href="' . esc_url($export) . '">' . esc_html__('Evidence', 'draco-insomnis') . '</a></td></tr>';
        }
        if ($rows === []) {
            echo '<tr><td colspan="6">' . esc_html($on ? __('No attacks seen yet.', 'draco-insomnis') : __('The firewall is off.', 'draco-insomnis')) . '</td></tr>';
        }
        echo '</tbody></table>';
        echo '<p>' . esc_html__('If the firewall ever blocks you, add define(\'DRACO_WAF_OFF\', true); to wp-config.php, log in, look at this list and remove the line.', 'draco-insomnis') . '</p></div>';
    }
}
