<?php

declare(strict_types=1);

namespace DracoInsomnis\Shield;

use DracoInsomnis\Input;
use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Core\NetList;
use DracoInsomnis\Plugin;

defined('ABSPATH') || exit;

/** The owner's screen: switch the shield on, see attempts, block and unblock, download evidence. */
final class Admin
{
    public const SLUG = 'draco-insomnis';
    private const ACTION = 'draco_admin';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu']);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
        add_action('admin_post_draco_export', [self::class, 'export']);
    }

    public static function menu(): void
    {
        $title = __('Anti-bot shield', 'draco-insomnis');
        add_submenu_page(Brand::PARENT, $title, $title, 'manage_options', self::SLUG, [self::class, 'render']);
    }

    public static function save(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'draco-insomnis'), 403);
        }
        check_admin_referer(self::ACTION);
        $do = sanitize_key((string) ($_POST['do'] ?? ''));
        $result = 'ok';
        if ($do === 'settings') {
            update_option(Plugin::OPTION_SHIELD, empty($_POST['shield']) ? 'no' : 'yes');
            $proxy = sanitize_key((string) ($_POST['proxy'] ?? ''));
            update_option(Guard::OPTION_PROXY, in_array($proxy, ['cf', 'xff'], true) ? $proxy : '');
            $nets = NetList::parse(sanitize_textarea_field(wp_unslash((string) ($_POST['nets'] ?? ''))));
            update_option(Guard::OPTION_NETS, implode("\n", $nets), false);
        } elseif ($do === 'block') {
            $done = false;
            $days = Input::postInt('days');
            $reason = sanitize_text_field(wp_unslash((string) ($_POST['reason'] ?? '')));
            foreach (['email', 'ip'] as $kind) {
                $value = sanitize_text_field(wp_unslash((string) ($_POST[$kind] ?? '')));
                if ($value !== '') {
                    $done = Store::block($kind, $value, $days, $reason) || $done;
                }
            }
            $result = $done ? 'ok' : 'refused';
        } elseif ($do === 'unblock') {
            Store::unblock(Input::postInt('id'));
        }
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=' . $result));
        exit;
    }

    private static function open(string $do): string
    {
        return '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">'
            . wp_nonce_field(self::ACTION, '_wpnonce', true, false)
            . '<input type="hidden" name="action" value="' . self::ACTION . '"><input type="hidden" name="do" value="' . esc_attr($do) . '">';
    }

    public static function render(): void
    {
        $on = get_option(Plugin::OPTION_SHIELD, 'no') === 'yes';
        $proxy = (string) get_option(Guard::OPTION_PROXY, '');
        $result = sanitize_key((string) ($_GET['result'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only

        echo '<div class="wrap">';
        Brand::header(__('Anti-bot shield', 'draco-insomnis'));
        if ($result === 'refused') {
            echo '<div class="notice notice-error"><p>' . esc_html__('Nothing was blocked: the value is not valid, belongs to an administrator, or is your own address.', 'draco-insomnis') . '</p></div>';
        } elseif ($result === 'ok') {
            echo '<div class="notice notice-success"><p>' . esc_html__('Changes saved.', 'draco-insomnis') . '</p></div>';
        }

        echo '<p>' . esc_html__('Stops programs that create fake accounts before the account exists. The bot is told "registration complete" after a short wait, and the attempt is kept as evidence. Nothing is sent back to the attacker.', 'draco-insomnis') . '</p>';
        echo self::open('settings'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo '<p><label><input type="checkbox" name="shield" value="1" ' . checked($on, true, false) . '> ' . esc_html__('Protect sign-ups (WordPress, WooCommerce and RealHomes)', 'draco-insomnis') . '</label></p>';
        echo '<p><label>' . esc_html__('Visitor address', 'draco-insomnis') . ' <select name="proxy">';
        foreach (['' => __('Connection address (safest; use this unless the site is behind a proxy)', 'draco-insomnis'), 'cf' => __('Cloudflare header (only if every visit goes through Cloudflare)', 'draco-insomnis'), 'xff' => __('X-Forwarded-For (only behind your own proxy or CDN)', 'draco-insomnis')] as $value => $label) {
            echo '<option value="' . esc_attr($value) . '"' . selected($proxy, $value, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select></label><br><small>' . esc_html__('Your address as the plugin sees it:', 'draco-insomnis') . ' <code>' . esc_html(Guard::clientIp()) . '</code></small></p>';
        echo '<p><label>' . esc_html__('Rented-server networks to watch, besides the ones already known (one per line, e.g. 198.51.100.0/24)', 'draco-insomnis') . '<br>';
        echo '<textarea name="nets" rows="3" class="large-text code">' . esc_textarea((string) get_option(Guard::OPTION_NETS, '')) . '</textarea></label></p>';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';

        echo '<h2>' . esc_html__('Block a sender', 'draco-insomnis') . '</h2>' . self::open('block'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo '<p><label>' . esc_html__('E-mail', 'draco-insomnis') . ' <input type="email" name="email" class="regular-text"></label> ';
        echo '<label>IP <input type="text" name="ip"></label> <label>' . esc_html__('For', 'draco-insomnis') . ' <select name="days">';
        foreach (Store::BLOCK_DAYS as $days) {
            /* translators: %d: number of days */
            echo '<option value="' . (int) $days . '"' . selected($days, 30, false) . '>' . esc_html(sprintf(__('%d days', 'draco-insomnis'), $days)) . '</option>';
        }
        echo '</select></label> <label>' . esc_html__('Reason', 'draco-insomnis') . ' <input type="text" name="reason"></label> ';
        submit_button(__('Block', 'draco-insomnis'), 'secondary', 'submit', false);
        echo '</p></form>';

        echo '<h2>' . esc_html__('Active blocks', 'draco-insomnis') . '</h2><table class="widefat striped"><thead><tr><th>' . esc_html__('Type', 'draco-insomnis') . '</th><th>' . esc_html__('Value', 'draco-insomnis') . '</th><th>' . esc_html__('Until (UTC)', 'draco-insomnis') . '</th><th>' . esc_html__('Reason', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        $blocks = Store::activeBlocks();
        foreach ($blocks as $b) {
            echo '<tr><td>' . esc_html((string) $b['kind']) . '</td><td>' . esc_html((string) $b['value']) . '</td><td>' . esc_html((string) $b['until_at']) . '</td><td>' . esc_html((string) $b['reason']) . '</td><td>'
                . self::open('unblock') . '<input type="hidden" name="id" value="' . (int) $b['id'] . '"><button class="button-link">' . esc_html__('Unblock', 'draco-insomnis') . '</button></form></td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        }
        if ($blocks === []) {
            echo '<tr><td colspan="5">' . esc_html__('None.', 'draco-insomnis') . '</td></tr>';
        }
        echo '</tbody></table>';

        $reasons = [
            'blocked' => __('already blocked', 'draco-insomnis'), 'privileged_role' => __('asked for an admin role', 'draco-insomnis'),
            'unknown_role' => __('role that does not exist', 'draco-insomnis'), 'honeypot' => __('filled the trap field', 'draco-insomnis'),
            'stamp_invalid' => __('forged page stamp', 'draco-insomnis'), 'stamp_missing' => __('never loaded the page', 'draco-insomnis'),
            'too_fast' => __('too fast', 'draco-insomnis'), 'random_username' => __('random username', 'draco-insomnis'),
            'hosting_network' => __('rented server', 'draco-insomnis'), 'repeat_offender' => __('repeat offender', 'draco-insomnis'),
            'script_client' => __('a script, not a browser', 'draco-insomnis'),
        ];
        echo '<h2>' . esc_html__('Recent suspicious attempts', 'draco-insomnis') . '</h2><p>' . esc_html__('Kept for 90 days. Three bot attempts in a day block the address for a week. "Evidence" downloads everything from that address as a CSV file to attach to an abuse report to the network provider.', 'draco-insomnis') . '</p>';
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('Where', 'draco-insomnis') . '</th><th>' . esc_html__('Points', 'draco-insomnis') . '</th><th>' . esc_html__('Verdict', 'draco-insomnis') . '</th><th>' . esc_html__('Why', 'draco-insomnis') . '</th><th>' . esc_html__('User / e-mail', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        $rows = Store::recent();
        foreach ($rows as $r) {
            $fields = json_decode((string) $r['fields'], true);
            $fields = is_array($fields) ? $fields : [];
            $why = array_map(static fn (string $k): string => $reasons[$k] ?? $k, array_filter(explode(',', (string) $r['reasons'])));
            $export = wp_nonce_url(admin_url('admin-post.php?action=draco_export&ip=' . rawurlencode((string) $r['ip'])), 'draco_export');
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td>' . esc_html((string) $r['ip']) . '</td><td>' . esc_html((string) $r['endpoint']) . '</td><td>' . (int) $r['score'] . '</td><td>'
                . esc_html($r['verdict'] === 'bot' ? __('Bot', 'draco-insomnis') : __('Doubtful', 'draco-insomnis')) . '</td><td>' . esc_html(implode(', ', $why)) . '</td><td>'
                . esc_html(trim((string) ($fields['username'] ?? '') . ' ' . (string) ($fields['email'] ?? ''))) . '</td><td><a href="' . esc_url($export) . '">' . esc_html__('Evidence', 'draco-insomnis') . '</a></td></tr>';
        }
        if ($rows === []) {
            echo '<tr><td colspan="8">' . esc_html($on ? __('No suspicious attempts yet.', 'draco-insomnis') : __('The shield is off.', 'draco-insomnis')) . '</td></tr>';
        }
        echo '</tbody></table></div>';
    }

    public static function export(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'draco-insomnis'), 403);
        }
        check_admin_referer('draco_export');
        $ip = (string) filter_var(wp_unslash((string) ($_GET['ip'] ?? '')), FILTER_VALIDATE_IP);
        if ($ip === '') {
            wp_die(esc_html__('Invalid address.', 'draco-insomnis'), 400);
        }
        nocache_headers();
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="evidence-' . str_replace(':', '-', $ip) . '-' . gmdate('Ymd') . '.csv"');
        $out = fopen('php://output', 'w');
        if ($out === false) {
            exit;
        }
        fputcsv($out, ['site', 'time_utc', 'client_ip', 'connection_ip', 'endpoint', 'score', 'verdict', 'reasons', 'user_agent', 'username', 'email', 'role', 'referer'], ',', '"', '');
        $site = home_url('/');
        foreach (Store::byIp($ip) as $r) {
            $f = json_decode((string) $r['fields'], true);
            $f = is_array($f) ? $f : [];
            fputcsv($out, [
                $site, $r['created_at'], $r['ip'], $r['remote_addr'], $r['endpoint'], $r['score'], $r['verdict'], $r['reasons'], self::cell((string) $r['user_agent']),
                self::cell((string) ($f['username'] ?? '')), self::cell((string) ($f['email'] ?? '')), self::cell((string) ($f['role'] ?? '')), self::cell((string) ($f['referer'] ?? '')),
            ], ',', '"', '');
        }
        fclose($out); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        exit;
    }

    /** What the bot typed must not run as a formula when the CSV is opened in a spreadsheet. */
    private static function cell(string $v): string
    {
        return $v !== '' && str_contains("=+-@\t\r", $v[0]) ? "'" . $v : $v;
    }
}
