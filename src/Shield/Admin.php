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
    public const SLUG = 'draco-insomnis-shield';
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
        if (Brand::nestedParent() !== '') {
            return; // Brand::menuNested() registers it inside the host plugin's menu.
        }
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

        Brand::open(__('Anti-bot shield', 'draco-insomnis'), __('Stops programs that create fake accounts before the account exists. The bot is told "registration complete" after a short wait, and the attempt is kept as evidence. Nothing is sent back to the attacker.', 'draco-insomnis'));
        if ($result === 'refused') {
            Brand::notice('error', __('Nothing was blocked: the value is not valid, belongs to an administrator, or is your own address.', 'draco-insomnis'));
        } elseif ($result === 'ok') {
            Brand::notice('success', __('Changes saved.', 'draco-insomnis'));
        }

        echo '<div class="draco-grid">';
        Brand::card('shield-alt', __('Settings', 'draco-insomnis'), __('WordPress, WooCommerce and RealHomes sign-up forms.', 'draco-insomnis'), Brand::pill(Brand::stateLabel($on ? 'on' : 'off'), $on ? 'on' : 'off'));
        echo self::open('settings'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        Brand::toggle('shield', $on, __('Protect sign-ups (WordPress, WooCommerce and RealHomes)', 'draco-insomnis'), __('A hidden trap field and a signed page stamp: people never solve puzzles.', 'draco-insomnis'));
        echo '<div class="draco-field"><label for="draco-proxy">' . esc_html__('Visitor address', 'draco-insomnis') . '</label><select id="draco-proxy" name="proxy" style="max-width:100%">';
        foreach (['' => __('Connection address (safest; use this unless the site is behind a proxy)', 'draco-insomnis'), 'cf' => __('Cloudflare header (only if every visit goes through Cloudflare)', 'draco-insomnis'), 'xff' => __('X-Forwarded-For (only behind your own proxy or CDN)', 'draco-insomnis')] as $value => $label) {
            echo '<option value="' . esc_attr($value) . '"' . selected($proxy, $value, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select><p class="description">' . esc_html__('Your address as the plugin sees it:', 'draco-insomnis') . ' <span class="draco-code">' . esc_html(Guard::clientIp()) . '</span></p></div>';
        echo '<div class="draco-field"><label for="draco-nets">' . esc_html__('Rented-server networks to watch, besides the ones already known (one per line, e.g. 198.51.100.0/24)', 'draco-insomnis') . '</label>';
        echo '<textarea id="draco-nets" name="nets" rows="3" class="large-text code">' . esc_textarea((string) get_option(Guard::OPTION_NETS, '')) . '</textarea></div>';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';
        Brand::cardEnd();

        Brand::card('dismiss', __('Block a sender', 'draco-insomnis'), __('Never an administrator, nor your own address.', 'draco-insomnis'), '', 'bad');
        echo self::open('block'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo '<div class="draco-field"><label for="draco-b-email">' . esc_html__('E-mail', 'draco-insomnis') . '</label><input id="draco-b-email" type="email" name="email" class="large-text"></div>';
        echo '<div class="draco-inline"><div class="draco-field"><label for="draco-b-ip">IP</label><input id="draco-b-ip" type="text" name="ip"></div>';
        echo '<div class="draco-field"><label for="draco-b-days">' . esc_html__('For', 'draco-insomnis') . '</label><select id="draco-b-days" name="days">';
        foreach (Store::BLOCK_DAYS as $days) {
            /* translators: %d: number of days */
            echo '<option value="' . (int) $days . '"' . selected($days, 30, false) . '>' . esc_html(sprintf(__('%d days', 'draco-insomnis'), $days)) . '</option>';
        }
        echo '</select></div></div>';
        echo '<div class="draco-field" style="margin-top:12px"><label for="draco-b-reason">' . esc_html__('Reason', 'draco-insomnis') . '</label><input id="draco-b-reason" type="text" name="reason" class="large-text"></div>';
        submit_button(__('Block', 'draco-insomnis'), 'secondary', 'submit', false);
        echo '</form>';
        Brand::cardEnd();
        echo '</div>';

        $blocks = Store::activeBlocks();
        /* translators: %d: number of active blocks */
        $count = sprintf(__('Active: %d', 'draco-insomnis'), count($blocks));
        Brand::card('lock', __('Active blocks', 'draco-insomnis'), '', Brand::pill($count, $blocks === [] ? 'off' : 'bad'), '', 'draco-card--flush');
        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Type', 'draco-insomnis') . '</th><th>' . esc_html__('Value', 'draco-insomnis') . '</th><th>' . esc_html__('Until (UTC)', 'draco-insomnis') . '</th><th>' . esc_html__('Reason', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        foreach ($blocks as $b) {
            echo '<tr><td>' . wp_kses_post(Brand::pill((string) $b['kind'], 'bad')) . '</td><td><span class="draco-code">' . esc_html((string) $b['value']) . '</span></td><td>' . esc_html((string) $b['until_at']) . '</td><td>' . esc_html((string) $b['reason']) . '</td><td>'
                . self::open('unblock') . '<input type="hidden" name="id" value="' . (int) $b['id'] . '"><button class="button-link">' . esc_html__('Unblock', 'draco-insomnis') . '</button></form></td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        }
        if ($blocks === []) {
            Brand::emptyRow(5, __('None.', 'draco-insomnis'));
        }
        echo '</tbody></table></div>';
        Brand::cardEnd();

        $reasons = [
            'blocked' => __('already blocked', 'draco-insomnis'), 'privileged_role' => __('asked for an admin role', 'draco-insomnis'),
            'unknown_role' => __('role that does not exist', 'draco-insomnis'), 'honeypot' => __('filled the trap field', 'draco-insomnis'),
            'stamp_invalid' => __('forged page stamp', 'draco-insomnis'), 'stamp_missing' => __('never loaded the page', 'draco-insomnis'),
            'too_fast' => __('too fast', 'draco-insomnis'), 'random_username' => __('random username', 'draco-insomnis'),
            'hosting_network' => __('rented server', 'draco-insomnis'), 'repeat_offender' => __('repeat offender', 'draco-insomnis'),
            'script_client' => __('a script, not a browser', 'draco-insomnis'),
        ];
        Brand::card('list-view', __('Recent suspicious attempts', 'draco-insomnis'), __('Kept for 90 days. Three bot attempts in a day block the address for a week. "Evidence" downloads everything from that address as a CSV file to attach to an abuse report to the network provider.', 'draco-insomnis'), '', 'info', 'draco-card--flush');
        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('Where', 'draco-insomnis') . '</th><th>' . esc_html__('Points', 'draco-insomnis') . '</th><th>' . esc_html__('Verdict', 'draco-insomnis') . '</th><th>' . esc_html__('Why', 'draco-insomnis') . '</th><th>' . esc_html__('User / e-mail', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        // The firewall and anti-copy have their own lists.
        $rows = array_values(array_filter(Store::recent(100), static fn (array $r): bool => !str_starts_with((string) $r['endpoint'], 'waf:') && !str_starts_with((string) $r['endpoint'], 'anticopy:')));
        foreach (array_slice($rows, 0, 50) as $r) {
            $fields = json_decode((string) $r['fields'], true);
            $fields = is_array($fields) ? $fields : [];
            $why = array_map(static fn (string $k): string => $reasons[$k] ?? $k, array_filter(explode(',', (string) $r['reasons'])));
            $export = wp_nonce_url(admin_url('admin-post.php?action=draco_export&ip=' . rawurlencode((string) $r['ip'])), 'draco_export');
            $verdict = $r['verdict'] === 'bot' ? Brand::pill(__('Bot', 'draco-insomnis'), 'bad') : Brand::pill(__('Doubtful', 'draco-insomnis'), 'warn');
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td><span class="draco-code">' . esc_html((string) $r['ip']) . '</span></td><td>' . esc_html((string) $r['endpoint']) . '</td><td>' . (int) $r['score'] . '</td><td>'
                . wp_kses_post($verdict) . '</td><td>' . esc_html(implode(', ', $why)) . '</td><td>'
                . esc_html(trim((string) ($fields['username'] ?? '') . ' ' . (string) ($fields['email'] ?? ''))) . '</td><td><a href="' . esc_url($export) . '">' . esc_html__('Evidence', 'draco-insomnis') . '</a></td></tr>';
        }
        if ($rows === []) {
            Brand::emptyRow(8, $on ? __('No suspicious attempts yet.', 'draco-insomnis') : __('The shield is off.', 'draco-insomnis'), $on ? 'yes-alt' : 'marker');
        }
        echo '</tbody></table></div>';
        Brand::cardEnd();
        Brand::close();
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
