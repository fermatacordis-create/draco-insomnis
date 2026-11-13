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
        add_action('admin_menu', [self::class, 'menu'], 13);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
    }

    public static function menu(): void
    {
        $title = __('Firewall', 'draco-insomnis');
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
        $do = Input::post('do');
        if ($do === 'test') {
            wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&test=' . rawurlencode(self::runTest())));
            exit;
        }
        if ($do === 'geo_update') {
            wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&geo=' . (GeoFilter::update() === '' ? 'ok' : 'fail') . '#draco-geo'));
            exit;
        }
        if ($do === 'geo') {
            $mode = Input::post('geo_mode');
            update_option(GeoFilter::OPTION_MODE, in_array($mode, ['block', 'allow'], true) ? $mode : 'off');
            update_option(GeoFilter::OPTION_SCOPE, Input::post('geo_scope') === 'site' ? 'site' : 'sensitive');
            update_option(GeoFilter::OPTION_ACTION, Input::post('geo_action') === 'block' ? 'block' : 'log');
            update_option(GeoFilter::OPTION_COUNTRIES, implode(', ', \DracoInsomnis\Core\Geo::parseList(Input::post('geo_countries'))), false);
            $fetched = '';
            if (GeoFilter::mode() !== 'off' && \DracoInsomnis\Core\Geo::built(GeoFilter::file()) === '') {
                $fetched = '&geo=' . (GeoFilter::update() === '' ? 'ok' : 'fail');
            }
            wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=ok' . $fetched . '#draco-geo'));
            exit;
        }
        if ($do === 'review') {
            $ok = Review::decide(Input::postInt('id'), Input::post('decision'), Input::postInt('days'));
            wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=' . ($ok ? 'ok' : 'refused') . '#draco-reviews'));
            exit;
        }
        update_option(Waf::OPTION_ENABLED, empty($_POST['enabled']) ? 'no' : 'yes');
        update_option(Waf::OPTION_MODE, Input::post('mode') === 'block' ? 'block' : 'log');
        foreach ([Waf::OPTION_HIDE_USERS => 'hide_users', Waf::OPTION_XMLRPC_OFF => 'xmlrpc_off', Waf::OPTION_LOGIN_LIMIT => 'login_limit', Headers::OPTION_SAFE => 'headers', Headers::OPTION_HSTS => 'hsts'] as $option => $field) {
            update_option($option, empty($_POST[$field]) ? 'no' : 'yes');
        }
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=ok'));
        exit;
    }

    /** Sends the signed attack-shaped request to the site itself. Returns rule|mode, or an error code. */
    private static function runTest(): string
    {
        if (!Waf::active()) {
            return 'off';
        }
        $url = add_query_arg(['draco_test' => Waf::TEST_ATTACK, 'cb' => wp_generate_password(8, false)], home_url('/'));
        $response = wp_remote_get($url, [
            'timeout' => 15,
            'redirection' => 0,
            'sslverify' => apply_filters('https_local_ssl_verify', false), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals -- WordPress core filter
            'headers' => ['X-Draco-Test' => Waf::testToken(time()), 'Cache-Control' => 'no-cache'],
        ]);
        if (is_wp_error($response)) {
            return 'error';
        }
        $result = (string) wp_remote_retrieve_header($response, 'x-draco-test-result');
        if ($result === '') {
            // Something in front of WordPress (the hosting's firewall or CDN) answered first.
            return (int) wp_remote_retrieve_response_code($response) === 403 ? 'upstream' : 'unseen';
        }

        return $result;
    }

    private static function testNotice(string $test): void
    {
        [$rule, $mode] = array_pad(explode('|', $test, 2), 2, '');
        if ($rule === 'off') {
            Brand::notice('warning', __('The firewall is off: switch it on and save, then test again.', 'draco-insomnis'));
        } elseif ($rule === 'error' || $rule === 'unseen') {
            Brand::notice('warning', __('The test could not reach the site from the server itself (some hostings do not allow it). The firewall may still work: look at "Recent attacks".', 'draco-insomnis'));
        } elseif ($rule === 'upstream') {
            Brand::notice('success', __('The test was stopped before it reached WordPress, by the hosting\'s own firewall. Good: two layers.', 'draco-insomnis'));
        } elseif ($rule === 'none') {
            Brand::notice('error', __('The test attack was not recognised. Please report it to Draco Insomnis.', 'draco-insomnis'));
        } elseif ($mode === 'block') {
            Brand::notice('success', __('Works: a database injection was recognised and blocked (403).', 'draco-insomnis'));
        } else {
            Brand::notice('success', __('Works: a database injection was recognised. In "Log only" it is written down but not stopped; switch to "Block" when you are ready.', 'draco-insomnis'));
        }
    }

    public static function render(): void
    {
        $on = get_option(Waf::OPTION_ENABLED, 'no') === 'yes';
        $mode = (string) get_option(Waf::OPTION_MODE, 'log');
        Brand::open(__('Firewall', 'draco-insomnis'), __('Stops requests with the shape of an attack (database injection, reading server files, running code, scripts in links) and the scanners that look for weak spots. People who can edit the site are never inspected.', 'draco-insomnis'));
        if (Input::get('result') === 'ok') {
            Brand::notice('success', __('Changes saved.', 'draco-insomnis'));
        }
        $test = Input::get('test');
        if ($test !== '') {
            self::testNotice($test);
        }
        if (defined('DRACO_WAF_OFF') && DRACO_WAF_OFF) {
            Brand::notice('warning', __('DRACO_WAF_OFF is set in wp-config.php: the firewall is off. Remove that line once the problem is fixed.', 'draco-insomnis'));
        }
        $state = $on ? ($mode === 'block' ? 'on' : 'log') : 'off';
        Brand::card('privacy', __('Settings', 'draco-insomnis'), '', Brand::pill(Brand::stateLabel($state), $state));
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '">';
        Brand::toggle('enabled', $on, __('Switch on the firewall', 'draco-insomnis'));
        Brand::modes('mode', $mode, [
            'log' => [__('Log only', 'draco-insomnis'), __('Writes down what it would stop, without stopping it. Start here for a few days.', 'draco-insomnis'), 'visibility'],
            'block' => [__('Block', 'draco-insomnis'), __('Stops those requests. Five in 10 minutes put the address on the block list for 7 days.', 'draco-insomnis'), 'dismiss'],
        ]);
        Brand::toggle('hide_users', get_option(Waf::OPTION_HIDE_USERS, 'yes') === 'yes', __('Hide the list of user names from anonymous visitors (?author=1 and /wp-json/wp/v2/users), the first step of password attacks', 'draco-insomnis'));
        Brand::toggle('login_limit', get_option(Waf::OPTION_LOGIN_LIMIT, 'yes') === 'yes', __('Limit failed logins: 10 in 10 minutes lock that address out of the login for 30 minutes', 'draco-insomnis'));
        Brand::toggle('headers', get_option(Headers::OPTION_SAFE, 'no') === 'yes', __('Send security headers on public pages (no sniffing of file types, no framing by other sites, less referrer data, no camera, microphone or location for embedded content)', 'draco-insomnis'), __('Safe for almost every site. If another plugin or the server already sends one of them, Draco leaves it alone.', 'draco-insomnis'));
        Brand::toggle('hsts', get_option(Headers::OPTION_HSTS, 'no') === 'yes', __('Force HTTPS in browsers for 6 months (HSTS)', 'draco-insomnis'), __('Only when the whole site works on HTTPS and will keep working: browsers remember it and refuse plain HTTP until it expires.', 'draco-insomnis'));
        Brand::toggle('xmlrpc_off', get_option(Waf::OPTION_XMLRPC_OFF, 'no') === 'yes', __('Turn off XML-RPC completely (leave it on if you use Jetpack or the WordPress mobile app; its riskiest parts are always off)', 'draco-insomnis'));
        echo '<p style="margin-top:12px">';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</p></form>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:8px">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="test">';
        submit_button(__('Test the firewall', 'draco-insomnis'), 'secondary', 'submit', false);
        echo ' <span class="description">' . esc_html__('Sends a harmless attack-shaped request to the site and tells you what happened. It is not logged.', 'draco-insomnis') . '</span></form>';
        Brand::cardEnd();

        $rules = [
            'waf_scanner' => __('scanner tool', 'draco-insomnis'), 'waf_probe' => __('looking for sensitive files', 'draco-insomnis'),
            'waf_sqli' => __('database injection', 'draco-insomnis'), 'waf_traversal' => __('reading server files', 'draco-insomnis'),
            'waf_code' => __('running code', 'draco-insomnis'), 'waf_xss' => __('script in the link', 'draco-insomnis'),
            'waf_multicall' => __('many passwords in one XML-RPC call', 'draco-insomnis'),
            'waf_geo' => __('country not allowed', 'draco-insomnis'),
        ];
        self::summary($rules);
        self::reviews();
        self::geo();

        Brand::card('warning', __('Recent attacks', 'draco-insomnis'), __('Kept for 90 days. "Evidence" downloads everything from that address for an abuse report. In log-only mode they appear as "Would block".', 'draco-insomnis'), '', 'warn', 'draco-card--flush');
        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('What', 'draco-insomnis') . '</th><th>' . esc_html__('Address requested', 'draco-insomnis') . '</th><th>' . esc_html__('Result', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        $rows = Store::recentWhere('waf:');
        foreach ($rows as $r) {
            $fields = json_decode((string) $r['fields'], true);
            $export = wp_nonce_url(admin_url('admin-post.php?action=draco_export&ip=' . rawurlencode((string) $r['ip'])), 'draco_export');
            $result = $r['verdict'] === 'bot' ? Brand::pill(__('Blocked', 'draco-insomnis'), 'bad') : Brand::pill(__('Would block', 'draco-insomnis'), 'log');
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td><span class="draco-code">' . esc_html((string) $r['ip']) . '</span></td><td>' . esc_html($rules[(string) $r['reasons']] ?? (string) $r['reasons']) . '</td><td><code>'
                . esc_html((string) (is_array($fields) ? ($fields['referer'] ?? '') : '')) . '</code></td><td>' . wp_kses_post($result) . '</td><td><a href="' . esc_url($export) . '">' . esc_html__('Evidence', 'draco-insomnis') . '</a></td></tr>';
        }
        if ($rows === []) {
            Brand::emptyRow(6, $on ? __('No attacks seen yet.', 'draco-insomnis') : __('The firewall is off.', 'draco-insomnis'), $on ? 'yes-alt' : 'marker');
        }
        echo '</tbody></table></div>';
        Brand::cardEnd();
        echo '<div class="draco-callout"><span class="dashicons dashicons-sos" aria-hidden="true"></span><span>' . esc_html__('If the firewall ever blocks you, add define(\'DRACO_WAF_OFF\', true); to wp-config.php, log in, look at this list and remove the line.', 'draco-insomnis') . '</span></div>';
        Brand::close();
    }

    /** @param array<string, string> $rules */
    private static function summary(array $rules): void
    {
        $sum = Store::wafSummary(7);
        /* translators: 1: attacks seen, 2: of them blocked */
        $line = sprintf(__('%1$d attacks seen, %2$d blocked.', 'draco-insomnis'), $sum['total'], $sum['blocked']);
        Brand::card('chart-bar', __('Last 7 days', 'draco-insomnis'), $line, '', 'info');
        if ($sum['total'] > 0) {
            echo '<div class="draco-inline" style="align-items:flex-start;gap:32px"><div><strong>' . esc_html__('What', 'draco-insomnis') . '</strong><ul>';
            foreach ($sum['rules'] as $rule => $n) {
                echo '<li>' . esc_html($rules[$rule] ?? $rule) . ': ' . (int) $n . '</li>';
            }
            echo '</ul></div><div><strong>' . esc_html__('Busiest addresses', 'draco-insomnis') . '</strong><ul>';
            foreach ($sum['ips'] as $ip => $n) {
                echo '<li><span class="draco-code">' . esc_html($ip) . '</span>: ' . (int) $n . '</li>';
            }
            echo '</ul></div></div>';
        }
        Brand::cardEnd();
    }

    private static function geo(): void
    {
        $mode = GeoFilter::mode();
        $built = \DracoInsomnis\Core\Geo::built(GeoFilter::file());
        $fetch = Input::get('geo');
        echo '<div id="draco-geo"></div>';
        if ($fetch === 'fail') {
            Brand::notice('error', __('The country list could not be downloaded. The filter does nothing until it is there; try "Update the country list" later.', 'draco-insomnis'));
        } elseif ($fetch === 'ok') {
            Brand::notice('success', __('Country list downloaded.', 'draco-insomnis'));
        }
        $state = $mode === 'off' ? 'off' : (get_option(GeoFilter::OPTION_ACTION, 'log') === 'block' ? 'on' : 'log');
        Brand::card('admin-site-alt3', __('Countries', 'draco-insomnis'), __('Most of your visitors may come from many countries, and an attacker changes country with a VPN. Filter only logging in, signing up and forms, and start with "Log only". Administrators, people you let through and search engines are never filtered.', 'draco-insomnis'), Brand::pill(Brand::stateLabel($state), $state));
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="geo">';
        $select = static function (string $name, string $label, string $value, array $options): void {
            echo '<div class="draco-field"><label for="draco-' . esc_attr($name) . '">' . esc_html($label) . '</label><select id="draco-' . esc_attr($name) . '" name="' . esc_attr($name) . '">';
            foreach ($options as $key => $text) {
                echo '<option value="' . esc_attr((string) $key) . '"' . selected($value, (string) $key, false) . '>' . esc_html($text) . '</option>';
            }
            echo '</select></div>';
        };
        echo '<div class="draco-inline">';
        $select('geo_mode', __('Filter', 'draco-insomnis'), $mode, ['off' => __('Off', 'draco-insomnis'), 'block' => __('Refuse the countries listed', 'draco-insomnis'), 'allow' => __('Only the countries listed', 'draco-insomnis')]);
        $select('geo_scope', __('Where', 'draco-insomnis'), (string) get_option(GeoFilter::OPTION_SCOPE, 'sensitive'), ['sensitive' => __('Logging in, signing up and forms (recommended)', 'draco-insomnis'), 'site' => __('The whole site', 'draco-insomnis')]);
        $select('geo_action', __('What to do', 'draco-insomnis'), (string) get_option(GeoFilter::OPTION_ACTION, 'log'), ['log' => __('Log only', 'draco-insomnis'), 'block' => __('Block', 'draco-insomnis')]);
        echo '</div><div class="draco-field"><label for="draco-geo_countries">' . esc_html__('Countries (two-letter codes, e.g. ES, FR, DE)', 'draco-insomnis') . '</label>';
        echo '<input id="draco-geo_countries" type="text" name="geo_countries" class="large-text code" value="' . esc_attr((string) get_option(GeoFilter::OPTION_COUNTRIES, '')) . '"></div>';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';
        /* translators: %s: date of the country list, e.g. 2026-11-13 */
        $status = $built === '' ? __('Country list: not downloaded yet (it is downloaded when you switch the filter on).', 'draco-insomnis') : sprintf(__('Country list of %s.', 'draco-insomnis'), substr($built, 0, 4) . '-' . substr($built, 4, 2) . '-' . substr($built, 6, 2));
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:8px">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="geo_update">';
        echo '<span class="description">' . esc_html($status) . ' </span>';
        submit_button(__('Update the country list', 'draco-insomnis'), 'secondary small', 'submit', false);
        echo '</form><p class="description">' . wp_kses_post(sprintf(
            /* translators: %s: link to DB-IP */
            __('IP geolocation by %s (CC BY 4.0). Looked up on your own server: no address is sent anywhere.', 'draco-insomnis'),
            '<a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a>'
        )) . '</p>';
        Brand::cardEnd();
    }

    private static function reviews(): void
    {
        $rows = Review::recent();
        $pending = Review::pendingCount();
        /* translators: %d: number of review requests waiting */
        $pill = Brand::pill(sprintf(__('Waiting: %d', 'draco-insomnis'), $pending), $pending > 0 ? 'log' : 'off');
        echo '<div id="draco-reviews"></div>';
        Brand::card('format-chat', __('Review requests', 'draco-insomnis'), __('People the firewall stopped can ask from the block page. Let them through for a while if it was a mistake. Draco never writes to them: answer from your own mail if you want.', 'draco-insomnis'), $pill, '', 'draco-card--flush');
        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('E-mail', 'draco-insomnis') . '</th><th>' . esc_html__('Message', 'draco-insomnis') . '</th><th>' . esc_html__('Result', 'draco-insomnis') . '</th></tr></thead><tbody>';
        $states = ['approved' => [__('Let through', 'draco-insomnis'), 'on'], 'denied' => [__('Denied', 'draco-insomnis'), 'off'], 'attacker' => [__('Attacker: blocked', 'draco-insomnis'), 'bad']];
        foreach ($rows as $r) {
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td><span class="draco-code">' . esc_html((string) $r['ip']) . '</span></td><td>' . esc_html((string) $r['email']) . '</td><td>' . esc_html((string) $r['message']) . '</td><td>';
            if ($r['status'] === 'pending') {
                echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" class="draco-inline">';
                wp_nonce_field(self::ACTION);
                echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="review"><input type="hidden" name="id" value="' . (int) $r['id'] . '">';
                echo '<select name="days" aria-label="' . esc_attr__('For', 'draco-insomnis') . '"><option value="1">' . esc_html__('24 hours', 'draco-insomnis') . '</option>';
                foreach ([7, 30, 0] as $days) {
                    echo '<option value="' . (int) $days . '">' . esc_html(Store::daysLabel($days)) . '</option>';
                }
                echo '</select> <button class="button button-primary" name="decision" value="approve">' . esc_html__('Let through', 'draco-insomnis') . '</button> ';
                echo '<button class="button" name="decision" value="deny">' . esc_html__('Deny', 'draco-insomnis') . '</button> ';
                echo '<button class="button-link" name="decision" value="attacker">' . esc_html__('Attacker', 'draco-insomnis') . '</button></form>';
            } else {
                $st = $states[(string) $r['status']] ?? [(string) $r['status'], 'off'];
                echo wp_kses_post(Brand::pill($st[0], $st[1]));
            }
            echo '</td></tr>';
        }
        if ($rows === []) {
            Brand::emptyRow(5, __('No requests.', 'draco-insomnis'), 'yes-alt');
        }
        echo '</tbody></table></div>';
        Brand::cardEnd();
    }
}
