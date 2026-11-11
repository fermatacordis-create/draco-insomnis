<?php

declare(strict_types=1);

namespace DracoInsomnis\Shield;

use DracoInsomnis\Input;
use DracoInsomnis\Core\BotScore;
use DracoInsomnis\Core\FormStamp;
use DracoInsomnis\Core\NetList;
use DracoInsomnis\Plugin;

defined('ABSPATH') || exit;

/**
 * Stands in front of the public sign-up forms and turns bots away before an account exists.
 *
 * Only defends this site: a bot gets a fake "done" after a short, capped wait, and its attempt is kept
 * as evidence. Nothing is ever sent back to the attacker's machine.
 */
final class Guard
{
    public const OPTION_NETS = 'draco_hosting_nets';
    /** '' = trust only the connection address; 'cf' = Cloudflare header; 'xff' = first X-Forwarded-For entry. */
    public const OPTION_PROXY = 'draco_proxy_header';
    private const AUTO_BLOCK_AFTER = 3;
    private const AUTO_BLOCK_DAYS = 7;
    /** Slow answers allowed per minute across the whole site, so a flood cannot use up PHP workers. */
    private const SLOW_PER_MINUTE = 10;
    private const SLOW_MAX_MS = 3000;
    private const TRAP_WORDS = ['website', 'homepage', 'company_site', 'web_address', 'url_home'];

    public static function register(): void
    {
        // RealHomes posts its sign-up modal here; the theme's own handler runs at 10.
        add_action('wp_ajax_nopriv_inspiry_ajax_register', [self::class, 'realHomes'], 1);
        add_filter('registration_errors', [self::class, 'wpRegistration'], 5, 3);
        add_filter('woocommerce_registration_errors', [self::class, 'wooRegistration'], 5, 3);
        add_action('register_form', [self::class, 'fields']);
        add_action('woocommerce_register_form', [self::class, 'fields']);
        add_action('wp_footer', [self::class, 'footerScript'], 99);
    }

    public static function stampField(): string
    {
        return 'dr_' . substr(hash('sha256', 'stamp|' . Plugin::secret()), 0, 8);
    }

    public static function trapField(): string
    {
        $h = hash('sha256', 'trap|' . Plugin::secret());

        return self::TRAP_WORDS[hexdec($h[0]) % count(self::TRAP_WORDS)] . '_' . substr($h, 1, 4);
    }

    /** Hidden inputs for forms rendered by WordPress itself. */
    public static function fields(): void
    {
        echo '<input type="hidden" name="' . esc_attr(self::stampField()) . '" value="' . esc_attr(self::stamp()) . '">';
        echo self::trapHtml(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from constants and esc_attr()
    }

    /** RealHomes builds its modal outside WordPress hooks, so the same inputs are added from the page. */
    public static function footerScript(): void
    {
        if (is_user_logged_in()) {
            return;
        }
        $stamp = wp_json_encode(self::stamp());
        $trap = wp_json_encode(self::trapHtml());
        $f = wp_json_encode(self::stampField());
        $js = "<script>(function(){var s={$stamp},t={$trap},f={$f};"
            . "function arm(){document.querySelectorAll('input[name=\"register_username\"]').forEach(function(u){var form=u.form;"
            . "if(!form||form.querySelector('input[name=\"'+f+'\"]'))return;"
            . "var h=document.createElement('input');h.type='hidden';h.name=f;h.value=s;form.appendChild(h);"
            . "form.insertAdjacentHTML('beforeend',t);});}"
            . "arm();document.addEventListener('DOMContentLoaded',arm);document.addEventListener('focusin',arm,true);})();</script>";
        echo $js; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every value inside is wp_json_encode()d.
    }

    public static function realHomes(): void
    {
        $roles = function_exists('inspiry_user_sync_roles') ? array_keys((array) inspiry_user_sync_roles()) : null;
        $result = self::judge('realhomes_ajax', [
            'username' => self::post('register_username'),
            'email' => self::post('register_email'),
            'role' => self::post('user_role'),
        ], $roles);
        if ($result['verdict'] !== 'bot') {
            return;
        }
        self::slowDown();
        // The theme's own success text, so the script believes it worked and moves on.
        $domain = defined('RH_TEXT_DOMAIN') ? (string) constant('RH_TEXT_DOMAIN') : 'framework';
        wp_send_json(['success' => true, 'message' => esc_html__('Registration is complete. Check your email for details!', $domain)]); // phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralDomain,WordPress.WP.I18n.TextDomainMismatch
    }

    /** @param \WP_Error $errors */
    public static function wpRegistration($errors, $login = '', $email = '')
    {
        return self::rejectIfBot($errors, 'wp_register', (string) $login, (string) $email);
    }

    /** @param \WP_Error $errors */
    public static function wooRegistration($errors, $login = '', $email = '')
    {
        return self::rejectIfBot($errors, 'woo_register', (string) $login, (string) $email);
    }

    /** @param \WP_Error $errors */
    private static function rejectIfBot($errors, string $endpoint, string $login, string $email)
    {
        if (!$errors instanceof \WP_Error || is_user_logged_in()) {
            return $errors;
        }
        $result = self::judge($endpoint, ['username' => $login, 'email' => $email, 'role' => self::post('role')], null);
        if ($result['verdict'] === 'bot') {
            self::slowDown();
            $errors->add('draco_rejected', __('The registration could not be completed.', 'draco-insomnis'));
        }

        return $errors;
    }

    /**
     * @param array{username: string, email: string, role: string} $fields
     * @param list<string>|null $roles
     * @return array{score: int, verdict: string, reasons: list<string>}
     */
    private static function judge(string $endpoint, array $fields, ?array $roles): array
    {
        $ip = self::clientIp();
        $remote = self::remoteAddr();
        $stamp = FormStamp::check(Plugin::secret(), self::post(self::stampField()), time());
        $ua = substr(Input::server('HTTP_USER_AGENT'), 0, 255);
        $result = BotScore::evaluate([
            'blocked' => Store::isBlocked($fields['email'], $ip),
            'requested_role' => $fields['role'],
            'allowed_roles' => $roles,
            'honeypot' => self::post(self::trapField()),
            'stamp' => $stamp['state'],
            'elapsed' => $stamp['elapsed'],
            'username' => $fields['username'],
            'hosting_network' => NetList::contains(self::nets(), $ip),
            'recent_bot_attempts' => Store::botAttemptsSince($ip, DAY_IN_SECONDS),
            'user_agent' => $ua,
        ]);
        $result = (array) apply_filters('draco_insomnis_verdict', $result, $endpoint, $fields, $ip);
        if ($result['verdict'] !== 'clean') {
            Store::log($ip, $remote, $endpoint, $result, $ua, self::evidence($fields));
        }
        if ($result['verdict'] === 'bot') {
            self::maybeAutoBlock($ip, $remote);
        }

        return $result;
    }

    /**
     * Three bot attempts in a day block the address for a week. Only when the address is the
     * connection's own, or comes from a proxy header the administrator chose to trust: otherwise a
     * forged header could get an innocent visitor blocked.
     */
    private static function maybeAutoBlock(string $ip, string $remote): void
    {
        $trusted = $ip === $remote || (string) get_option(self::OPTION_PROXY, '') !== '';
        if (!$trusted || Store::isBlocked('', $ip)) {
            return;
        }
        if (Store::botAttemptsSince($ip, DAY_IN_SECONDS) >= self::AUTO_BLOCK_AFTER) {
            /* translators: %d: number of attempts */
            Store::block('ip', $ip, self::AUTO_BLOCK_DAYS, sprintf(__('Automatic: %d bot attempts in 24 h', 'draco-insomnis'), self::AUTO_BLOCK_AFTER), true);
        }
    }

    /** A few seconds, never more, and only while the site has workers to spare. */
    private static function slowDown(): void
    {
        $key = 'draco_slow_' . gmdate('YmdHi');
        $used = (int) get_transient($key) + 1;
        set_transient($key, $used, 120);
        if ($used <= self::SLOW_PER_MINUTE) {
            usleep(random_int(intdiv(self::SLOW_MAX_MS, 2), self::SLOW_MAX_MS) * 1000);
        }
    }

    /** @param array{username: string, email: string, role: string} $fields @return array<string, string> */
    private static function evidence(array $fields): array
    {
        return [
            'username' => substr($fields['username'], 0, 60),
            'email' => substr($fields['email'], 0, 120),
            'role' => substr($fields['role'], 0, 60),
            'referer' => substr(esc_url_raw(Input::server('HTTP_REFERER')), 0, 200),
        ];
    }

    /** @return list<string> */
    public static function nets(): array
    {
        $own = NetList::parse((string) get_option(self::OPTION_NETS, ''));

        return (array) apply_filters('draco_insomnis_hosting_nets', array_merge(NetList::SEEN_HOSTING, $own));
    }

    public static function clientIp(): string
    {
        $mode = (string) get_option(self::OPTION_PROXY, '');
        $candidate = '';
        if ($mode === 'cf') {
            $candidate = Input::server('HTTP_CF_CONNECTING_IP');
        } elseif ($mode === 'xff') {
            $candidate = explode(',', Input::server('HTTP_X_FORWARDED_FOR'))[0];
        }
        $ip = filter_var(trim($candidate), FILTER_VALIDATE_IP);

        return is_string($ip) ? $ip : self::remoteAddr();
    }

    private static function remoteAddr(): string
    {
        $ip = filter_var(Input::server('REMOTE_ADDR'), FILTER_VALIDATE_IP);

        return is_string($ip) ? $ip : '0.0.0.0';
    }

    private static function stamp(): string
    {
        return FormStamp::make(Plugin::secret(), time());
    }

    private static function trapHtml(): string
    {
        // Out of sight and out of the tab order; people and password managers leave it empty.
        return '<div aria-hidden="true" style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden">'
            . '<label>Website <input type="text" name="' . esc_attr(self::trapField()) . '" value="" tabindex="-1" autocomplete="off"></label></div>';
    }

    private static function post(string $name): string
    {
        return Input::post($name);
    }
}
