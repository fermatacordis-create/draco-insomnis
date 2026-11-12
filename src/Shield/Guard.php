<?php

declare(strict_types=1);

namespace DracoInsomnis\Shield;

use DracoInsomnis\Core\Shield;
use DracoInsomnis\Input;
use DracoInsomnis\WpHost;

defined('ABSPATH') || exit;

/**
 * Stands in front of the public sign-up forms of WordPress, WooCommerce and RealHomes. The judging
 * itself lives in Core\Shield, shared with the other CMSs.
 *
 * Only defends this site: a bot gets a fake "done" after a short, capped wait, and its attempt is kept
 * as evidence. Nothing is ever sent back to the attacker's machine.
 */
final class Guard
{
    public const OPTION_NETS = 'draco_hosting_nets';
    /** '' = trust only the connection address; 'cf' = Cloudflare header; 'xff' = first X-Forwarded-For entry. */
    public const OPTION_PROXY = 'draco_proxy_header';

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

    private static function engine(): Shield
    {
        return new Shield(WpHost::get());
    }

    public static function stampField(): string
    {
        return self::engine()->stampField();
    }

    public static function trapField(): string
    {
        return self::engine()->trapField();
    }

    /** Hidden inputs for forms rendered by WordPress itself. */
    public static function fields(): void
    {
        echo self::engine()->fieldsHtml(time()); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from constants and escaped attribute values
    }

    /** RealHomes builds its modal outside WordPress hooks, so the same inputs are added from the page. */
    public static function footerScript(): void
    {
        if (is_user_logged_in()) {
            return;
        }
        $engine = self::engine();
        $stamp = wp_json_encode($engine->stamp(time()));
        $trap = wp_json_encode($engine->trapHtml());
        $f = wp_json_encode($engine->stampField());
        $js = "(function(){var s={$stamp},t={$trap},f={$f};"
            . "function arm(){document.querySelectorAll('input[name=\"register_username\"]').forEach(function(u){var form=u.form;"
            . "if(!form||form.querySelector('input[name=\"'+f+'\"]'))return;"
            . "var h=document.createElement('input');h.type='hidden';h.name=f;h.value=s;form.appendChild(h);"
            . "form.insertAdjacentHTML('beforeend',t);});}"
            . "arm();document.addEventListener('DOMContentLoaded',arm);document.addEventListener('focusin',arm,true);})();";
        wp_print_inline_script_tag($js); // Every value inside is wp_json_encode()d.
    }

    public static function realHomes(): void
    {
        $roles = function_exists('inspiry_user_sync_roles') ? array_keys((array) inspiry_user_sync_roles()) : null;
        $result = self::judge('realhomes_ajax', [
            'username' => Input::post('register_username'),
            'email' => Input::post('register_email'),
            'role' => Input::post('user_role'),
        ], $roles);
        if ($result['verdict'] !== 'bot') {
            return;
        }
        self::engine()->slowDown();
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
        $result = self::judge($endpoint, ['username' => $login, 'email' => $email, 'role' => Input::post('role')], null);
        if ($result['verdict'] === 'bot') {
            self::engine()->slowDown();
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
        return self::engine()->judge(WpHost::request(), $endpoint, $fields, $roles, time());
    }

    /** @return list<string> */
    public static function nets(): array
    {
        return self::engine()->nets();
    }

    public static function clientIp(): string
    {
        return WpHost::request()->ip((string) get_option(self::OPTION_PROXY, ''));
    }
}
