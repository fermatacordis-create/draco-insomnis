<?php

declare(strict_types=1);

namespace DracoInsomnis;

use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\Host;
use DracoInsomnis\Core\Request;
use DracoInsomnis\Core\WafRules;
use DracoInsomnis\Shield\Events;

defined('ABSPATH') || exit;

/** The engines in src/Core, running in WordPress. */
final class WpHost implements Host
{
    private static ?self $instance = null;

    public static function get(): self
    {
        return self::$instance ??= new self();
    }

    /** The current request, read fresh every time (tests and long requests change it). */
    public static function request(): Request
    {
        $method = Input::method();
        $uri = Input::rawServer('REQUEST_URI');
        $post = [];
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- read to judge the request, never acted on.
        foreach ($_POST as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $post[$name] = sanitize_text_field(wp_unslash($value));
            }
        }

        return new Request(
            $method,
            rawurldecode((string) wp_parse_url($uri, PHP_URL_PATH)),
            urldecode((string) wp_parse_url($uri, PHP_URL_QUERY)),
            WafRules::flatten(array_merge(wp_unslash($_GET), $method === 'POST' ? wp_unslash($_POST) : [])), // phpcs:ignore WordPress.Security.NonceVerification -- inspected, never acted on
            $post,
            Input::server('HTTP_USER_AGENT'),
            Input::rawServer('HTTP_USER_AGENT'),
            Input::server('REMOTE_ADDR'),
            Input::server('HTTP_CF_CONNECTING_IP'),
            Input::server('HTTP_X_FORWARDED_FOR'),
            esc_url_raw(Input::server('HTTP_REFERER')),
        );
    }

    public function secret(): string
    {
        return Plugin::secret();
    }

    public function setting(string $name): string
    {
        $value = get_option('draco_' . $name, '');

        return is_scalar($value) ? (string) $value : '';
    }

    public function adminIps(): array
    {
        return array_values(array_map('strval', (array) get_option(Plugin::OPTION_ADMIN_IPS, [])));
    }

    public function bump(string $key, int $ttl): int
    {
        $count = (int) get_transient($key) + 1;
        set_transient($key, $count, $ttl);

        return $count;
    }

    public function recall(string $key): ?string
    {
        $value = get_transient($key);

        return $value === false ? null : (string) $value;
    }

    public function remember(string $key, string $value, int $ttl): void
    {
        set_transient($key, $value, $ttl);
    }

    public function filter(string $name, $value, ...$args)
    {
        return apply_filters('draco_insomnis_' . $name, $value, ...$args);
    }

    public function text(string $id, int $number): string
    {
        if ($id === 'waf_block') {
            self::earlyTranslations();
            /* translators: %d: number of attacks */
            return sprintf(__('Firewall: %d attacks in 10 minutes', 'draco-insomnis'), $number);
        }

        /* translators: %d: number of attempts */
        return sprintf(__('Automatic: %d bot attempts in 24 h', 'draco-insomnis'), $number);
    }

    public function events(): EventStore
    {
        return new Events();
    }

    /**
     * The firewall answers before WordPress loads translations (on purpose: it stops the request as
     * early as it can). Load this plugin's own file now; with no file for the language (English)
     * there is nothing to load, and WordPress's "too early" notice is about this case only.
     */
    public static function earlyTranslations(): void
    {
        if (did_action('after_setup_theme') || is_textdomain_loaded('draco-insomnis')) {
            return;
        }
        $locale = determine_locale();
        if (!load_textdomain('draco-insomnis', DRACO_INSOMNIS_DIR . 'languages/draco-insomnis-' . $locale . '.mo', $locale)) {
            add_filter('doing_it_wrong_trigger_error', static function ($trigger, $function, $message = '') {
                return $function === '_load_textdomain_just_in_time' && str_contains((string) $message, 'draco-insomnis') ? false : $trigger;
            }, 10, 3);
        }
    }
}
