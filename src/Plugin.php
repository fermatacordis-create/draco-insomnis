<?php

declare(strict_types=1);

namespace DracoInsomnis;

use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Gate\Gate;
use DracoInsomnis\Mail\Admin as MailAdmin;
use DracoInsomnis\Mail\Transport;
use DracoInsomnis\Shield\Admin;
use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

final class Plugin
{
    public const OPTION_SHIELD = 'draco_shield_enabled';
    public const OPTION_ADMIN_IPS = 'draco_admin_ips';
    public const OPTION_SECRET = 'draco_secret';
    public const HOOK_CLEANUP = 'draco_cleanup';
    private static bool $booted = false;

    public static function boot(): void
    {
        if (self::$booted) {
            return;
        }
        self::$booted = true;
        load_plugin_textdomain('draco-insomnis', false, dirname(plugin_basename(DRACO_INSOMNIS_FILE)) . '/languages');
        Store::ensureTables();
        Brand::register();
        Admin::register();
        MailAdmin::register();
        Transport::register();
        Gate::boot();
        add_action(self::HOOK_CLEANUP, [Store::class, 'cleanup']);
        add_action('admin_init', [self::class, 'rememberAdminIp']);
        if (get_option(self::OPTION_SHIELD, 'no') === 'yes') {
            Guard::register();
        }
    }

    public static function activate(): void
    {
        self::secret();
        Store::ensureTables();
        if (!wp_next_scheduled(self::HOOK_CLEANUP)) {
            wp_schedule_event(time() + 900, 'daily', self::HOOK_CLEANUP);
        }
    }

    public static function deactivate(): void
    {
        wp_clear_scheduled_hook(self::HOOK_CLEANUP);
        wp_clear_scheduled_hook(Gate::HOOK_CLEANUP);
    }

    /**
     * Per-site secret. It signs the page stamp and picks this site's field names, so knowing the
     * plugin's source code does not tell a bot what to send.
     */
    public static function secret(): string
    {
        $secret = (string) get_option(self::OPTION_SECRET, '');
        if (strlen($secret) !== 64) {
            $secret = bin2hex(random_bytes(32));
            update_option(self::OPTION_SECRET, $secret, true);
        }

        return $secret;
    }

    /** The automatic block never touches the last addresses an administrator worked from. */
    public static function rememberAdminIp(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $ip = Guard::clientIp();
        $list = (array) get_option(self::OPTION_ADMIN_IPS, []);
        if (($list[0] ?? null) === $ip) {
            return;
        }
        update_option(self::OPTION_ADMIN_IPS, array_slice(array_values(array_unique(array_merge([$ip], $list))), 0, 10), false);
    }
}
