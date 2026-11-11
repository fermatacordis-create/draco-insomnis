<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

use DracoInsomnis\Mail\Transport;

defined('ABSPATH') || exit;

/** Off until the owner switches it on, site by site. */
final class Gate
{
    public const OPTION_ENABLED = 'draco_gate_enabled';
    public const OPTION_REGISTRATION = 'draco_gate_registration';
    public const OPTION_COMMENTS = 'draco_gate_comments';
    public const HOOK_CLEANUP = 'draco_gate_cleanup';

    public static function boot(): void
    {
        Admin::register();
        // Links already sent keep working, and pending accounts stay closed, if it is switched off later.
        Verify::register();
        add_action(self::HOOK_CLEANUP, [self::class, 'cleanup']);
        if (get_option(self::OPTION_ENABLED, 'no') !== 'yes') {
            return;
        }
        Store::ensureTable();
        MailHold::register();
        if (get_option(self::OPTION_REGISTRATION, 'yes') === 'yes') {
            RegistrationHold::register();
        }
        if (get_option(self::OPTION_COMMENTS, 'yes') === 'yes') {
            CommentHold::register();
        }
        if (!wp_next_scheduled(self::HOOK_CLEANUP)) {
            wp_schedule_event(time() + 600, 'hourly', self::HOOK_CLEANUP);
        }
    }

    /** Why it cannot be switched on, or '' if it can. */
    public static function blocker(): string
    {
        if (get_option('opnv_form_gate_enabled', 'no') === 'yes') {
            return __('Form verification of OPNV-WP is already on in this site. Use one of them, not both.', 'draco-insomnis');
        }
        if (!Transport::hasSmtp()) {
            return __('Without SMTP the confirmation mail may not arrive and messages would be lost. Set up Site mail (SMTP) first.', 'draco-insomnis');
        }

        return '';
    }

    public static function cleanup(): void
    {
        Store::cleanup();
        RegistrationHold::purge();
    }
}
