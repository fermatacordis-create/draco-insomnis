<?php

declare(strict_types=1);

namespace DracoInsomnis\Admin;

use DracoInsomnis\Firewall\Waf;
use DracoInsomnis\Gate\Gate;
use DracoInsomnis\Login\Mfa;
use DracoInsomnis\Login\Recovery;
use DracoInsomnis\Mail\Settings;
use DracoInsomnis\Mail\Transport;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- counts over the plugin's own tables; every value goes through prepare().

/** The landing screen: what is on, what it did this week, and what is left to do. */
final class Overview
{
    private const WEEK = 7 * DAY_IN_SECONDS;

    public static function render(): void
    {
        $since = gmdate('Y-m-d H:i:s', time() - self::WEEK);
        Brand::open(__('Overview', 'draco-insomnis'), __('Everything Draco Insomnis protects on this site, at a glance. Each module can be switched on and off on its own screen.', 'draco-insomnis'));

        $bots = self::bots($since);
        $attacks = self::events('waf:', $since);
        $copy = self::events('anticopy:', $since);
        $held = self::submissions($since);
        echo '<div class="draco-stats">';
        self::stat($bots, __('bots stopped in sign-ups', 'draco-insomnis'), 'shield-alt');
        self::stat($held, __('submissions checked by e-mail', 'draco-insomnis'), 'feedback');
        self::stat($attacks, __('attacks seen by the firewall', 'draco-insomnis'), 'privacy');
        self::stat($copy, __('copy attempts recorded', 'draco-insomnis'), 'hidden');
        echo '</div><p class="draco-hint" style="margin:-8px 0 18px">' . esc_html__('Last 7 days.', 'draco-insomnis') . '</p>';

        $modules = Brand::modules();
        $facts = [
            'draco-insomnis-shield' => [
                /* translators: %d: number of addresses or e-mails */
                sprintf(__('%d blocked addresses or e-mails right now', 'draco-insomnis'), count(Store::activeBlocks())),
                __('Fake sign-ups are answered "done" and kept as evidence.', 'draco-insomnis'),
            ],
            'draco-insomnis-forms' => [
                /* translators: %d: number of submissions */
                sprintf(__('%d waiting for their sender to confirm', 'draco-insomnis'), self::pending()),
                get_option(Gate::OPTION_ENABLED, 'no') === 'yes' && !Transport::hasSmtp() ? __('On without SMTP: confirmations may not arrive.', 'draco-insomnis') : __('Messages, comments and new accounts wait for an e-mail confirmation.', 'draco-insomnis'),
            ],
            'draco-insomnis-login' => [
                Mfa::active() ? self::who() : __('Only the password is asked for.', 'draco-insomnis'),
                get_option(Mfa::OPTION_TRUST, 'yes') === 'yes' ? __('Trusted devices: 7 days without a code.', 'draco-insomnis') : __('A code at every login.', 'draco-insomnis'),
            ],
            'draco-insomnis-firewall' => [
                Waf::active() ? (Waf::blocking() ? __('Stopping attacks.', 'draco-insomnis') : __('Recording attacks without stopping them.', 'draco-insomnis')) : __('No request is inspected.', 'draco-insomnis'),
                __('User list hidden, failed logins limited, XML-RPC tamed.', 'draco-insomnis'),
            ],
            'draco-insomnis-anticopy' => [
                __('Content API for anonymous visitors and pages per minute.', 'draco-insomnis'),
                __('Verified search engines are never limited.', 'draco-insomnis'),
            ],
            'draco-insomnis-mail' => [
                /* translators: %s: sender address */
                Settings::active() ? sprintf(__('Sending as %s', 'draco-insomnis'), Settings::fromAddress()) : (Transport::otherSender() !== '' ? sprintf(__('Sending through %s', 'draco-insomnis'), Transport::otherSender()) : __('Sending with PHP mail()', 'draco-insomnis')),
                __('Login codes and confirmations depend on it.', 'draco-insomnis'),
            ],
        ];
        echo '<div class="draco-grid">';
        foreach ($modules as $slug => [$title, $icon, $state]) {
            if (!isset($facts[$slug])) {
                continue;
            }
            if ($slug === 'draco-insomnis-mail' && $state === 'off' && Transport::otherSender() !== '') {
                $state = 'other';
            }
            $tone = $state === 'on' ? 'on' : ($state === 'log' ? 'log' : ($state === 'other' ? 'info' : 'off'));
            $label = $state === 'other' ? __('Another plugin', 'draco-insomnis') : Brand::stateLabel($state);
            Brand::card($icon, $title, '', Brand::pill($label, $tone), '', 'draco-module');
            foreach ($facts[$slug] as $fact) {
                echo '<p class="draco-module__fact">' . esc_html($fact) . '</p>';
            }
            echo '</div><div class="draco-card__foot"><a href="' . esc_url(admin_url('admin.php?page=' . $slug)) . '">' . esc_html__('Open', 'draco-insomnis') . ' →</a>';
            Brand::cardEnd();
        }
        echo '</div>';

        Brand::card('yes-alt', __('Checklist', 'draco-insomnis'), __('What makes the biggest difference, in order.', 'draco-insomnis'));
        echo '<ul class="draco-todo">';
        $user = wp_get_current_user();
        self::todo(Settings::active() || Transport::otherSender() !== '', __('Site mail goes out through a real mailbox', 'draco-insomnis'), 'draco-insomnis-mail');
        self::todo(get_option(Plugin::OPTION_SHIELD, 'no') === 'yes', __('The anti-bot shield protects sign-ups', 'draco-insomnis'), 'draco-insomnis-shield');
        self::todo(get_option(Gate::OPTION_ENABLED, 'no') === 'yes', __('Forms and sign-ups are confirmed by e-mail', 'draco-insomnis'), 'draco-insomnis-forms');
        self::todo(Mfa::active(), __('Administrators log in with a code by e-mail', 'draco-insomnis'), 'draco-insomnis-login');
        if (Mfa::active()) {
            self::todo(Recovery::email((int) $user->ID) !== '', __('You have a recovery e-mail', 'draco-insomnis'), 'users.php?page=' . Recovery::SLUG);
        }
        self::todo(Waf::active() && Waf::blocking(), Waf::active() ? __('The firewall blocks attacks (switch it from "Log only" once you have looked at what it records)', 'draco-insomnis') : __('The firewall is on', 'draco-insomnis'), 'draco-insomnis-firewall');
        echo '</ul>';
        Brand::cardEnd();
        Brand::close();
    }

    private static function stat(int $number, string $label, string $icon): void
    {
        echo '<div class="draco-stat"><div class="draco-stat__num">' . esc_html(number_format_i18n($number)) . '</div><div class="draco-stat__label"><span class="dashicons dashicons-' . esc_attr($icon) . '" aria-hidden="true"></span>' . esc_html($label) . '</div></div>';
    }

    private static function todo(bool $done, string $text, string $page): void
    {
        $url = str_contains($page, '.php') ? admin_url($page) : admin_url('admin.php?page=' . $page);
        echo '<li><span class="dashicons dashicons-' . ($done ? 'yes-alt is-ok' : 'warning is-warn') . '" aria-hidden="true"></span><span>' . esc_html($text);
        if (!$done) {
            echo ' · <a href="' . esc_url($url) . '">' . esc_html__('Set it up', 'draco-insomnis') . ' →</a>';
        }
        echo '</span></li>';
    }

    private static function who(): string
    {
        $who = (string) get_option(Mfa::OPTION_WHO, 'admins');
        $labels = ['admins' => __('Administrators enter a code by e-mail.', 'draco-insomnis'), 'editors' => __('Everyone who edits content enters a code by e-mail.', 'draco-insomnis'), 'all' => __('Every user enters a code by e-mail.', 'draco-insomnis')];

        return $labels[$who] ?? $labels['admins'];
    }

    /** Events whose endpoint starts with $prefix (firewall, anti-copy) since a date. */
    private static function events(string $prefix, string $since): int
    {
        global $wpdb;
        if (get_option('draco_schema') === false) {
            return 0;
        }

        return (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i WHERE endpoint LIKE %s AND created_at > %s', Store::events(), $wpdb->esc_like($prefix) . '%', $since));
    }

    /** Bot verdicts of the shield: everything except the firewall and anti-copy. */
    private static function bots(string $since): int
    {
        global $wpdb;
        if (get_option('draco_schema') === false) {
            return 0;
        }

        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM %i WHERE endpoint NOT LIKE %s AND endpoint NOT LIKE %s AND verdict = 'bot' AND created_at > %s",
            Store::events(),
            $wpdb->esc_like('waf:') . '%',
            $wpdb->esc_like('anticopy:') . '%',
            $since,
        ));
    }

    private static function submissions(string $since): int
    {
        global $wpdb;
        if (get_option('draco_gate_schema') === false) {
            return 0;
        }

        return (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i WHERE created_at > %s', \DracoInsomnis\Gate\Store::table(), $since));
    }

    private static function pending(): int
    {
        global $wpdb;
        if (get_option('draco_gate_schema') === false) {
            return 0;
        }

        return (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM %i WHERE status = 'pending' AND created_at > %s", \DracoInsomnis\Gate\Store::table(), gmdate('Y-m-d H:i:s', time() - 2 * DAY_IN_SECONDS)));
    }
}
