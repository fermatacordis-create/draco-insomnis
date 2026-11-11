<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

use DracoInsomnis\Input;
use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Mail\Template;
use DracoInsomnis\Mail\Transport;
use DracoInsomnis\Shield\Store as Blocks;

defined('ABSPATH') || exit;

/** The owner's screen: switch it on, see what is waiting, deliver or block. */
final class Admin
{
    public const SLUG = 'draco-insomnis-forms';
    private const ACTION = 'draco_gate_admin';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu'], 15);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
    }

    public static function menu(): void
    {
        $title = __('Forms and sign-ups', 'draco-insomnis');
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
            $wanted = !empty($_POST['enabled']);
            $wasOn = get_option(Gate::OPTION_ENABLED, 'no') === 'yes';
            if ($wanted && !$wasOn && Gate::blocker() !== '') {
                $wanted = false;
                $result = 'blocked';
            }
            update_option(Gate::OPTION_ENABLED, $wanted ? 'yes' : 'no');
            update_option(Gate::OPTION_REGISTRATION, empty($_POST['registration']) ? 'no' : 'yes');
            update_option(Gate::OPTION_COMMENTS, empty($_POST['comments']) ? 'no' : 'yes');
            update_option(Template::OPTION_CREDIT, empty($_POST['credit']) ? 'no' : 'yes');
            if ($wanted) {
                Store::ensureTable();
            }
        } elseif ($do === 'release') {
            $row = Store::find(Input::postInt('id'));
            if ($row !== null && $row['status'] === 'pending' && Store::claim((int) $row['id'])) {
                Verify::complete($row);
            }
        } elseif ($do === 'block') {
            $row = Store::find(Input::postInt('id'));
            $days = Input::postInt('days', 30);
            $done = false;
            if ($row !== null) {
                /* translators: %d: submission number */
                $reason = sprintf(__('From the list of submissions (#%d)', 'draco-insomnis'), (int) $row['id']);
                $done = Blocks::block('email', (string) $row['email'], $days, $reason);
                $done = (!empty($_POST['ip']) && Blocks::block('ip', (string) $row['ip'], $days, $reason)) || $done;
            }
            $result = $done ? 'ok' : 'refused';
        }
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=' . $result));
        exit;
    }

    private static function open(string $do): string
    {
        return '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline">'
            . wp_nonce_field(self::ACTION, '_wpnonce', true, false)
            . '<input type="hidden" name="action" value="' . self::ACTION . '"><input type="hidden" name="do" value="' . esc_attr($do) . '">';
    }

    public static function render(): void
    {
        $enabled = get_option(Gate::OPTION_ENABLED, 'no') === 'yes';
        $result = sanitize_key((string) ($_GET['result'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        $blockId = Input::getInt('block');

        echo '<div class="wrap">';
        Brand::header(__('Forms and sign-ups', 'draco-insomnis'));
        echo '<p>' . esc_html__('Holds every contact message, comment and new account until the sender confirms from their e-mail. Bots do not confirm, so their spam never reaches you. Payments in the shop are never held.', 'draco-insomnis') . '</p>';
        if ($result === 'blocked') {
            echo '<div class="notice notice-error"><p>' . esc_html(Gate::blocker()) . '</p></div>';
        } elseif ($result === 'refused') {
            echo '<div class="notice notice-error"><p>' . esc_html__('Nothing was blocked: the value is not valid, belongs to an administrator, or is your own address.', 'draco-insomnis') . '</p></div>';
        } elseif ($result === 'ok') {
            echo '<div class="notice notice-success"><p>' . esc_html__('Changes saved.', 'draco-insomnis') . '</p></div>';
        }
        if ($enabled && !Transport::hasSmtp()) {
            echo '<div class="notice notice-error"><p>' . esc_html__('It is on without SMTP. If the confirmation mail does not arrive, messages are deleted after 48 hours without anyone knowing.', 'draco-insomnis') . ' <a href="' . esc_url(admin_url('admin.php?page=draco-insomnis-mail')) . '">' . esc_html__('Set up Site mail (SMTP) →', 'draco-insomnis') . '</a></p></div>';
        }

        $row = $blockId > 0 ? Store::find($blockId) : null;
        if ($row !== null) {
            echo '<div class="notice notice-warning"><p><strong>' . esc_html__('Block this sender?', 'draco-insomnis') . '</strong> ' . esc_html((string) $row['email']) . ' · IP ' . esc_html((string) $row['ip']) . '</p><p>';
            echo self::open('block') . '<input type="hidden" name="id" value="' . (int) $row['id'] . '">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo '<label><input type="checkbox" name="ip" value="1"> ' . esc_html__('Also block the IP address', 'draco-insomnis') . '</label> ';
            echo '<select name="days">';
            foreach (Blocks::BLOCK_DAYS as $days) {
                /* translators: %d: number of days */
                echo '<option value="' . (int) $days . '"' . selected($days, 30, false) . '>' . esc_html(sprintf(__('%d days', 'draco-insomnis'), $days)) . '</option>';
            }
            echo '</select> ';
            submit_button(__('Block', 'draco-insomnis'), 'primary', 'submit', false);
            echo '</form></p></div>';
        }

        echo '<h2>' . esc_html__('Settings', 'draco-insomnis') . '</h2>' . self::open('settings'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        $box = static function (string $name, bool $on, string $label): void {
            echo '<p><label><input type="checkbox" name="' . esc_attr($name) . '" value="1" ' . checked($on, true, false) . '> ' . esc_html($label) . '</label></p>';
        };
        $box('enabled', $enabled, __('Verify contact forms and sign-ups', 'draco-insomnis'));
        $box('registration', get_option(Gate::OPTION_REGISTRATION, 'yes') === 'yes', __('Include new user accounts (accounts created while paying in the shop are never held)', 'draco-insomnis'));
        $box('comments', get_option(Gate::OPTION_COMMENTS, 'yes') === 'yes', __('Include blog comments: they are not saved, not even as pending, until the author confirms. Trackbacks and pingbacks are dropped.', 'draco-insomnis'));
        $box('credit', get_option(Template::OPTION_CREDIT, 'no') === 'yes', __('Mention Draco Insomnis in the footer of confirmation e-mails', 'draco-insomnis'));
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';

        $labels = ['pending' => __('Waiting for confirmation', 'draco-insomnis'), 'verified' => __('Confirmed', 'draco-insomnis'), 'expired' => __('Expired without confirmation', 'draco-insomnis')];
        $kinds = ['user' => __('Account', 'draco-insomnis'), 'comment' => __('Comment', 'draco-insomnis'), 'form' => __('Message', 'draco-insomnis')];
        echo '<h2>' . esc_html__('Recent submissions', 'draco-insomnis') . '</h2><p>' . esc_html__('Each submission is kept for 90 days, confirmed or not. "Block" works on any row: confirming only proves the mailbox exists, not that it can be trusted. "Deliver now" lets a real submission through without waiting.', 'draco-insomnis') . '</p>';
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>' . esc_html__('Type', 'draco-insomnis') . '</th><th>' . esc_html__('Where', 'draco-insomnis') . '</th><th>' . esc_html__('E-mail', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('Status', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        $rows = get_option('draco_gate_schema') ? Store::recent() : [];
        foreach ($rows as $r) {
            $link = admin_url('admin.php?page=' . self::SLUG . '&block=' . (int) $r['id']);
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td>' . esc_html($kinds[(string) $r['kind']] ?? (string) $r['kind']) . '</td><td>' . esc_html((string) $r['context']) . '</td><td>' . esc_html((string) $r['email']) . '</td><td>' . esc_html((string) $r['ip']) . '</td><td>'
                . esc_html($labels[(string) $r['status']] ?? (string) $r['status']) . '</td><td><a href="' . esc_url($link) . '">' . esc_html__('Block', 'draco-insomnis') . '</a>';
            if ($r['status'] === 'pending') {
                echo ' · ' . self::open('release') . '<input type="hidden" name="id" value="' . (int) $r['id'] . '"><button class="button-link">' . esc_html__('Deliver now', 'draco-insomnis') . '</button></form>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            }
            echo '</td></tr>';
        }
        if ($rows === []) {
            echo '<tr><td colspan="7">' . esc_html__('No submissions yet.', 'draco-insomnis') . '</td></tr>';
        }
        echo '</tbody></table></div>';
    }
}
