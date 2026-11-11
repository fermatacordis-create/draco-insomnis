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
        add_action('admin_menu', [self::class, 'menu'], 11);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
    }

    public static function menu(): void
    {
        $title = __('Forms and sign-ups', 'draco-insomnis');
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

        Brand::open(__('Forms and sign-ups', 'draco-insomnis'), __('Holds every contact message, comment and new account until the sender confirms from their e-mail. Bots do not confirm, so their spam never reaches you. Payments in the shop are never held.', 'draco-insomnis'));
        if ($result === 'blocked') {
            Brand::notice('error', Gate::blocker());
        } elseif ($result === 'refused') {
            Brand::notice('error', __('Nothing was blocked: the value is not valid, belongs to an administrator, or is your own address.', 'draco-insomnis'));
        } elseif ($result === 'ok') {
            Brand::notice('success', __('Changes saved.', 'draco-insomnis'));
        }
        if ($enabled && !Transport::hasSmtp()) {
            Brand::notice('error', __('It is on without SMTP. If the confirmation mail does not arrive, messages are deleted after 48 hours without anyone knowing.', 'draco-insomnis'), admin_url('admin.php?page=draco-insomnis-mail'), __('Set up Site mail (SMTP) →', 'draco-insomnis'));
        }

        $row = $blockId > 0 ? Store::find($blockId) : null;
        if ($row !== null) {
            Brand::card('dismiss', __('Block this sender?', 'draco-insomnis'), (string) $row['email'] . ' · IP ' . (string) $row['ip'], '', 'bad');
            echo self::open('block') . '<input type="hidden" name="id" value="' . (int) $row['id'] . '">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo '<div class="draco-inline"><label class="draco-switch" style="padding:0"><input type="checkbox" name="ip" value="1"><span class="draco-switch__text"><strong>' . esc_html__('Also block the IP address', 'draco-insomnis') . '</strong></span></label>';
            echo '<select name="days" aria-label="' . esc_attr__('For', 'draco-insomnis') . '">';
            foreach (Blocks::BLOCK_DAYS as $days) {
                /* translators: %d: number of days */
                echo '<option value="' . (int) $days . '"' . selected($days, 30, false) . '>' . esc_html(sprintf(__('%d days', 'draco-insomnis'), $days)) . '</option>';
            }
            echo '</select> ';
            submit_button(__('Block', 'draco-insomnis'), 'primary', 'submit', false);
            echo '</div></form>';
            Brand::cardEnd();
        }

        Brand::card('feedback', __('Settings', 'draco-insomnis'), __('Contact Form 7, WPForms, Elementor, Divi, RealHomes, comments and new accounts.', 'draco-insomnis'), Brand::pill(Brand::stateLabel($enabled ? 'on' : 'off'), $enabled ? 'on' : 'off'));
        echo self::open('settings'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        Brand::toggle('enabled', $enabled, __('Verify contact forms and sign-ups', 'draco-insomnis'), __('The sender gets an e-mail with a button; nothing is delivered until it is pressed.', 'draco-insomnis'));
        Brand::toggle('registration', get_option(Gate::OPTION_REGISTRATION, 'yes') === 'yes', __('Include new user accounts (accounts created while paying in the shop are never held)', 'draco-insomnis'));
        Brand::toggle('comments', get_option(Gate::OPTION_COMMENTS, 'yes') === 'yes', __('Include blog comments: they are not saved, not even as pending, until the author confirms. Trackbacks and pingbacks are dropped.', 'draco-insomnis'));
        Brand::toggle('credit', get_option(Template::OPTION_CREDIT, 'no') === 'yes', __('Mention Draco Insomnis in the footer of confirmation e-mails', 'draco-insomnis'));
        echo '<p style="margin-top:12px">';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</p></form>';
        Brand::cardEnd();

        $labels = ['pending' => [__('Waiting for confirmation', 'draco-insomnis'), 'warn'], 'verified' => [__('Confirmed', 'draco-insomnis'), 'on'], 'expired' => [__('Expired without confirmation', 'draco-insomnis'), 'off']];
        $kinds = ['user' => [__('Account', 'draco-insomnis'), 'admin-users'], 'comment' => [__('Comment', 'draco-insomnis'), 'admin-comments'], 'form' => [__('Message', 'draco-insomnis'), 'email']];
        Brand::card('list-view', __('Recent submissions', 'draco-insomnis'), __('Each submission is kept for 90 days, confirmed or not. "Block" works on any row: confirming only proves the mailbox exists, not that it can be trusted. "Deliver now" lets a real submission through without waiting.', 'draco-insomnis'), '', 'info', 'draco-card--flush');
        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>' . esc_html__('Type', 'draco-insomnis') . '</th><th>' . esc_html__('Where', 'draco-insomnis') . '</th><th>' . esc_html__('E-mail', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('Status', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        $rows = get_option('draco_gate_schema') ? Store::recent() : [];
        foreach ($rows as $r) {
            $link = admin_url('admin.php?page=' . self::SLUG . '&block=' . (int) $r['id']);
            $kind = $kinds[(string) $r['kind']] ?? [(string) $r['kind'], 'marker'];
            $status = $labels[(string) $r['status']] ?? [(string) $r['status'], 'off'];
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td><span class="dashicons dashicons-' . esc_attr($kind[1]) . '" aria-hidden="true" style="color:#64748b"></span> ' . esc_html($kind[0]) . '</td><td>' . esc_html((string) $r['context']) . '</td><td>' . esc_html((string) $r['email']) . '</td><td><span class="draco-code">' . esc_html((string) $r['ip']) . '</span></td><td>'
                . wp_kses_post(Brand::pill($status[0], $status[1])) . '</td><td><a href="' . esc_url($link) . '">' . esc_html__('Block', 'draco-insomnis') . '</a>';
            if ($r['status'] === 'pending') {
                echo ' · ' . self::open('release') . '<input type="hidden" name="id" value="' . (int) $r['id'] . '"><button class="button-link">' . esc_html__('Deliver now', 'draco-insomnis') . '</button></form>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            }
            echo '</td></tr>';
        }
        if ($rows === []) {
            Brand::emptyRow(7, __('No submissions yet.', 'draco-insomnis'), 'email');
        }
        echo '</tbody></table></div>';
        Brand::cardEnd();
        Brand::close();
    }
}
