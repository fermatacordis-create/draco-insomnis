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
        } elseif ($do === 'purge') {
            Store::clear();
            $result = 'purged';
        } elseif ($do === 'unblock') {
            Blocks::unblock(Input::postInt('id'));
            $result = 'unblocked';
        } elseif ($do === 'urlhaus' && LinkCheck::available()) {
            $confirmed = !empty($_POST['urlhaus_confirm']);
            $wanted = !empty($_POST['urlhaus']);
            update_option(LinkCheck::OPTION_CONFIRMED, $confirmed ? 'yes' : 'no');
            if ($wanted && !LinkCheck::hasKey()) {
                $wanted = false;
                $result = 'urlhaus_key';
            } elseif ($wanted && !$confirmed) {
                $wanted = false;
                $result = 'urlhaus_confirm';
            }
            update_option(LinkCheck::OPTION_ENABLED, $wanted ? 'yes' : 'no');
            if ($wanted) {
                $result = LinkCheck::update() === '' ? 'urlhaus_on' : 'urlhaus_failed';
            } else {
                wp_clear_scheduled_hook(LinkCheck::HOOK_UPDATE);
            }
        } elseif ($do === 'urlhaus_update' && LinkCheck::active()) {
            $result = LinkCheck::update() === '' ? 'urlhaus_updated' : 'urlhaus_failed';
        } elseif ($do === 'phishtank') {
            $wanted = !empty($_POST['phishtank']);
            update_option(LinkCheck::PT_OPTION_ENABLED, $wanted ? 'yes' : 'no');
            if ($wanted) {
                $result = LinkCheck::update(LinkCheck::PHISHTANK) === '' ? 'phishtank_on' : 'phishtank_failed';
            } else {
                LinkCheck::forget(LinkCheck::PHISHTANK);
                $result = 'phishtank_off';
            }
            if (LinkCheck::activeFeeds() === []) {
                wp_clear_scheduled_hook(LinkCheck::HOOK_UPDATE);
            }
        } elseif ($do === 'phishtank_update' && LinkCheck::phishtankActive()) {
            $result = LinkCheck::update(LinkCheck::PHISHTANK) === '' ? 'phishtank_on' : 'phishtank_failed';
        }
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=' . $result));
        exit;
    }

    /** Phishing links (PhishTank): off by default; allowed for commercial use; a key is optional. */
    private static function phishtankCard(): void
    {
        $on = LinkCheck::phishtankActive();
        $state = LinkCheck::state(LinkCheck::PHISHTANK);
        $stale = $on && LinkCheck::stale(LinkCheck::PHISHTANK);
        Brand::card('shield-alt', __('Phishing links (PhishTank)', 'draco-insomnis'), __('Links in comments and contact forms are checked against PhishTank, the list of verified phishing pages that are still online, kept by Cisco Talos. The list is downloaded twice a day and checked on this server: nothing your visitors write is sent anywhere. A comment with a listed link goes to spam; a contact message with one is not delivered.', 'draco-insomnis'), Brand::pill(Brand::stateLabel($on ? 'on' : 'off'), $on ? 'on' : 'off'));
        echo '<p class="description">' . esc_html__('PhishTank allows commercial and non-commercial use.', 'draco-insomnis') . ' <a href="' . esc_url(LinkCheck::PT_TERMS) . '" target="_blank" rel="noopener">' . esc_html__('PhishTank FAQ', 'draco-insomnis') . '</a></p>';
        if (!LinkCheck::phishtankHasKey()) {
            echo '<p class="description">' . esc_html__('Without a key PhishTank allows only a few downloads a day from the same server. If the download fails, create a free account at phishtank.org and add your application key to wp-config.php:', 'draco-insomnis') . ' <code>define( \'' . esc_html(LinkCheck::PT_KEY_CONSTANT) . '\', \'' . esc_html__('your-key', 'draco-insomnis') . '\' );</code></p>';
        }
        if ($state['updated'] > 0) {
            /* translators: 1: date and time, 2: number of entries */
            echo '<p>' . esc_html(sprintf(__('Last download: %1$s, %2$d entries.', 'draco-insomnis'), wp_date('Y-m-d H:i', $state['updated']), $state['count']));
            if ($state['error'] !== '') {
                /* translators: %s: short reason */
                echo ' <strong>' . esc_html(sprintf(__('Last attempt failed: %s.', 'draco-insomnis'), $state['error'])) . '</strong>';
            }
            echo '</p>';
        }
        if ($stale) {
            /* translators: %s: date */
            echo '<p class="draco-callout is-warn"><span class="dashicons dashicons-warning" aria-hidden="true"></span><span>' . esc_html(sprintf(__('The list has not changed since %s: PhishTank may have stopped updating it. Links are still checked against the last copy.', 'draco-insomnis'), wp_date('Y-m-d', $state['changed']))) . '</span></p>';
        }
        echo self::open('phishtank'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        Brand::toggle('phishtank', $on, __('Check links in comments and contact forms against PhishTank', 'draco-insomnis'));
        echo '<p style="margin-top:12px">';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</p></form>';
        if ($on) {
            echo self::open('phishtank_update'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            submit_button(__('Download the list now', 'draco-insomnis'), 'secondary', 'submit', false);
            echo '</form>';
        }
        Brand::cardEnd();
    }

    /** Malicious links (URLhaus): off by default; the owner's own key; non-profit use only for free. */
    private static function urlhausCard(): void
    {
        $on = LinkCheck::active();
        $state = LinkCheck::state();
        Brand::card('shield', __('Malicious links (URLhaus)', 'draco-insomnis'), __('Links in comments and contact forms are checked against URLhaus, the list of malware sites kept by abuse.ch. The list is downloaded twice a day with your own key and checked on this server: nothing your visitors write is sent anywhere. A comment with a listed link goes to spam; a contact message with one is not delivered.', 'draco-insomnis'), Brand::pill(Brand::stateLabel($on ? 'on' : 'off'), $on ? 'on' : 'off'));
        echo '<div class="notice notice-warning inline" style="margin:0 0 12px"><p><strong>' . esc_html__('Free use only for non-profit websites; for commercial use, a Spamhaus subscription.', 'draco-insomnis') . '</strong> '
            . esc_html__('That is what the abuse.ch terms of use say for URLhaus.', 'draco-insomnis') . ' '
            . '<a href="' . esc_url(LinkCheck::TERMS) . '" target="_blank" rel="noopener">' . esc_html__('Terms of use', 'draco-insomnis') . '</a> · '
            . '<a href="' . esc_url(LinkCheck::SPAMHAUS) . '" target="_blank" rel="noopener">' . esc_html__('Spamhaus subscription', 'draco-insomnis') . '</a></p></div>';
        if (!LinkCheck::hasKey()) {
            echo '<p>' . esc_html__('To use it, create a free account at auth.abuse.ch, copy your Auth-Key and add this line to wp-config.php. The key stays there: it is never saved in the database or shown on any screen.', 'draco-insomnis') . '</p>';
            echo '<p><code>define( \'' . esc_html(LinkCheck::KEY_CONSTANT) . '\', \'' . esc_html__('your-key', 'draco-insomnis') . '\' );</code></p>';
        } else {
            echo '<p>' . esc_html__('Key found in wp-config.php.', 'draco-insomnis') . ' ';
            if ($state['updated'] > 0) {
                /* translators: 1: date and time, 2: number of entries */
                echo esc_html(sprintf(__('Last download: %1$s, %2$d entries.', 'draco-insomnis'), wp_date('Y-m-d H:i', $state['updated']), $state['count']));
            }
            if ($state['error'] !== '') {
                /* translators: %s: short reason */
                echo ' <strong>' . esc_html(sprintf(__('Last attempt failed: %s.', 'draco-insomnis'), $state['error'])) . '</strong>';
            }
            echo '</p>';
        }
        echo self::open('urlhaus'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        Brand::toggle('urlhaus_confirm', get_option(LinkCheck::OPTION_CONFIRMED, 'no') === 'yes', __('I confirm this website is non-profit, or has a Spamhaus subscription', 'draco-insomnis'));
        Brand::toggle('urlhaus', get_option(LinkCheck::OPTION_ENABLED, 'no') === 'yes', __('Check links in comments and contact forms', 'draco-insomnis'));
        echo '<p style="margin-top:12px">';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</p></form>';
        if ($on) {
            echo self::open('urlhaus_update'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            submit_button(__('Download the list now', 'draco-insomnis'), 'secondary', 'submit', false);
            echo '</form>';
        }
        Brand::cardEnd();
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
        } elseif ($result === 'purged') {
            Brand::notice('success', __('Recent submissions cleared. Blocked addresses stay on the block list.', 'draco-insomnis'));
        } elseif ($result === 'unblocked') {
            Brand::notice('success', __('Address unblocked.', 'draco-insomnis'));
        } elseif ($result === 'urlhaus_key') {
            Brand::notice('error', __('Malicious links were not switched on: add your abuse.ch key to wp-config.php first.', 'draco-insomnis'));
        } elseif ($result === 'urlhaus_confirm') {
            Brand::notice('error', __('Malicious links were not switched on: confirm first that the site is non-profit or has a Spamhaus subscription.', 'draco-insomnis'));
        } elseif ($result === 'urlhaus_on' || $result === 'urlhaus_updated') {
            /* translators: %d: number of entries in the list */
            Brand::notice('success', sprintf(__('URLhaus list downloaded: %d entries.', 'draco-insomnis'), LinkCheck::state()['count']));
        } elseif ($result === 'urlhaus_failed') {
            /* translators: %s: short reason, such as "HTTP 403" */
            Brand::notice('error', sprintf(__('The URLhaus list could not be downloaded (%s). Links are not checked until it is.', 'draco-insomnis'), LinkCheck::state()['error']));
        } elseif ($result === 'phishtank_on') {
            /* translators: %d: number of entries in the list */
            Brand::notice('success', sprintf(__('PhishTank list downloaded: %d entries.', 'draco-insomnis'), LinkCheck::state(LinkCheck::PHISHTANK)['count']));
        } elseif ($result === 'phishtank_failed') {
            /* translators: %s: short reason, such as "HTTP 509" */
            Brand::notice('error', sprintf(__('The PhishTank list could not be downloaded (%s). Links are not checked against it until it is.', 'draco-insomnis'), LinkCheck::state(LinkCheck::PHISHTANK)['error']));
        } elseif ($result === 'phishtank_off') {
            Brand::notice('success', __('Phishing links are no longer checked.', 'draco-insomnis'));
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
                echo '<option value="' . (int) $days . '"' . selected($days, 30, false) . '>' . esc_html(Blocks::daysLabel($days)) . '</option>';
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
        // Phishing links (PhishTank) everywhere; malware links (URLhaus) only where its terms allow it.
        self::phishtankCard();
        if (LinkCheck::available()) {
            self::urlhausCard();
        }

        $labels = ['pending' => [__('Waiting for confirmation', 'draco-insomnis'), 'warn'], 'verified' => [__('Confirmed', 'draco-insomnis'), 'on'], 'expired' => [__('Expired without confirmation', 'draco-insomnis'), 'off']];
        $kinds = ['user' => [__('Account', 'draco-insomnis'), 'admin-users'], 'comment' => [__('Comment', 'draco-insomnis'), 'admin-comments'], 'form' => [__('Message', 'draco-insomnis'), 'email']];
        Brand::card('list-view', __('Recent submissions', 'draco-insomnis'), __('Each submission is kept for 90 days, confirmed or not. "Block" works on any row — including after they confirm from their e-mail: confirming only proves the mailbox exists, not that it can be trusted. "Deliver now" lets a real submission through without waiting.', 'draco-insomnis'), '', 'info', 'draco-card--flush');
        $rows = get_option('draco_gate_schema') ? Store::recent() : [];
        if ($rows !== []) {
            echo self::open('purge'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo '<p class="draco-toolbar"><button type="submit" class="button" onclick="return confirm(\'' . esc_js(__('Clear all recent submissions from this list? Blocked addresses stay on the block list. This cannot be undone.', 'draco-insomnis')) . '\')">' . esc_html__('Clear list', 'draco-insomnis') . '</button></p></form>';
        }
        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>' . esc_html__('Type', 'draco-insomnis') . '</th><th>' . esc_html__('Where', 'draco-insomnis') . '</th><th>' . esc_html__('E-mail', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('Status', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $link = admin_url('admin.php?page=' . self::SLUG . '&block=' . (int) $r['id']);
            $kind = $kinds[(string) $r['kind']] ?? [(string) $r['kind'], 'marker'];
            $status = $labels[(string) $r['status']] ?? [(string) $r['status'], 'off'];
            $blockLabel = $r['status'] === 'verified' ? __('Block confirmed sender', 'draco-insomnis') : __('Block', 'draco-insomnis');
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td><span class="dashicons dashicons-' . esc_attr($kind[1]) . '" aria-hidden="true" style="color:#64748b"></span> ' . esc_html($kind[0]) . '</td><td>' . esc_html((string) $r['context']) . '</td><td>' . esc_html((string) $r['email']) . '</td><td><span class="draco-code">' . esc_html((string) $r['ip']) . '</span></td><td>'
                . wp_kses_post(Brand::pill($status[0], $status[1])) . '</td><td><a class="button button-small" href="' . esc_url($link) . '">' . esc_html($blockLabel) . '</a>';
            if ($r['status'] === 'pending') {
                echo ' ' . self::open('release') . '<input type="hidden" name="id" value="' . (int) $r['id'] . '"><button class="button button-small">' . esc_html__('Deliver now', 'draco-insomnis') . '</button></form>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            }
            echo '</td></tr>';
        }
        if ($rows === []) {
            Brand::emptyRow(7, __('No submissions yet.', 'draco-insomnis'), 'email');
        }
        echo '</tbody></table></div>';
        Brand::cardEnd();
        \DracoInsomnis\Shield\Admin::renderSharedBlocksCard(self::ACTION, self::ACTION, ['email', 'ip']);
        Brand::close();
    }
}
