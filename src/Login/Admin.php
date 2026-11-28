<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Input;

defined('ABSPATH') || exit;

/** The owner's screen for the two-step login. */
final class Admin
{
    public const SLUG = 'draco-insomnis-login';
    private const ACTION = 'draco_mfa_admin';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu'], 12);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
    }

    public static function menu(): void
    {
        $title = __('Two-step login', 'draco-insomnis');
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
        if (Input::post('do') === 'lock') {
            self::saveLock();
        }
        if (Input::post('do') === 'passwords') {
            $min = Input::postInt('pwd_min');
            update_option(Passwords::OPTION_MIN, $min >= 8 && $min <= 64 ? $min : 0);
            update_option(Passwords::OPTION_BREACHED, empty($_POST['pwd_breached']) ? 'no' : 'yes');
            wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=ok#draco-passwords'));
            exit;
        }
        $result = 'ok';
        $wanted = !empty($_POST['enabled']);
        if ($wanted && get_option(Mfa::OPTION_ENABLED, 'no') !== 'yes' && Mfa::blocker() !== '') {
            $wanted = false;
            $result = 'blocked';
        }
        update_option(Mfa::OPTION_ENABLED, $wanted ? 'yes' : 'no');
        $who = sanitize_key((string) ($_POST['who'] ?? 'admins'));
        update_option(Mfa::OPTION_WHO, in_array($who, ['admins', 'editors', 'all'], true) ? $who : 'admins');
        update_option(Mfa::OPTION_TRUST, empty($_POST['trust']) ? 'no' : 'yes');
        $cosign = !empty($_POST['cosign']);
        // Never switched on when nobody could co-sign your own next login.
        if ($cosign && get_option(CoSign::OPTION_ENABLED, 'no') !== 'yes' && !CoSign::reachableFor(wp_get_current_user())) {
            $cosign = false;
            $result = 'cosign_blocked';
        }
        update_option(CoSign::OPTION_ENABLED, $cosign ? 'yes' : 'no');
        if (empty($_POST['trust'])) {
            TrustedDevice::revokeAll(get_current_user_id());
        }
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=' . $result));
        exit;
    }

    /** Switch the privileged accounts lock on or off, approve or withdraw an account. */
    private static function saveLock(): void
    {
        $result = 'ok';
        $me = wp_get_current_user();
        $user = Input::postInt('user');
        if (Input::post('approve') !== '' && $user > 0 && AccountLock::active()) {
            $target = get_userdata($user);
            if ($target instanceof \WP_User) {
                AccountLock::approve($target);
            }
        } elseif (Input::post('revoke') !== '' && $user > 0 && $user !== (int) $me->ID) {
            AccountLock::revoke($user);
        } elseif (Input::post('switch') !== '') {
            if (Input::post('lock_enabled') === '') {
                AccountLock::disable();
            } elseif (AccountLock::blocker() !== '') {
                $result = 'lock_blocked';
            } elseif (!AccountLock::active()) {
                AccountLock::enable($me);
            }
        }
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=' . $result . '#draco-lock'));
        exit;
    }

    private static function formOpen(): void
    {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="lock">';
    }

    private static function renderLock(): void
    {
        echo '<div id="draco-lock"></div>';
        $on = AccountLock::active();
        Brand::card('shield', __('Accounts that can change the site', 'draco-insomnis'), __('Administrators, editors and shop managers only work once you approved them, so an account created by an attack cannot log in. If the site e-mail, its address, the default role or open registration change without you, they are all paused until you confirm from your e-mail.', 'draco-insomnis'), Brand::pill(Brand::stateLabel($on ? 'on' : 'off'), $on ? 'on' : 'off'));
        self::formOpen();
        Brand::toggle('lock_enabled', $on, __('Only approved accounts can change the site', 'draco-insomnis'), __('Switching it on approves you and keeps your e-mail for confirmations. Other privileged accounts wait until you approve them below.', 'draco-insomnis'));
        echo '<input type="hidden" name="switch" value="1"><p style="margin-top:12px">';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</p></form>';
        if ($on) {
            if (AccountLock::frozen() !== '') {
                Brand::notice('warning', __('Paused: a sensitive setting changed. The confirmation link was sent to the e-mail kept when the lock was switched on.', 'draco-insomnis'));
            }
            $owner = AccountLock::ownerEmail();
            /* translators: %s: e-mail address */
            echo '<p>' . esc_html(sprintf(__('Confirmations go to %s.', 'draco-insomnis'), $owner !== '' ? $owner : '—')) . '</p>';
            echo '<div class="draco-table-wrap"><table class="widefat striped"><thead><tr><th>' . esc_html__('Account', 'draco-insomnis') . '</th><th>' . esc_html__('Role', 'draco-insomnis') . '</th><th>' . esc_html__('State', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
            foreach (get_users(['number' => 200, 'orderby' => 'ID']) as $user) {
                if (!$user instanceof \WP_User || !AccountLock::privileged($user)) {
                    continue;
                }
                $ok = AccountLock::approved($user);
                echo '<tr><td>' . esc_html($user->user_login . ' · ' . $user->user_email) . '</td><td>' . esc_html(implode(', ', $user->roles)) . '</td><td>'
                    . esc_html($ok ? __('Approved', 'draco-insomnis') : __('Waiting for approval', 'draco-insomnis')) . '</td><td>';
                if (!($ok && $user->ID === get_current_user_id())) {
                    self::formOpen();
                    echo '<input type="hidden" name="user" value="' . (int) $user->ID . '"><button class="button" name="' . ($ok ? 'revoke' : 'approve') . '" value="1">'
                        . esc_html($ok ? __('Withdraw approval', 'draco-insomnis') : __('Approve', 'draco-insomnis')) . '</button></form>';
                }
                echo '</td></tr>';
            }
            echo '</tbody></table></div>';
        }
        echo '<p class="description">' . esc_html__('Accounts created from the command line (WP-CLI) also wait for approval. Locked out? Add define(\'DRACO_LOCK_OFF\', true); to wp-config.php, log in, fix it and remove the line.', 'draco-insomnis') . '</p>';
        Brand::cardEnd();
    }

    public static function render(): void
    {
        $on = get_option(Mfa::OPTION_ENABLED, 'no') === 'yes';
        $who = (string) get_option(Mfa::OPTION_WHO, 'admins');
        $result = sanitize_key((string) ($_GET['result'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        Brand::open(__('Two-step login', 'draco-insomnis'), __('After the right password, WordPress asks for a 6-digit code sent by e-mail. A stolen password alone is no longer enough to get in.', 'draco-insomnis'));
        if (defined('DRACO_LOCK_OFF') && DRACO_LOCK_OFF) {
            Brand::notice('warning', __('DRACO_LOCK_OFF is set in wp-config.php: accounts that can change the site are not checked. Remove that line once you are back in.', 'draco-insomnis'));
        }
        if ($result === 'lock_blocked') {
            Brand::notice('error', AccountLock::blocker());
        } elseif ($result === 'blocked') {
            Brand::notice('error', Mfa::blocker());
        } elseif ($result === 'cosign_blocked') {
            Brand::notice('error', __('Administrator co-sign was not switched on: nobody could approve your next login. Add recovery e-mails 2 and 3 first, or create a second administrator.', 'draco-insomnis'), admin_url('admin.php?page=' . Recovery::SLUG), __('Recovery e-mail →', 'draco-insomnis'));
        } elseif ($result === 'ok') {
            Brand::notice('success', __('Changes saved.', 'draco-insomnis'));
        }
        if (defined('DRACO_MFA_OFF') && DRACO_MFA_OFF) {
            Brand::notice('warning', __('DRACO_MFA_OFF is set in wp-config.php: no codes are asked for. Remove that line once you are back in.', 'draco-insomnis'));
        }
        if (defined('DRACO_COSIGN_OFF') && DRACO_COSIGN_OFF) {
            Brand::notice('warning', __('DRACO_COSIGN_OFF is set in wp-config.php: a second administrator is not required to co-sign. Remove that line once you are back in.', 'draco-insomnis'));
        }
        $cosignOn = CoSign::active();
        echo '<div class="draco-grid">';
        Brand::card('lock', __('Settings', 'draco-insomnis'), '', Brand::pill(Brand::stateLabel($on ? 'on' : 'off'), $on ? 'on' : 'off'));
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '">';
        Brand::toggle('enabled', $on, __('Ask for a code by e-mail after the password', 'draco-insomnis'));
        echo '<p class="draco-field__label" style="margin-top:10px">' . esc_html__('Who has to enter it:', 'draco-insomnis') . '</p>';
        Brand::modes('who', $who, [
            'admins' => [__('Administrators', 'draco-insomnis'), '', 'admin-network'],
            'editors' => [__('Anyone who can write or edit content', 'draco-insomnis'), '', 'edit'],
            'all' => [__('Every user', 'draco-insomnis'), '', 'groups'],
        ], 'draco-modes--stack');
        /* translators: %d: days */
        Brand::toggle('trust', get_option(Mfa::OPTION_TRUST, 'yes') === 'yes', sprintf(__('Offer "Trust this device for %d days"', 'draco-insomnis'), TrustedDevice::DAYS), __('Trusted devices skip only the verification code. A second administrator approval is still required when CoSign is enabled.', 'draco-insomnis'));
        Brand::toggle('cosign', get_option(CoSign::OPTION_ENABLED, 'no') === 'yes', __('Administrator co-sign', 'draco-insomnis'), __('A second administrator must approve this sign-in. The session belongs only to the first account.', 'draco-insomnis'));
        $approvers = CoSign::approvers(get_current_user_id());
        echo '<p class="description">' . esc_html($approvers !== []
            /* translators: %s: recovery e-mail addresses */
            ? sprintf(__('Your sign-ins can be approved by a link sent to recovery e-mails 2 and 3 (%s), or by another administrator.', 'draco-insomnis'), implode(', ', $approvers))
            : __('Add recovery e-mails 2 and 3 to approve your sign-ins by a link sent to them, without a second administrator account.', 'draco-insomnis')) . '</p>';
        if ($cosignOn) {
            echo '<p class="description">' . esc_html__('Service accounts cannot be used for co-sign approval.', 'draco-insomnis') . '</p>';
            echo '<p class="description">' . esc_html__('Trust Device is not a trusted login: passwords A and B and co-sign stay mandatory; only the e-mail code may be skipped. Prefer a quiet approval account (Admin B) with its own mailbox, unused on the public site.', 'draco-insomnis') . '</p>';
        }
        echo '<p style="margin-top:12px">';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</p></form>';
        Brand::cardEnd();

        echo '<div id="draco-passwords"></div>';
        $pwdOn = Passwords::minLength() > 0 || Passwords::checksBreaches();
        Brand::card('admin-network', __('Passwords', 'draco-insomnis'), __('Applied when someone chooses a password: profile, reset and WooCommerce sign-up. Existing passwords keep working.', 'draco-insomnis'), Brand::pill(Brand::stateLabel($pwdOn ? 'on' : 'off'), $pwdOn ? 'on' : 'off'));
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="passwords">';
        echo '<div class="draco-field"><label for="draco-pwd-min">' . esc_html__('Minimum length', 'draco-insomnis') . '</label><select id="draco-pwd-min" name="pwd_min">';
        foreach ([0, 8, 10, 12, 14, 16] as $n) {
            /* translators: %d: number of characters */
            $label = $n === 0 ? __('No minimum (WordPress default)', 'draco-insomnis') : sprintf(__('%d characters', 'draco-insomnis'), $n) . ($n === 12 ? ' · ' . __('recommended', 'draco-insomnis') : '');
            echo '<option value="' . (int) $n . '"' . selected(Passwords::minLength(), $n, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select></div>';
        Brand::toggle('pwd_breached', Passwords::checksBreaches(), __('Refuse passwords that appear in known data breaches, and warn people who log in with one', 'draco-insomnis'), __('Asks Have I Been Pwned with only the first 5 characters of the password\'s SHA-1: the password never leaves your site. If the service does not answer in 3 seconds, the password is accepted.', 'draco-insomnis'));
        echo '<p style="margin-top:12px">';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</p></form>';
        Brand::cardEnd();

        self::renderLock();

        Brand::card('lightbulb', __('Good to know', 'draco-insomnis'), '', '', 'info');
        echo '<ul class="draco-list">';
        foreach ([
            ['email-alt', __('It can only be switched on with Site mail (SMTP) working, and it switches itself off if that connection is forgotten: a code that never arrives would lock you out.', 'draco-insomnis')],
            ['clock', __('The code is only sent after the right password. It expires in 10 minutes and allows 5 tries; repeated failures block the address for 15 minutes.', 'draco-insomnis')],
            ['update', __('Changing the password or the e-mail of an account makes all its trusted devices ask for a code again.', 'draco-insomnis')],
            ['admin-appearance', __('Login boxes that work without reloading the page (some themes) cannot show the code step: those users are asked to log in from the normal login page.', 'draco-insomnis')],
            ['sos', __('If you are ever locked out, add define(\'DRACO_MFA_OFF\', true); to wp-config.php, log in, fix the problem and remove the line. Only someone with access to the server can do this, unlike a "skip" button.', 'draco-insomnis')],
        ] as [$icon, $item]) {
            echo '<li><span class="dashicons dashicons-' . esc_attr($icon) . '" aria-hidden="true"></span>' . esc_html($item) . '</li>';
        }
        echo '</ul>';
        Brand::cardEnd();
        echo '</div>';
        Brand::close();
    }
}
