<?php

declare(strict_types=1);

namespace DracoInsomnis\Mail;

use DracoInsomnis\Input;
use DracoInsomnis\Admin\Brand;

defined('ABSPATH') || exit;

/** The owner's screen: connect a mailbox, prove it works, switch it on, see what left. */
final class Admin
{
    public const SLUG = 'draco-insomnis-mail';
    private const ACTION = 'draco_mail_admin';
    private const ERROR_KEY = 'draco_mail_error_';
    private const DMARC_KEY = 'draco_mail_dmarc';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu'], 20);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
    }

    public static function menu(): void
    {
        $title = __('Site mail (SMTP)', 'draco-insomnis');
        add_submenu_page(Brand::PARENT, $title, $title, 'manage_options', self::SLUG, [self::class, 'render']);
    }

    /**
     * host => [name, encryption, port, user help, password help, group]
     *
     * @return array<string, array{string, string, int, string, string, string}>
     */
    private static function providers(): array
    {
        $box = __('The full address of the mailbox, with @ and domain. Not your WordPress username.', 'draco-insomnis');
        $pass = __('The password of that mailbox, not the one for WordPress or your hosting. If you do not remember it, change it in your hosting or domain panel, in the e-mail section.', 'draco-insomnis');
        $app = __('An app password, created in the security settings of your account. Not your normal password.', 'draco-insomnis');
        $full = __('Your full address.', 'draco-insomnis');

        return [
            'smtp.hostinger.com' => ['Hostinger', 'ssl', 465, $box, $pass, 'domain'],
            'smtp.ionos.es' => ['IONOS', 'ssl', 465, $box, $pass, 'domain'],
            'ssl0.ovh.net' => ['OVHcloud', 'ssl', 465, $box, $pass, 'domain'],
            'smtp.serviciodecorreo.es' => ['Arsys', 'ssl', 465, $box, $pass, 'domain'],
            'smtpout.secureserver.net' => ['GoDaddy', 'ssl', 465, $box, $pass, 'domain'],
            'smtp.zoho.eu' => ['Zoho Mail', 'ssl', 465, $box, __('The mailbox password, or an app password if you use two-step verification.', 'draco-insomnis'), 'domain'],
            'smtp.office365.com' => ['Microsoft 365', 'tls', 587, $box, __('The mailbox password or an app password. SMTP sending must be allowed in Microsoft 365.', 'draco-insomnis'), 'domain'],
            'smtp.gmail.com' => ['Google Workspace / Gmail', 'ssl', 465, __('The full address of the Google account.', 'draco-insomnis'), $app, 'domain'],
            'smtp-relay.brevo.com' => ['Brevo', 'tls', 587, __('The SMTP login shown in your Brevo account.', 'draco-insomnis'), __('The Brevo SMTP key, not your account password.', 'draco-insomnis'), 'relay'],
            'smtp.mailgun.org' => ['Mailgun', 'tls', 587, __('The SMTP user of your domain in Mailgun.', 'draco-insomnis'), __('The SMTP password of that user.', 'draco-insomnis'), 'relay'],
            'smtp.sendgrid.net' => ['SendGrid', 'tls', 587, __('Type literally: apikey', 'draco-insomnis'), __('Your SendGrid API key.', 'draco-insomnis'), 'relay'],
            'smtp.postmarkapp.com' => ['Postmark', 'tls', 587, __('The Postmark Server API Token.', 'draco-insomnis'), __('The same Server API Token.', 'draco-insomnis'), 'relay'],
            'in-v3.mailjet.com' => ['Mailjet', 'tls', 587, __('Your Mailjet API key.', 'draco-insomnis'), __('Your Mailjet secret key.', 'draco-insomnis'), 'relay'],
            'email-smtp.eu-west-1.amazonaws.com' => ['Amazon SES (Ireland)', 'tls', 587, __('The SMTP user created in Amazon SES.', 'draco-insomnis'), __('The Amazon SES SMTP password, not your AWS password.', 'draco-insomnis'), 'relay'], // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- an SMTP host name; nothing is loaded from it.
            'smtp-mail.outlook.com' => ['Outlook.com / Hotmail', 'tls', 587, $full, $app, 'personal'],
            'smtp.mail.yahoo.com' => ['Yahoo Mail', 'ssl', 465, $full, $app, 'personal'],
            'smtp.mail.me.com' => ['iCloud Mail', 'tls', 587, $full, $app, 'personal'],
        ];
    }

    public static function save(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'draco-insomnis'), 403);
        }
        check_admin_referer(self::ACTION);
        $do = sanitize_key((string) ($_POST['do'] ?? ''));
        $result = 'ok';
        $to = '';
        if ($do === 'settings') {
            $result = Settings::save(wp_unslash($_POST), (string) wp_unslash($_POST['password'] ?? '')); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- sanitized field by field in Settings::save(); the password is stored encrypted as typed
            $result = $result === 'ok' ? 'saved' : $result;
        } elseif ($do === 'test') {
            $to = sanitize_email(wp_unslash((string) ($_POST['to'] ?? '')));
            if (!is_email($to) || !Settings::complete()) {
                $result = 'invalid';
            } else {
                $test = Transport::test($to);
                $result = $test['ok'] ? 'test_ok' : 'test_bad';
                set_transient(self::ERROR_KEY . get_current_user_id(), $test['error'], 300);
            }
        } elseif ($do === 'enable') {
            $result = Transport::otherSender() !== '' ? 'other' : (Settings::setEnabled(true) ? 'enabled' : 'untested');
        } elseif ($do === 'disable') {
            Settings::forget();
            // Modules that need mail to reach people (login codes) switch themselves off here.
            do_action('draco_insomnis_mail_forgotten');
            $result = 'forgotten';
        }
        wp_safe_redirect(add_query_arg(['page' => self::SLUG, 'result' => $result, 'to' => rawurlencode($to)], admin_url('admin.php')));
        exit;
    }

    private static function open(string $do): void
    {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="' . esc_attr($do) . '">';
    }

    public static function render(): void
    {
        $s = Settings::get();
        $active = Settings::active();
        $other = Transport::otherSender();
        $domain = self::siteDomain();

        echo '<div class="wrap">';
        Brand::header(__('Site mail (SMTP)', 'draco-insomnis'));
        echo '<p>' . esc_html__('Sends the mail of this site through a real mailbox with its password, instead of the server\'s mail() function. Without it, many messages are silently rejected: login codes, forms and orders.', 'draco-insomnis') . '</p>';
        self::notice(sanitize_key((string) ($_GET['result'] ?? ''))); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only

        if ($s['pass'] !== '' && Settings::password() === '') {
            echo '<div class="notice notice-error"><p>' . esc_html__('The saved password can no longer be read (the site\'s security keys changed). Type it again and repeat the test.', 'draco-insomnis') . '</p></div>';
        }
        if ($other !== '') {
            /* translators: %s: plugin name */
            echo '<div class="notice notice-warning"><p>' . esc_html(sprintf(__('%s is sending the mail of this site. Turn it off before testing or switching on this module.', 'draco-insomnis'), $other)) . '</p></div>';
        }
        $policy = self::dmarcPolicy();
        if (!$active && $other === '' && in_array($policy, ['reject', 'quarantine'], true)) {
            /* translators: %s: DMARC policy (reject or quarantine) */
            echo '<div class="notice notice-error"><p>' . esc_html(sprintf(__('The domain has DMARC "%s" and this site sends with PHP mail(): messages, including login codes, may never arrive even though the site says "sent".', 'draco-insomnis'), $policy)) . '</p></div>';
        }
        $sender = strtolower(Settings::fromAddress());
        if (Settings::complete() && !str_ends_with($sender, '@' . $domain)) {
            /* translators: 1: sender address, 2: site domain */
            echo '<div class="notice notice-error"><p>' . esc_html(sprintf(__('The sender %1$s is not from the domain of this site. Use an @%2$s address or messages may be rejected.', 'draco-insomnis'), $sender, $domain)) . '</p></div>';
        }

        /* translators: %s: sender address */
        $state = $active ? sprintf(__('Sending through SMTP as %s', 'draco-insomnis'), Settings::fromAddress())
            /* translators: %s: plugin name */
            : ($other !== '' ? sprintf(__('Sending through %s', 'draco-insomnis'), $other) : __('Sending with PHP mail()', 'draco-insomnis'));
        echo '<h2>' . esc_html__('Status', 'draco-insomnis') . '</h2><p><strong>' . esc_html($state) . '</strong></p>';

        echo '<h2>' . esc_html__('1. Connection', 'draco-insomnis') . '</h2>';
        self::open('settings');
        echo '<table class="form-table" role="presentation">';
        self::fields($s, $domain);
        echo '</table>';
        submit_button(__('Save connection', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';

        echo '<h2>' . esc_html__('2. Test', 'draco-insomnis') . '</h2>';
        if (!Settings::complete()) {
            echo '<p>' . esc_html__('Save the connection to send tests.', 'draco-insomnis') . '</p>';
        } else {
            echo '<p>' . esc_html__('Send a test and check that it arrived, also in spam. "Accepted" only means the server took it.', 'draco-insomnis') . '</p>';
            self::open('test');
            $me = (string) wp_get_current_user()->user_email;
            echo '<p><label>' . esc_html__('Send a test to', 'draco-insomnis') . ' <input type="email" name="to" class="regular-text" required value="' . esc_attr($me) . '"></label> ';
            submit_button(__('Send test', 'draco-insomnis'), 'secondary', 'submit', false);
            echo '</p></form>';
        }

        echo '<h2>' . esc_html__('3. Switch on', 'draco-insomnis') . '</h2><p>' . esc_html__('Until this step, the site keeps sending as before.', 'draco-insomnis') . '</p>';
        if ($active) {
            self::open('disable');
            echo '<p>' . esc_html__('This forgets the connection above (server, user, password and sender) and goes back to PHP mail(). Modules that send login codes are switched off, because the codes might not arrive.', 'draco-insomnis') . '</p>';
            submit_button(__('Go back to PHP mail() and forget the connection', 'draco-insomnis'), 'secondary', 'submit', false);
            echo '</form>';
        } elseif (Settings::tested()) {
            self::open('enable');
            submit_button(__('Switch on SMTP for this site', 'draco-insomnis'), 'primary', 'submit', false);
            echo '</form>';
        } else {
            echo '<p>' . esc_html__('It can be switched on once a test succeeds.', 'draco-insomnis') . '</p>';
        }

        self::logTable();
        self::script($domain);
        echo '</div>';
    }

    /** @param array<string, mixed> $s */
    private static function fields(array $s, string $domain): void
    {
        $providers = self::providers();
        $example = 'info@' . $domain;
        $known = $providers[(string) $s['host']] ?? null;
        $userHelp = __('Usually the full address of the mailbox. Not your WordPress username.', 'draco-insomnis');
        $passHelp = __('The password of that mailbox, not the one for WordPress or your hosting.', 'draco-insomnis');
        $row = static function (string $id, string $label, string $control, string $help): void {
            echo '<tr><th><label for="' . esc_attr($id) . '">' . esc_html($label) . '</label></th><td>' . $control // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built with esc_attr() below
                . '<p class="description" id="' . esc_attr($id) . '-help">' . esc_html($help) . '</p></td></tr>';
        };

        $groups = ['domain' => __('Mail on your own domain (recommended)', 'draco-insomnis'), 'relay' => __('Sending services', 'draco-insomnis'), 'personal' => __('Personal mail (not recommended)', 'draco-insomnis')];
        $options = '<option value="">' . esc_html__('Choose your provider…', 'draco-insomnis') . '</option>';
        foreach ($groups as $group => $label) {
            $options .= '<optgroup label="' . esc_attr($label) . '">';
            foreach ($providers as $host => $p) {
                if ($p[5] === $group) {
                    $options .= '<option value="' . esc_attr($host) . '" data-secure="' . esc_attr($p[1]) . '" data-port="' . (int) $p[2]
                        . '" data-user="' . esc_attr($p[3]) . '" data-pass="' . esc_attr($p[4]) . '"' . selected((string) $s['host'], $host, false) . '>' . esc_html($p[0]) . '</option>';
                }
            }
            $options .= '</optgroup>';
        }
        /* translators: 1: site domain, 2: site domain */
        $row('draco-mail-provider', __('Where is your mailbox?', 'draco-insomnis'), '<select id="draco-mail-provider">' . $options . '</select>', sprintf(__('Preferably a mailbox on the domain of this site, @%1$s. This fills in server, encryption and port. If your provider is not listed, the server is usually mail.%2$s: type it by hand and confirm it with them.', 'draco-insomnis'), $domain, $domain));
        $row('draco-mail-host', __('Outgoing server (SMTP)', 'draco-insomnis'), '<input id="draco-mail-host" name="host" class="regular-text" required placeholder="smtp.example.com" value="' . esc_attr((string) $s['host']) . '">', __('The address of the server that sends the mail. Your provider gives it to you.', 'draco-insomnis'));
        $row('draco-mail-secure', __('Encryption and port', 'draco-insomnis'), '<select id="draco-mail-secure" name="secure"><option value="ssl"' . selected($s['secure'], 'ssl', false) . '>SSL (465)</option><option value="tls"' . selected($s['secure'], 'tls', false) . '>STARTTLS (587)</option></select> '
            . '<label>' . esc_html__('Port', 'draco-insomnis') . ' <input id="draco-mail-port" type="number" name="port" class="small-text" min="1" max="65535" value="' . (int) $s['port'] . '"></label>', __('Use what your provider says. If it does not connect, try the other option.', 'draco-insomnis'));
        $row('draco-mail-user', __('Username', 'draco-insomnis'), '<input id="draco-mail-user" name="user" class="regular-text" autocomplete="off" required placeholder="' . esc_attr($example) . '" value="' . esc_attr((string) $s['user']) . '">', $known[3] ?? $userHelp);
        $row('draco-mail-pass', __('Password', 'draco-insomnis'), '<input id="draco-mail-pass" type="password" name="password" class="regular-text" autocomplete="new-password" placeholder="' . esc_attr($s['pass'] !== '' ? __('Saved. Leave empty to keep it', 'draco-insomnis') : '') . '">', ($known[4] ?? $passHelp) . ' ' . __('It is stored encrypted.', 'draco-insomnis'));
        $row('draco-mail-from', __('Sender address (optional)', 'draco-insomnis'), '<input id="draco-mail-from" type="email" name="from" class="regular-text" placeholder="' . esc_attr($example) . '" value="' . esc_attr((string) $s['from']) . '">', __('The address people see. Empty uses the username above, which is normal. If you fill it in, it must be a mailbox or authorised alias on the domain of this site.', 'draco-insomnis'));
        echo '<tr><th></th><td><div id="draco-mail-domain-warning" class="notice notice-error inline" style="margin:0" hidden><p></p></div></td></tr>';
        $row('draco-mail-name', __('Sender name (optional)', 'draco-insomnis'), '<input id="draco-mail-name" name="from_name" class="regular-text" placeholder="' . esc_attr((string) get_bloginfo('name')) . '" value="' . esc_attr((string) $s['from_name']) . '">', __('The name people see. Empty keeps whatever each plugin sets, usually "WordPress".', 'draco-insomnis'));
        $row('draco-mail-extra', __('Addresses for security alerts', 'draco-insomnis'), '<textarea id="draco-mail-extra" name="security_recipients" rows="3" class="large-text" placeholder="you@gmail.com">' . esc_textarea(implode("\n", Settings::securityRecipients())) . '</textarea>',
            /* translators: %s: site domain */
            sprintf(__('One per line. Besides the administrator, they receive the WordPress link to get in and fix the site if a plugin or theme breaks it (it gives access to the dashboard: trusted mailboxes only), and password-change alerts. Put at least one that is not @%s: if this domain fails, alerts still arrive.', 'draco-insomnis'), $domain));
    }

    private static function script(string $domain): void
    {
        $text = wp_json_encode([
            'domain' => $domain,
            'notAddress' => __('The username is not an e-mail address: type an address on this domain in "Sender address".', 'draco-insomnis'),
            /* translators: %s: site domain */
            'otherDomain' => sprintf(__('This sender is not from the domain of this site. Use an @%s address or messages may be rejected.', 'draco-insomnis'), $domain),
        ]);
        ?>
        <script>
        (function () {
            var t = <?php echo $text; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- wp_json_encode ?>;
            var $ = function (id) { return document.getElementById(id); };
            var provider = $('draco-mail-provider'), secure = $('draco-mail-secure'), port = $('draco-mail-port');
            if (!provider) { return; }
            var userHelp = $('draco-mail-user-help').textContent, passHelp = $('draco-mail-pass-help').textContent;
            provider.addEventListener('change', function () {
                var o = provider.options[provider.selectedIndex];
                $('draco-mail-user-help').textContent = o.dataset.user || userHelp;
                $('draco-mail-pass-help').textContent = o.dataset.pass || passHelp;
                if (!provider.value) { return; }
                $('draco-mail-host').value = provider.value;
                secure.value = o.dataset.secure;
                port.value = o.dataset.port;
            });
            secure.addEventListener('change', function () { port.value = secure.value === 'ssl' ? 465 : 587; });
            var box = $('draco-mail-domain-warning');
            var check = function () {
                var sender = ($('draco-mail-from').value.trim() || $('draco-mail-user').value.trim()).toLowerCase();
                var msg = '';
                if (sender !== '' && sender.indexOf('@') < 0) { msg = t.notAddress; }
                else if (sender !== '' && sender.slice(-(t.domain.length + 1)) !== '@' + t.domain) { msg = t.otherDomain; }
                box.hidden = msg === '';
                box.firstChild.textContent = msg;
            };
            $('draco-mail-user').addEventListener('input', check);
            $('draco-mail-from').addEventListener('input', check);
            check();
        })();
        </script>
        <?php
    }

    private static function notice(string $result): void
    {
        $to = sanitize_email(Input::get('to'));
        $messages = [
            'saved' => ['success', __('Connection saved. Now send a test.', 'draco-insomnis')],
            'enabled' => ['success', __('SMTP switched on. The mail of this site now leaves through your mailbox.', 'draco-insomnis')],
            'forgotten' => ['warning', __('Connection forgotten. The site sends with PHP mail() again. The alert addresses were kept.', 'draco-insomnis')],
            /* translators: %s: e-mail address */
            'test_ok' => ['success', sprintf(__('Test sent to %s. The server accepted it: check that it arrived, also in spam.', 'draco-insomnis'), $to)],
            'invalid' => ['error', __('Missing data. Check server, username, password, sender and recipient.', 'draco-insomnis')],
            'cipher' => ['error', __('Not saved: the password could not be encrypted (OpenSSL is missing on the server).', 'draco-insomnis')],
            'untested' => ['error', __('A successful test with this connection is needed first.', 'draco-insomnis')],
            'other' => ['error', __('Another plugin is sending the mail of this site. Turn it off first.', 'draco-insomnis')],
        ];
        if ($result === 'test_bad') {
            $key = self::ERROR_KEY . get_current_user_id();
            /* translators: 1: e-mail address, 2: error message */
            $messages[$result] = ['error', sprintf(__('The test to %1$s failed: %2$s', 'draco-insomnis'), $to, (string) get_transient($key))];
            delete_transient($key);
        }
        if (isset($messages[$result])) {
            echo '<div class="notice notice-' . esc_attr($messages[$result][0]) . '"><p>' . esc_html($messages[$result][1]) . '</p></div>';
        }
    }

    private static function logTable(): void
    {
        $labels = ['smtp' => 'SMTP', 'php' => 'PHP mail()', 'other' => __('Another plugin', 'draco-insomnis')];
        echo '<h2>' . esc_html__('Recent messages', 'draco-insomnis') . '</h2><p>' . esc_html__('"Accepted" means the server took it, not that it reached the inbox. With PHP mail(), not even that. Message bodies are never stored.', 'draco-insomnis') . '</p>';
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>' . esc_html__('Via', 'draco-insomnis') . '</th><th>' . esc_html__('To', 'draco-insomnis') . '</th><th>' . esc_html__('Subject', 'draco-insomnis') . '</th><th>' . esc_html__('Result', 'draco-insomnis') . '</th></tr></thead><tbody>';
        $rows = Log::rows();
        foreach ($rows as $row) {
            /* translators: %s: error message */
            $state = !empty($row['ok']) ? __('Accepted', 'draco-insomnis') : sprintf(__('Error: %s', 'draco-insomnis'), (string) ($row['error'] ?? ''));
            echo '<tr><td>' . esc_html(gmdate('Y-m-d H:i:s', (int) ($row['at'] ?? 0))) . '</td><td>' . esc_html($labels[(string) ($row['transport'] ?? '')] ?? '') . '</td><td>'
                . esc_html((string) ($row['to'] ?? '')) . '</td><td>' . esc_html((string) ($row['subject'] ?? '')) . '</td><td>' . esc_html($state) . '</td></tr>';
        }
        if ($rows === []) {
            echo '<tr><td colspan="5">' . esc_html__('Nothing yet.', 'draco-insomnis') . '</td></tr>';
        }
        echo '</tbody></table>';
    }

    private static function siteDomain(): string
    {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);

        return (string) preg_replace('/^www\./', '', strtolower(is_string($host) ? $host : 'example.com'));
    }

    private static function dmarcPolicy(): string
    {
        $cached = get_transient(self::DMARC_KEY);
        if (is_string($cached)) {
            return $cached;
        }
        $policy = '';
        if (function_exists('dns_get_record')) {
            $records = @dns_get_record('_dmarc.' . self::siteDomain(), DNS_TXT); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- a missing record is normal
            foreach (is_array($records) ? $records : [] as $record) {
                if (preg_match('/\bp=(none|quarantine|reject)\b/i', (string) ($record['txt'] ?? ''), $m) === 1) {
                    $policy = strtolower($m[1]);
                }
            }
        }
        set_transient(self::DMARC_KEY, $policy, 12 * HOUR_IN_SECONDS);

        return $policy;
    }
}
