<?php

declare(strict_types=1);

namespace DracoInsomnis\Mail;

use DracoInsomnis\Input;
use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Shield\Store as Blocks;

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
        } elseif ($do === 'purge_log') {
            Log::clear();
            $result = 'purged';
        } elseif ($do === 'block') {
            $email = sanitize_email(wp_unslash((string) ($_POST['email'] ?? '')));
            $days = Input::postInt('days', 30);
            /* translators: %s: e-mail address */
            $reason = sprintf(__('From recent messages (%s)', 'draco-insomnis'), $email);
            $result = ($email !== '' && Blocks::block('email', $email, $days, $reason)) ? 'blocked' : 'block_refused';
            $to = $email;
        } elseif ($do === 'unblock') {
            Blocks::unblock(Input::postInt('id'));
            $result = 'unblocked';
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

        Brand::open(__('Site mail (SMTP)', 'draco-insomnis'), __('Sends the mail of this site through a real mailbox with its password, instead of the server\'s mail() function. Without it, many messages are silently rejected: login codes, forms and orders.', 'draco-insomnis'));
        self::notice(sanitize_key((string) ($_GET['result'] ?? ''))); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only

        if ($s['pass'] !== '' && Settings::password() === '') {
            Brand::notice('error', __('The saved password can no longer be read (the site\'s security keys changed). Type it again and repeat the test.', 'draco-insomnis'));
        }
        if ($other !== '') {
            /* translators: %s: plugin name */
            Brand::notice('warning', sprintf(__('%s is sending the mail of this site. Turn it off before testing or switching on this module.', 'draco-insomnis'), $other));
        }
        $policy = self::dmarcPolicy();
        if (!$active && $other === '' && in_array($policy, ['reject', 'quarantine'], true)) {
            /* translators: %s: DMARC policy (reject or quarantine) */
            Brand::notice('error', sprintf(__('The domain has DMARC "%s" and this site sends with PHP mail(): messages, including login codes, may never arrive even though the site says "sent".', 'draco-insomnis'), $policy));
        }
        $sender = strtolower(Settings::fromAddress());
        if (Settings::complete() && !str_ends_with($sender, '@' . $domain)) {
            /* translators: 1: sender address, 2: site domain */
            Brand::notice('error', sprintf(__('The sender %1$s is not from the domain of this site. Use an @%2$s address or messages may be rejected.', 'draco-insomnis'), $sender, $domain));
        }

        /* translators: %s: sender address */
        $state = $active ? sprintf(__('Sending through SMTP as %s', 'draco-insomnis'), Settings::fromAddress())
            /* translators: %s: plugin name */
            : ($other !== '' ? sprintf(__('Sending through %s', 'draco-insomnis'), $other) : __('Sending with PHP mail()', 'draco-insomnis'));
        $pill = $active ? Brand::pill(__('SMTP', 'draco-insomnis'), 'on') : ($other !== '' ? Brand::pill(__('Another plugin', 'draco-insomnis'), 'info') : Brand::pill('PHP mail()', 'warn'));
        Brand::card($active ? 'yes-alt' : 'email-alt', __('Status', 'draco-insomnis'), $state, $pill, $active ? '' : 'warn');
        $done = static fn (bool $ok, int $n): string => '<span class="draco-step' . ($ok ? ' is-done' : '') . '">' . ($ok ? '✓' : (string) $n) . '</span>';
        echo '<p style="margin:0">' . $done(Settings::complete(), 1) . esc_html__('1. Connection', 'draco-insomnis') . ' &nbsp; ' . $done(Settings::tested(), 2) . esc_html__('2. Test', 'draco-insomnis') . ' &nbsp; ' . $done($active, 3) . esc_html__('3. Switch on', 'draco-insomnis') . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $done builds fixed markup
        Brand::cardEnd();

        Brand::card('admin-network', __('1. Connection', 'draco-insomnis'), __('Choose your provider and the server, encryption and port fill themselves in.', 'draco-insomnis'), Settings::complete() ? Brand::pill(__('Saved', 'draco-insomnis'), 'on') : '');
        self::open('settings');
        echo '<table class="form-table" role="presentation">';
        self::fields($s, $domain);
        echo '</table>';
        submit_button(__('Save connection', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';
        Brand::cardEnd();

        echo '<div class="draco-grid">';
        Brand::card('controls-play', __('2. Test', 'draco-insomnis'), '', Settings::tested() ? Brand::pill(__('Passed', 'draco-insomnis'), 'on') : '');
        if (!Settings::complete()) {
            echo '<p>' . esc_html__('Save the connection to send tests.', 'draco-insomnis') . '</p>';
        } else {
            echo '<p>' . esc_html__('Send a test and check that it arrived, also in spam. "Accepted" only means the server took it.', 'draco-insomnis') . '</p>';
            self::open('test');
            $me = (string) wp_get_current_user()->user_email;
            echo '<div class="draco-field"><label for="draco-mail-to">' . esc_html__('Send a test to', 'draco-insomnis') . '</label><input id="draco-mail-to" type="email" name="to" class="large-text" required value="' . esc_attr($me) . '"></div>';
            submit_button(__('Send test', 'draco-insomnis'), 'secondary', 'submit', false);
            echo '</form>';
        }
        Brand::cardEnd();

        Brand::card('yes-alt', __('3. Switch on', 'draco-insomnis'), __('Until this step, the site keeps sending as before.', 'draco-insomnis'), Brand::pill(Brand::stateLabel($active ? 'on' : 'off'), $active ? 'on' : 'off'));
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
        Brand::cardEnd();
        echo '</div>';

        self::logTable();
        \DracoInsomnis\Shield\Admin::renderSharedBlocksCard(self::ACTION, self::ACTION, ['email']);
        self::script($domain);
        Brand::close();
    }

    /** @param array<string, mixed> $s */
    private static function fields(array $s, string $domain): void
    {
        $example = 'info@' . $domain;
        $known = Providers::byHost((string) $s['host']);
        $userHelp = __('Usually the full address of the mailbox. Not your WordPress username.', 'draco-insomnis');
        $passHelp = __('The password of that mailbox, not the one for WordPress or your hosting.', 'draco-insomnis');
        $row = static function (string $id, string $label, string $control, string $help): void {
            echo '<tr><th><label for="' . esc_attr($id) . '">' . esc_html($label) . '</label></th><td>' . $control // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built with esc_attr() below
                . '<p class="description" id="' . esc_attr($id) . '-help">' . esc_html($help) . '</p></td></tr>';
        };

        $regions = Providers::regions();
        $regionOpts = '<option value="">' . esc_html__('Country or Global…', 'draco-insomnis') . '</option>';
        foreach ($regions as $code => $label) {
            $sel = $known && $known['region'] === $code ? ' selected' : '';
            $regionOpts .= '<option value="' . esc_attr($code) . '"' . $sel . '>' . esc_html($label) . '</option>';
        }

        $catalog = [];
        foreach (Providers::all() as $p) {
            $catalog[] = [
                'id' => $p['id'],
                'label' => $p['label'],
                'region' => $p['region'],
                'host' => Providers::resolveHost($p, $domain),
                'host_kind' => $p['host_kind'],
                'host_pattern' => $p['host'],
                'secure' => $p['secure'],
                'port' => $p['port'],
                'user' => $p['user'],
                'pass' => $p['pass'],
                'group' => $p['group'],
                'trust' => $p['trust'],
                'note' => $p['note'],
                'alt' => $p['alt'] ?? '',
            ];
        }
        $json = wp_json_encode($catalog, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        $providerSelect = '<select id="draco-mail-provider" disabled><option value="">' . esc_html__('Choose your provider…', 'draco-insomnis') . '</option></select>';
        $cascade = '<div class="draco-mail-cascade" data-domain="' . esc_attr($domain) . '">'
            . '<div class="draco-mail-cascade__picks">'
            . '<label class="draco-mail-cascade__label" for="draco-mail-region">' . esc_html__('Country or Global', 'draco-insomnis') . '</label>'
            . '<select id="draco-mail-region">' . $regionOpts . '</select>'
            . '<label class="draco-mail-cascade__label" for="draco-mail-provider">' . esc_html__('Provider', 'draco-insomnis') . '</label>'
            . $providerSelect
            . '</div>'
            . '<aside id="draco-mail-note" class="draco-mail-note" hidden>'
            . '<strong id="draco-mail-note-title"></strong>'
            . '<dl id="draco-mail-note-params" class="draco-mail-note__params"></dl>'
            . '<div id="draco-mail-note-body" class="draco-mail-note__body"></div>'
            . '</aside>'
            . '</div>'
            . '<script type="application/json" id="draco-mail-providers-json">' . $json . '</script>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON_HEX_* encoded

        /* translators: 1: site domain, 2: site domain */
        $row('draco-mail-region', __('Where is your mailbox?', 'draco-insomnis'), $cascade, sprintf(__('Preferably a mailbox on the domain of this site, @%1$s. Country → provider fills SMTP server, encryption and port automatically (shown in the note and editable below). If yours is missing, type the server by hand (often mail.%2$s) and confirm it with them.', 'draco-insomnis'), $domain, $domain));
        $row('draco-mail-host', __('Outgoing server (SMTP)', 'draco-insomnis'), '<input id="draco-mail-host" type="text" name="host" class="regular-text" required placeholder="smtp.example.com" value="' . esc_attr((string) $s['host']) . '">', __('Filled when you choose a provider. You can still edit it. Your provider gives it to you.', 'draco-insomnis'));
        $row('draco-mail-secure', __('Encryption and port', 'draco-insomnis'), '<select id="draco-mail-secure" name="secure"><option value="ssl"' . selected($s['secure'], 'ssl', false) . '>SSL (465)</option><option value="tls"' . selected($s['secure'], 'tls', false) . '>STARTTLS (587)</option></select> '
            . '<label>' . esc_html__('Port', 'draco-insomnis') . ' <input id="draco-mail-port" type="number" name="port" class="small-text" min="1" max="65535" value="' . (int) $s['port'] . '"></label>', __('Filled with the provider preset. Some providers use other values — check the note and change them here if needed.', 'draco-insomnis'));
        $row('draco-mail-user', __('Username', 'draco-insomnis'), '<input id="draco-mail-user" type="text" name="user" class="regular-text" autocomplete="off" required placeholder="' . esc_attr($example) . '" value="' . esc_attr((string) $s['user']) . '">', $known['user'] ?? $userHelp);
        $row('draco-mail-pass', __('Password', 'draco-insomnis'), '<input id="draco-mail-pass" type="password" name="password" class="regular-text" autocomplete="new-password" placeholder="' . esc_attr($s['pass'] !== '' ? __('Saved. Leave empty to keep it', 'draco-insomnis') : '') . '">', ($known['pass'] ?? $passHelp) . ' ' . __('It is stored encrypted.', 'draco-insomnis'));
        $row('draco-mail-from', __('Sender address (optional)', 'draco-insomnis'), '<input id="draco-mail-from" type="email" name="from" class="regular-text" placeholder="' . esc_attr($example) . '" value="' . esc_attr((string) $s['from']) . '">', __('The address people see. Empty uses the username above, which is normal. If you fill it in, it must be a mailbox or authorised alias on the domain of this site.', 'draco-insomnis'));
        echo '<tr><th></th><td><div id="draco-mail-domain-warning" class="notice notice-error inline" style="margin:0" hidden><p></p></div></td></tr>';
        $row('draco-mail-name', __('Sender name (optional)', 'draco-insomnis'), '<input id="draco-mail-name" type="text" name="from_name" class="regular-text" placeholder="' . esc_attr((string) get_bloginfo('name')) . '" value="' . esc_attr((string) $s['from_name']) . '">', __('The name people see. Empty keeps whatever each plugin sets, usually "WordPress".', 'draco-insomnis'));
        $row('draco-mail-extra', __('Addresses for security alerts', 'draco-insomnis'), '<textarea id="draco-mail-extra" name="security_recipients" rows="3" class="large-text" placeholder="you@gmail.com">' . esc_textarea(implode("\n", Settings::securityRecipients())) . '</textarea>',
            /* translators: %s: site domain */
            sprintf(__('One per line. Besides the administrator, they receive the WordPress link to get in and fix the site if a plugin or theme breaks it (it gives access to the dashboard: trusted mailboxes only), and password-change alerts. Put at least one that is not @%s: if this domain fails, alerts still arrive.', 'draco-insomnis'), $domain));
    }

    private static function script(string $domain): void
    {
        $text = wp_json_encode([
            'domain' => $domain,
            'choose' => __('Choose your provider…', 'draco-insomnis'),
            'notAddress' => __('The username is not an e-mail address: type an address on this domain in "Sender address".', 'draco-insomnis'),
            /* translators: %s: site domain */
            'otherDomain' => sprintf(__('This sender is not from the domain of this site. Use an @%s address or messages may be rejected.', 'draco-insomnis'), $domain),
            'noteTemplate' => __('Template host', 'draco-insomnis'),
            'noteWarn' => __('Check before you trust this preset', 'draco-insomnis'),
            'noteOk' => __('Connection preset', 'draco-insomnis'),
            'smtp' => __('Outgoing server (SMTP)', 'draco-insomnis'),
            'encryption' => __('Encryption', 'draco-insomnis'),
            'port' => __('Port', 'draco-insomnis'),
            'askHost' => __('Fill this from your hosting panel (assigned per account).', 'draco-insomnis'),
            'fillsFields' => __('Choosing a provider fills SMTP server, encryption and port below automatically. You can still edit them.', 'draco-insomnis'),
            'ssl' => 'SSL/TLS',
            'tls' => 'STARTTLS',
        ]);
        $js = '(function () {' . "\n" . '            var t = ' . $text . ';' . "\n" . <<<'JS'
            var $ = function (id) { return document.getElementById(id); };
            var region = $('draco-mail-region'), provider = $('draco-mail-provider');
            var secure = $('draco-mail-secure'), port = $('draco-mail-port');
            var note = $('draco-mail-note'), noteTitle = $('draco-mail-note-title');
            var noteBody = $('draco-mail-note-body'), noteParams = $('draco-mail-note-params');
            var raw = $('draco-mail-providers-json');
            if (!region || !provider || !raw) { return; }
            var catalog = [];
            try { catalog = JSON.parse(raw.textContent || '[]'); } catch (e) { catalog = []; }
            var userHelp = $('draco-mail-user-help').textContent, passHelp = $('draco-mail-pass-help').textContent;
            var byId = {};
            catalog.forEach(function (p) { byId[p.id] = p; });

            function fillProviders(code, selectedId) {
                provider.innerHTML = '';
                var ph = document.createElement('option');
                ph.value = '';
                ph.textContent = t.choose;
                provider.appendChild(ph);
                if (!code) {
                    provider.disabled = true;
                    hideNote();
                    return;
                }
                provider.disabled = false;
                catalog.filter(function (p) { return p.region === code; }).forEach(function (p) {
                    var o = document.createElement('option');
                    o.value = p.id;
                    o.textContent = p.label;
                    if (selectedId && selectedId === p.id) { o.selected = true; }
                    provider.appendChild(o);
                });
            }

            function hideNote() {
                note.hidden = true;
                noteTitle.textContent = '';
                noteBody.innerHTML = '';
                noteParams.innerHTML = '';
                note.className = 'draco-mail-note';
            }

            function row(dt, dd) {
                var d1 = document.createElement('dt');
                d1.textContent = dt;
                var d2 = document.createElement('dd');
                d2.textContent = dd;
                noteParams.appendChild(d1);
                noteParams.appendChild(d2);
            }

            function para(text, className) {
                if (!text) { return; }
                var el = document.createElement('p');
                if (className) { el.className = className; }
                el.textContent = text;
                noteBody.appendChild(el);
            }

            function showNote(p) {
                if (!p) { hideNote(); return; }
                var title = t.noteOk;
                var cls = 'draco-mail-note';
                if (p.trust === 'template') { title = t.noteTemplate; cls += ' is-template'; }
                else if (p.trust === 'warn') { title = t.noteWarn; cls += ' is-warn'; }
                note.className = cls;
                noteTitle.textContent = title;
                noteParams.innerHTML = '';
                noteBody.innerHTML = '';
                var hostLabel = p.host || (p.host_pattern || t.askHost);
                if (p.host_kind === 'ask' && !p.host) { hostLabel = t.askHost; }
                row(t.smtp, hostLabel);
                row(t.encryption, p.secure === 'tls' ? t.tls : t.ssl);
                row(t.port, String(p.port));
                para(t.fillsFields, 'draco-mail-note__auto');
                para(p.note || '');
                para(p.alt || '', 'draco-mail-note__alt');
                note.hidden = false;
            }

            // fill: only when the person chooses a provider; on opening the screen the saved values stay.
            function applyProvider(id, fill) {
                var p = byId[id];
                if (!p) {
                    hideNote();
                    $('draco-mail-user-help').textContent = userHelp;
                    $('draco-mail-pass-help').textContent = passHelp;
                    return;
                }
                $('draco-mail-user-help').textContent = p.user || userHelp;
                $('draco-mail-pass-help').textContent = p.pass || passHelp;
                if (fill) {
                    if (p.host) { $('draco-mail-host').value = p.host; }
                    else if (p.host_kind === 'ask') { $('draco-mail-host').value = ''; $('draco-mail-host').focus(); }
                    secure.value = p.secure;
                    port.value = p.port;
                }
                showNote(p);
            }

            region.addEventListener('change', function () {
                fillProviders(region.value, '');
                hideNote();
            });
            provider.addEventListener('change', function () {
                if (!provider.value) { hideNote(); return; }
                applyProvider(provider.value, true);
            });
            secure.addEventListener('change', function () { port.value = secure.value === 'ssl' ? 465 : 587; });

            // Restore cascade from saved host when possible.
            var savedHost = ($('draco-mail-host').value || '').toLowerCase();
            if (savedHost) {
                var same = catalog.filter(function (p) { return p.host && p.host.toLowerCase() === savedHost; });
                var match = same.find(function (p) { return String(p.port) === port.value && p.secure === secure.value; }) || same[0];
                if (match) {
                    region.value = match.region;
                    fillProviders(match.region, match.id);
                    applyProvider(match.id, false);
                }
            }

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
        JS;
        wp_print_inline_script_tag($js);
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
            'purged' => ['success', __('Recent messages cleared.', 'draco-insomnis')],
            /* translators: %s: e-mail address */
            'blocked' => ['success', sprintf(__('%s is blocked. Messages and sign-ups from that address are held or refused.', 'draco-insomnis'), $to)],
            'unblocked' => ['success', __('Address unblocked.', 'draco-insomnis')],
            'block_refused' => ['error', __('Nothing was blocked: the address is not valid, belongs to an administrator, or is your own.', 'draco-insomnis')],
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

        $blockEmail = sanitize_email(Input::get('block'));
        if ($blockEmail !== '') {
            Brand::card('dismiss', __('Block this address?', 'draco-insomnis'), $blockEmail, '', 'bad');
            self::open('block');
            echo '<input type="hidden" name="email" value="' . esc_attr($blockEmail) . '">';
            echo '<div class="draco-inline"><select name="days" aria-label="' . esc_attr__('For', 'draco-insomnis') . '">';
            foreach (Blocks::BLOCK_DAYS as $days) {
                echo '<option value="' . (int) $days . '"' . selected($days, 30, false) . '>' . esc_html(Blocks::daysLabel($days)) . '</option>';
            }
            echo '</select> ';
            submit_button(__('Block', 'draco-insomnis'), 'primary', 'submit', false);
            echo ' <a class="button button-link" href="' . esc_url(admin_url('admin.php?page=' . self::SLUG)) . '">' . esc_html__('Cancel', 'draco-insomnis') . '</a></div></form>';
            Brand::cardEnd();
        }

        Brand::card('list-view', __('Recent messages', 'draco-insomnis'), __('"Accepted" means the server took it, not that it reached the inbox. With PHP mail(), not even that. Message bodies are never stored. You can clear the list, or block an address that confirmed a form or sign-up.', 'draco-insomnis'), '', 'info', 'draco-card--flush');
        $rows = Log::rows();
        if ($rows !== []) {
            self::open('purge_log');
            echo '<p class="draco-toolbar">';
            submit_button(__('Clear list', 'draco-insomnis'), 'secondary', 'submit', false, [
                'onclick' => "return confirm('" . esc_js(__('Clear all recent messages from this list? This cannot be undone.', 'draco-insomnis')) . "');",
            ]);
            echo '</p></form>';
        }

        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>' . esc_html__('Via', 'draco-insomnis') . '</th><th>' . esc_html__('To', 'draco-insomnis') . '</th><th>' . esc_html__('Subject', 'draco-insomnis') . '</th><th>' . esc_html__('Result', 'draco-insomnis') . '</th><th></th></tr></thead><tbody>';
        foreach ($rows as $row) {
            /* translators: %s: error message */
            $state = !empty($row['ok']) ? Brand::pill(__('Accepted', 'draco-insomnis'), 'on') : Brand::pill(sprintf(__('Error: %s', 'draco-insomnis'), (string) ($row['error'] ?? '')), 'bad');
            $via = (string) ($row['transport'] ?? '');
            $toRaw = (string) ($row['to'] ?? '');
            $first = strtolower(trim(explode(',', $toRaw)[0] ?? ''));
            $block = is_email($first)
                ? '<a href="' . esc_url(admin_url('admin.php?page=' . self::SLUG . '&block=' . rawurlencode($first))) . '">' . esc_html__('Block', 'draco-insomnis') . '</a>'
                : '';
            echo '<tr><td>' . esc_html(gmdate('Y-m-d H:i:s', (int) ($row['at'] ?? 0))) . '</td><td>' . wp_kses_post(Brand::pill($labels[$via] ?? '', $via === 'smtp' ? 'info' : 'off')) . '</td><td>'
                . esc_html($toRaw) . '</td><td>' . esc_html((string) ($row['subject'] ?? '')) . '</td><td>' . wp_kses_post($state) . '</td><td>' . $block . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $block built with esc_url/esc_html
        }
        if ($rows === []) {
            Brand::emptyRow(6, __('Nothing yet.', 'draco-insomnis'), 'email');
        }
        echo '</tbody></table></div>';
        Brand::cardEnd();
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
