<?php

declare(strict_types=1);

namespace DracoInsomnis\Mail;

defined('ABSPATH') || exit;

/**
 * SMTP presets: Global + by country. Built from verified help docs (2026-11-16).
 * trust: ok = fixed host · template = build/ask host · warn = convergent sources · no = unverified (not listed).
 *
 * @phpstan-type Provider array{
 *   id: string,
 *   label: string,
 *   region: string,
 *   host: string,
 *   host_kind: string,
 *   secure: string,
 *   port: int,
 *   user: string,
 *   pass: string,
 *   group: string,
 *   trust: string,
 *   note: string,
 *   alt: string
 * }
 */
final class Providers
{
    /**
     * Regions for the first cascade (global first, then countries A–Z by label).
     *
     * @return array<string, string> region code => label
     */
    public static function regions(): array
    {
        $map = [
            'global' => __('Global', 'draco-insomnis'),
            'BD' => __('BD — Bangladesh', 'draco-insomnis'),
            'BR' => __('BR — Brasil', 'draco-insomnis'),
            'CN' => __('CN — China', 'draco-insomnis'),
            'CO' => __('CO — Colombia', 'draco-insomnis'),
            'DE' => __('DE — Deutschland (Germany)', 'draco-insomnis'),
            'ES' => __('ES — España', 'draco-insomnis'),
            'ET' => __('ET — Ethiopia', 'draco-insomnis'),
            'FR' => __('FR — France', 'draco-insomnis'),
            'HK' => __('HK — Hong Kong', 'draco-insomnis'),
            'ID' => __('ID — Indonesia', 'draco-insomnis'),
            'IN' => __('IN — India', 'draco-insomnis'),
            'IQ' => __('IQ — Iraq', 'draco-insomnis'),
            'MX' => __('MX — México', 'draco-insomnis'),
            'NL' => __('NL — Nederland (Netherlands)', 'draco-insomnis'),
            'PL' => __('PL — Polska (Poland)', 'draco-insomnis'),
            'RU' => __('RU — Россия (Russia)', 'draco-insomnis'),
            'TR' => __('TR — Türkiye', 'draco-insomnis'),
            'UK' => __('UK — United Kingdom', 'draco-insomnis'),
            'US' => __('US — United States', 'draco-insomnis'),
            'VN' => __('VN — Việt Nam', 'draco-insomnis'),
        ];

        return $map;
    }

    /**
     * All selectable presets (verified fixed + templates with notes). Unverified providers are omitted.
     *
     * @return list<Provider>
     */
    public static function all(): array
    {
        $box = __('The full address of the mailbox, with @ and domain. Not your WordPress username.', 'draco-insomnis');
        $pass = __('The password of that mailbox, not the one for WordPress or your hosting. If you do not remember it, change it in your hosting or domain panel, in the e-mail section.', 'draco-insomnis');
        $app = __('An app password, created in the security settings of your account. Not your normal password.', 'draco-insomnis');
        $full = __('Your full address.', 'draco-insomnis');
        $tpl = __('This provider uses a host that depends on your domain or the server assigned to your account. Fill the outgoing server as shown, or copy it from your hosting panel.', 'draco-insomnis');
        $titanNote = __('Titan Email (smtp.titan.email, 465 SSL) is used by several hostings (Bluehost Professional Email, HostGator Brasil Titan, BigRock Titan, IraqHosting business mail…).', 'draco-insomnis');

        $alt587 = __('Also documented: port 587 with STARTTLS/TLS if 465 fails.', 'draco-insomnis');
        $p = static function (
            string $id,
            string $label,
            string $region,
            string $host,
            string $kind,
            string $secure,
            int $port,
            string $user,
            string $passHelp,
            string $group,
            string $trust,
            string $note = '',
            string $alt = ''
        ): array {
            return compact('id', 'label', 'region', 'host', 'secure', 'port', 'user', 'group', 'trust', 'note', 'alt') + [
                'host_kind' => $kind,
                'pass' => $passHelp,
            ];
        };

        return [
            // —— Global (cross-border / already in Draco) ——
            $p('hostinger', 'Hostinger', 'global', 'smtp.hostinger.com', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Use the normal mailbox password. SSL on 465 is the usual setting.', 'draco-insomnis'), $alt587),
            $p('ionos-com', 'IONOS (international)', 'global', 'smtp.ionos.com', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('IONOS hosts differ by country: .es, .de and .com are not interchangeable.', 'draco-insomnis'), $alt587),
            $p('ovh', 'OVHcloud', 'global', 'ssl0.ovh.net', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Official alternative host: smtp.mail.ovh.net (same 465 SSL).', 'draco-insomnis')),
            $p('godaddy-titan', 'GoDaddy / 123 Reg — Professional Email (Titan)', 'global', 'smtpout.secureserver.net', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('123 Reg Professional Email currently uses the same GoDaddy Titan host (smtpout.secureserver.net).', 'draco-insomnis'), $alt587),
            $p('titan', 'Titan Email', 'global', 'smtp.titan.email', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', $titanNote, $alt587),
            $p('arsys', 'Arsys', 'global', 'smtp.serviciodecorreo.es', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Spanish hosting mail. Prefer a mailbox on this site’s domain.', 'draco-insomnis')),
            $p('zoho-eu', 'Zoho Mail (EU)', 'global', 'smtp.zoho.eu', 'fixed', 'ssl', 465, $box, __('The mailbox password, or an app password if you use two-step verification.', 'draco-insomnis'), 'domain', 'ok', __('EU datacentre. With two-step verification, create an app password.', 'draco-insomnis')),
            $p('m365', 'Microsoft 365', 'global', 'smtp.office365.com', 'fixed', 'tls', 587, $box, __('The mailbox password or an app password. SMTP sending must be allowed in Microsoft 365.', 'draco-insomnis'), 'domain', 'ok', __('Authenticated SMTP must be enabled for the mailbox in the Microsoft 365 admin centre.', 'draco-insomnis')),
            $p('google', 'Google Workspace / Gmail', 'global', 'smtp.gmail.com', 'fixed', 'ssl', 465, __('The full address of the Google account.', 'draco-insomnis'), $app, 'domain', 'ok', __('Requires an app password (or SMTP relay for Workspace). Normal Google password will not work with 2FA.', 'draco-insomnis')),
            $p('brevo', 'Brevo', 'global', 'smtp-relay.brevo.com', 'fixed', 'tls', 587, __('The SMTP login shown in your Brevo account.', 'draco-insomnis'), __('The Brevo SMTP key, not your account password.', 'draco-insomnis'), 'relay', 'ok', __('Transactional relay: use the SMTP login and key from Brevo, not the mailbox password.', 'draco-insomnis')),
            $p('mailgun', 'Mailgun', 'global', 'smtp.mailgun.org', 'fixed', 'tls', 587, __('The SMTP user of your domain in Mailgun.', 'draco-insomnis'), __('The SMTP password of that user.', 'draco-insomnis'), 'relay', 'ok', __('Relay for a verified domain in Mailgun.', 'draco-insomnis')),
            $p('sendgrid', 'SendGrid', 'global', 'smtp.sendgrid.net', 'fixed', 'tls', 587, __('Type literally: apikey', 'draco-insomnis'), __('Your SendGrid API key.', 'draco-insomnis'), 'relay', 'ok', __('Username must be the literal word “apikey”; password is the API key.', 'draco-insomnis')),
            $p('postmark', 'Postmark', 'global', 'smtp.postmarkapp.com', 'fixed', 'tls', 587, __('The Postmark Server API Token.', 'draco-insomnis'), __('The same Server API Token.', 'draco-insomnis'), 'relay', 'ok', __('Username and password are both the Server API Token.', 'draco-insomnis')),
            $p('mailjet', 'Mailjet', 'global', 'in-v3.mailjet.com', 'fixed', 'tls', 587, __('Your Mailjet API key.', 'draco-insomnis'), __('Your Mailjet secret key.', 'draco-insomnis'), 'relay', 'ok', __('API key as username, secret key as password.', 'draco-insomnis')),
            $p('ses-eu', 'Amazon SES (Ireland)', 'global', 'email-smtp.eu-west-1.amazonaws.com', 'fixed', 'tls', 587, __('The SMTP user created in Amazon SES.', 'draco-insomnis'), __('The Amazon SES SMTP password, not your AWS password.', 'draco-insomnis'), 'relay', 'ok', __('Region Ireland (eu-west-1). Create SMTP credentials in SES; do not use your AWS console password.', 'draco-insomnis')), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- an SMTP host name, nothing is loaded from it.
            $p('outlook', 'Outlook.com / Hotmail', 'global', 'smtp-mail.outlook.com', 'fixed', 'tls', 587, $full, $app, 'personal', 'ok', __('Personal Microsoft account. Prefer a mailbox on this site’s domain for deliverability.', 'draco-insomnis')),
            $p('yahoo', 'Yahoo Mail', 'global', 'smtp.mail.yahoo.com', 'fixed', 'ssl', 465, $full, $app, 'personal', 'ok', __('Requires an app password. Not ideal as the site’s main sender.', 'draco-insomnis')),
            $p('icloud', 'iCloud Mail', 'global', 'smtp.mail.me.com', 'fixed', 'tls', 587, $full, $app, 'personal', 'ok', __('Requires an app-specific password from appleid.apple.com.', 'draco-insomnis')),

            // —— United States ——
            $p('us-godaddy-m365', 'GoDaddy — Microsoft 365', 'US', 'smtp.office365.com', 'fixed', 'tls', 587, $box, __('The mailbox password or an app password. SMTP sending must be allowed in Microsoft 365.', 'draco-insomnis'), 'domain', 'ok', __('Different product from GoDaddy Professional Email (Titan). Authenticated SMTP must be allowed in Microsoft 365.', 'draco-insomnis')),
            $p('us-bluehost-titan', 'Bluehost — Professional Email (Titan)', 'US', 'smtp.titan.email', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', $titanNote . ' ' . __('In the EU, Bluehost documents smtp0101.titan.email as a variant.', 'draco-insomnis'), $alt587),
            $p('us-bluehost-cpanel', 'Bluehost — cPanel mail', 'US', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl, $alt587),
            $p('us-hostgator', 'HostGator — hosting mail', 'US', '', 'ask', 'ssl', 465, $box, $pass, 'domain', 'template', __('Host is often {server}.hostgator.com or mail.{domain}. Copy it from HostGator.', 'draco-insomnis'), $alt587),

            // —— China ——
            $p('cn-qq', 'QQ Mail (Tencent, personal)', 'CN', 'smtp.qq.com', 'fixed', 'ssl', 465, $full, $app, 'personal', 'warn', __('Reliable sources agree, but no direct official URL was found. You must enable IMAP/SMTP and use a 16-character authorization code (normal password fails).', 'draco-insomnis')),
            $p('cn-163', '163 Mail (NetEase, personal)', 'CN', 'smtp.163.com', 'fixed', 'ssl', 465, $full, $app, 'personal', 'warn', __('Reliable sources agree; no direct official URL. Safe preset is 465 SSL only. Enable IMAP/SMTP and use an authorization code.', 'draco-insomnis')),
            $p('cn-aliyun-ent', 'Alibaba Cloud Mail — Enterprise', 'CN', 'smtp.qiye.aliyun.com', 'fixed', 'ssl', 465, $box, $app, 'domain', 'ok', __('Official docs: ports 80 and 587 are not available for SMTP. Use 465 SSL only. Enable third-party clients / client password.', 'draco-insomnis')),
            $p('cn-aliyun-pers', 'Alibaba Cloud Mail — Personal', 'CN', 'smtp.aliyun.com', 'fixed', 'ssl', 465, $full, $app, 'personal', 'ok', __('Official docs: ports 80 and 587 are not available for SMTP. Use 465 SSL only.', 'draco-insomnis')),
            $p('cn-exmail', 'Tencent Exmail / WeCom Mail', 'CN', 'smtp.exmail.qq.com', 'fixed', 'ssl', 465, $box, $app, 'domain', 'warn', __('Reliable sources agree; no direct official URL. App password required if Secure Login is on.', 'draco-insomnis')),

            // —— India ——
            $p('in-hostinger', 'Hostinger', 'IN', 'smtp.hostinger.com', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Same Hostinger SMTP worldwide. Use the mailbox password.', 'draco-insomnis'), $alt587),
            $p('in-bigrock-cpanel', 'BigRock — cPanel', 'IN', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl, $alt587),
            $p('in-bigrock-biz', 'BigRock — Business Email', 'IN', 'us2.smtp.mailhostbox.com', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Mailhostbox product (not Titan). Confirm the regional host in the BigRock panel if login fails.', 'draco-insomnis'), $alt587),
            $p('in-bigrock-titan', 'BigRock — Titan Email', 'IN', 'smtp.titan.email', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', $titanNote, $alt587),

            // —— Brasil ——
            $p('br-hg-cpanel', 'HostGator Brasil — cPanel', 'BR', 'mail.{domain}', 'template', 'tls', 587, $box, $pass, 'domain', 'template', $tpl . ' ' . __('Their WP-Mail-SMTP guide uses mail.{domain}.com.br style hosts and prefers 587/STARTTLS.', 'draco-insomnis')),
            $p('br-hg-titan', 'HostGator Brasil — Titan', 'BR', 'smtp.titan.email', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', $titanNote, $alt587),
            $p('br-locaweb', 'Locaweb — Email Locaweb', 'BR', 'email-ssl.com.br', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Mailbox product on Locaweb. Prefer a mailbox on this site’s domain.', 'draco-insomnis')),
            $p('br-locaweb-smtp', 'Locaweb — SMTP Locaweb (transactional)', 'BR', 'smtplw.com.br', 'fixed', 'ssl', 465, $box, $pass, 'relay', 'ok', __('Transactional SMTP product (smtplw.com.br), separate from Email Locaweb.', 'draco-insomnis')),

            // —— UK ——
            $p('uk-123reg', '123 Reg — Professional Email', 'UK', 'smtpout.secureserver.net', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Same host as GoDaddy Titan. Old smtp.123-reg.co.uk is not in current official docs.', 'draco-insomnis'), $alt587),

            // —— Indonesia ——
            $p('id-rumahweb', 'Rumahweb', 'ID', 'mail.{domain}', 'template', 'tls', 587, $box, $pass, 'domain', 'template', $tpl . ' ' . __('Their guide uses 587/STARTTLS for hosting mail.', 'draco-insomnis')),

            // —— Vietnam ——
            $p('vn-azdigi-host', 'AZDIGI — Hosting (cPanel)', 'VN', '', 'ask', 'ssl', 465, $box, $pass, 'domain', 'template', __('Host is the assigned server (e.g. chv4-24911.azdigi.com). Copy it from AZDIGI.', 'draco-insomnis'), $alt587),
            $p('vn-azdigi-pro', 'AZDIGI — Pro Mail', 'VN', 'h01.azdigimail.com', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Pro Mail host (not the same as cPanel hosting mail).', 'draco-insomnis'), $alt587),
            $p('vn-matbao', 'Mat Bao — Email Pro / 4B', 'VN', '', 'ask', 'ssl', 465, $box, $pass, 'domain', 'template', __('Host looks like proXX.emailserver.vn or svXXdXXX.emailserver.vn — copy from Mat Bao.', 'draco-insomnis'), $alt587),
            $p('vn-pa', 'PA Vietnam — Email Server', 'VN', '', 'ask', 'ssl', 465, $box, $pass, 'domain', 'template', __('Host looks like mailXX.maychuemail.com — assigned per account.', 'draco-insomnis'), $alt587),

            // —— Russia ——
            $p('ru-reg', 'reg.ru — Linux hosting', 'RU', 'mail.hosting.reg.ru', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Linux hosting mail. Confirm in the reg.ru panel if your plan uses another host.', 'draco-insomnis'), $alt587),
            $p('ru-beget', 'Beget', 'RU', 'smtp.beget.com', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Documented limit: 30 messages/min and 1500/hour over SMTP.', 'draco-insomnis'), $alt587),
            $p('ru-timeweb', 'Timeweb / Timeweb Cloud', 'RU', 'smtp.timeweb.ru', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Shared Timeweb SMTP for hosting mailboxes.', 'draco-insomnis'), $alt587),
            $p('ru-yandex', 'Yandex Mail', 'RU', 'smtp.yandex.com', 'fixed', 'ssl', 465, $full, $app, 'personal', 'ok', __('Enable IMAP and use an app password.', 'draco-insomnis')),

            // —— Turkey ——
            $p('tr-natro-host', 'Natro — hosting mail', 'TR', 'mail.{domain}', 'template', 'tls', 587, $box, $pass, 'domain', 'template', __('Their WordPress guide documents 587 without encryption for hosting mail. Corporate mail is a different product. Prefer STARTTLS if the server allows it.', 'draco-insomnis')),
            $p('tr-natro-corp', 'Natro — corporate mail', 'TR', 'mail.kurumsaleposta.com', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Corporate product (mail.kurumsaleposta.com), not hosting mail.', 'draco-insomnis'), $alt587),
            $p('tr-turhost', 'Turhost — hosting', 'TR', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl, $alt587),
            $p('tr-isim-gen', 'İsimtescil — generic', 'TR', 'mail.isimtescil.net', 'fixed', 'tls', 587, $box, $pass, 'domain', 'ok', __('Encryption not stated clearly in the source; try STARTTLS on 587 first.', 'draco-insomnis')),
            $p('tr-isim-host', 'İsimtescil — hosting mail', 'TR', 'smtp.{domain}', 'template', 'tls', 587, $box, $pass, 'domain', 'template', $tpl),
            $p('tr-mailmatik', 'İsimtescil — Mailmatik', 'TR', 'giden.mailmatik.com', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Mailmatik outgoing host (giden.mailmatik.com).', 'draco-insomnis'), $alt587),

            // —— Mexico ——
            $p('mx-neubox-host', 'Neubox — hosting mail', 'MX', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl, $alt587),
            $p('mx-neubox-biz', 'Neubox — Correo Empresarial', 'MX', 'smtp.us.appsuite.cloud', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('OX App Suite enterprise mail (smtp.us.appsuite.cloud), not hosting mail.', 'draco-insomnis'), $alt587),
            $p('mx-hospedando', 'Hospedando', 'MX', 'mail.{domain}', 'template', 'tls', 587, $box, $pass, 'domain', 'template', $tpl . ' ' . __('Their guide prefers 587/STARTTLS.', 'draco-insomnis')),

            // —— Iraq ——
            $p('iq-iqhosting', 'IQ-Hosting', 'IQ', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl, $alt587),
            $p('iq-iraqserv', 'Iraq Serv', 'IQ', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl, $alt587),
            $p('iq-iraqhosting-titan', 'IraqHosting — business (Titan)', 'IQ', 'smtp.titan.email', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', $titanNote, $alt587),

            // —— Bangladesh ——
            $p('bd-exon', 'ExonHost', 'BD', 'meghna.exonhost.com', 'fixed', 'tls', 587, $box, $pass, 'domain', 'ok', __('SSL required; TLS 1.2+. 465 also documented — switch encryption/port below if 587 fails.', 'draco-insomnis')),
            $p('bd-alpha', 'Alpha Net', 'BD', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl, $alt587),
            $p('bd-hostmight', 'HostMight', 'BD', 'smtp.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', __('Their docs mark STARTTLS as unused: prefer 465 SSL. 587 is without SSL.', 'draco-insomnis')),

            // —— Ethiopia ——
            $p('et-yegara', 'Yegara Host', 'ET', 'mail.{domain}', 'template', 'tls', 587, $box, $pass, 'domain', 'template', __('Only 587/TLS is documented. On their VPS, ports 25 and 465 are blocked by default — do not force 465.', 'draco-insomnis')),

            // —— Hong Kong ——
            $p('hk-aliyun', 'Alibaba Mail — Hong Kong', 'HK', 'smtphk.qiye.aliyun.com', 'fixed', 'ssl', 465, $box, $app, 'domain', 'ok', __('Same Alibaba rule: no port 587 for SMTP; use 465 SSL.', 'draco-insomnis')),

            // —— Spain ——
            $p('es-cdmon', 'CDmon', 'ES', 'smtp.{domain}', 'template', 'tls', 587, $box, $pass, 'domain', 'template', __('Official docs recommend 587/STARTTLS at the top and 465/SSL in detailed steps — both work. Prefer 587 first; you can change encryption/port below.', 'draco-insomnis')),
            $p('es-dina', 'dinahosting', 'ES', '{domain}.correoseguro.dinaserver.com', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl . ' ' . __('Host pattern: yourdomain.correoseguro.dinaserver.com.', 'draco-insomnis'), $alt587),
            $p('es-nominalia', 'Nominalia', 'ES', 'authsmtp.securemail.pro', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Current official page uses authsmtp.securemail.pro (not the older smtp-es.securemail.pro).', 'draco-insomnis'), $alt587),
            $p('es-raiola', 'Raiola Networks', 'ES', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl . ' ' . __('Or the cPanel hostname assigned to your account.', 'draco-insomnis'), $alt587),
            $p('es-ionos', 'IONOS España', 'ES', 'smtp.ionos.es', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Not interchangeable with smtp.ionos.de or smtp.ionos.com.', 'draco-insomnis'), $alt587),

            // —— Germany ——
            $p('de-strato', 'Strato', 'DE', 'smtp.strato.de', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Strato mailbox SMTP. Prefer a mailbox on this site’s domain.', 'draco-insomnis'), $alt587),
            $p('de-ionos', 'IONOS Deutschland', 'DE', 'smtp.ionos.de', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Not interchangeable with smtp.ionos.es or smtp.ionos.com.', 'draco-insomnis'), $alt587),

            // —— France ——
            $p('fr-ovh', 'OVHcloud', 'FR', 'ssl0.ovh.net', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('Official alternative host: smtp.mail.ovh.net (same 465 SSL).', 'draco-insomnis')),
            $p('fr-o2switch', 'o2switch', 'FR', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', __('Or {server}.o2switch.net — copy from o2switch.', 'draco-insomnis'), $alt587),
            $p('fr-planet', 'PlanetHoster', 'FR', '', 'ask', 'ssl', 465, $box, $pass, 'domain', 'template', __('Host is the hosting server hostname for your account.', 'draco-insomnis'), $alt587),

            // —— Netherlands ——
            $p('nl-transip', 'TransIP', 'NL', 'smtp.transip.email', 'fixed', 'ssl', 465, $box, $pass, 'domain', 'ok', __('TransIP mailbox SMTP.', 'draco-insomnis'), $alt587),
            $p('nl-hostnet', 'Hostnet', 'NL', 'smtp.hostnet.nl', 'fixed', 'tls', 587, $box, $pass, 'domain', 'ok', __('Exception: Hostnet’s standard is 587/STARTTLS, not 465/SSL. Do not force 465. Guide also mentions mailout.hostnet.nl.', 'draco-insomnis')),

            // —— Poland ——
            $p('pl-home', 'home.pl', 'PL', '', 'ask', 'ssl', 465, $box, $pass, 'domain', 'template', __('Host looks like serwerNNNNNN.home.pl — assigned per account.', 'draco-insomnis'), $alt587),
            $p('pl-nazwa', 'nazwa.pl', 'PL', '', 'ask', 'ssl', 465, $box, $pass, 'domain', 'template', __('Host looks like serverNNNNNN.nazwa.pl — assigned per account.', 'draco-insomnis'), $alt587),

            // —— Colombia ——
            $p('co-colhost', 'ColombiaHosting', 'CO', 'mail.{domain}', 'template', 'ssl', 465, $box, $pass, 'domain', 'template', $tpl, $alt587),
            $p('co-mi', 'mi.com.co (Mi)', 'CO', 'smtp.mi.com.co', 'fixed', 'tls', 587, $box, $pass, 'domain', 'ok', __('mi.com.co documents 587/STARTTLS as the standard outgoing setting.', 'draco-insomnis')),
        ];
    }

    /** @return list<Provider> */
    public static function forRegion(string $region): array
    {
        $out = [];
        foreach (self::all() as $row) {
            if ($row['region'] === $region) {
                $out[] = $row;
            }
        }

        return $out;
    }

    /** Find a preset by SMTP host (first match). */
    public static function byHost(string $host): ?array
    {
        $host = strtolower(trim($host));
        if ($host === '') {
            return null;
        }
        foreach (self::all() as $row) {
            if ($row['host_kind'] === 'fixed' && strtolower($row['host']) === $host) {
                return $row;
            }
        }

        return null;
    }

    /**
     * Resolve template host placeholders for this site.
     *
     * @param Provider $provider
     */
    public static function resolveHost(array $provider, string $domain): string
    {
        if ($provider['host_kind'] === 'ask' || $provider['host'] === '') {
            return '';
        }
        if ($provider['host_kind'] === 'fixed') {
            return $provider['host'];
        }

        return str_replace('{domain}', $domain, $provider['host']);
    }
}
