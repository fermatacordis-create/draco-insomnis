<?php
/**
 * @author    Notorius Vision
 * @license   GPL-2.0-or-later
 */

declare(strict_types=1);

namespace DracoInsomnis\Presta;

use DracoInsomnis\Core\NetList;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * The module's configuration page: settings, the evidence of the last attempts (with a CSV per address
 * for abuse reports) and the block list. PrestaShop checks the back-office token of this page itself.
 */
final class Admin
{
    public function __construct(private \DracoInsomnis $module)
    {
    }

    public function render(): string
    {
        $csv = (string) \Tools::getValue('draco_csv');
        if ($csv !== '' && filter_var($csv, FILTER_VALIDATE_IP) !== false) {
            $this->csv($csv);
        }
        $out = '';
        if (\Tools::isSubmit('submitDracoSettings')) {
            $this->save();
            $out .= $this->module->displayConfirmation($this->module->t('Settings saved.'));
            $host = PsHost::get();
            if (in_array($host->setting('geo_mode'), ['block', 'allow'], true) && \DracoInsomnis\Core\Geo::built($host->setting('geo_file')) === '') {
                $out .= \DracoInsomnis\Core\GeoUpdate::update($host->setting('geo_file')) === ''
                    ? $this->module->displayConfirmation($this->t('Country list downloaded.'))
                    : $this->module->displayError($this->t('The country list could not be downloaded. The filter does nothing until it is there; save again later.'));
            }
        }
        if (\Tools::isSubmit('draco_block')) {
            $value = trim((string) \Tools::getValue('draco_block_value'));
            $done = (new Store())->block('ip', $value, (int) \Tools::getValue('draco_block_days'), (string) \Tools::getValue('draco_block_reason'));
            $out .= $done ? $this->module->displayConfirmation(sprintf($this->t('Blocked: %s'), $value)) : $this->module->displayError($this->t('Nothing was blocked: the value is not valid, belongs to an employee, or is your own address.'));
        }
        if (\Tools::isSubmit('draco_unblock')) {
            Store::unblock((int) \Tools::getValue('draco_unblock'));
            $out .= $this->module->displayConfirmation($this->module->t('Address unblocked.'));
        }

        return $out . $this->intro() . $this->form() . $this->blocks() . $this->events();
    }

    private function t(string $text): string
    {
        return $this->module->t($text);
    }

    private static function h(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }

    private function url(array $params = []): string
    {
        $link = \Context::getContext()->link->getAdminLink('AdminModules', true, [], ['configure' => $this->module->name]);

        return $link . ($params !== [] ? '&' . http_build_query($params) : '');
    }

    private function save(): void
    {
        Settings::set(Settings::SHIELD, \Tools::getValue('DRACO_SHIELD') ? '1' : '0');
        foreach ([Settings::WAF_MODE, Settings::PACE_MODE] as $name) {
            $mode = (string) \Tools::getValue($name);
            Settings::set($name, in_array($mode, Settings::MODES, true) ? $mode : 'off');
        }
        foreach ([Settings::RATE_IP => 120, Settings::RATE_NET => 600] as $name => $default) {
            $value = (int) \Tools::getValue($name);
            Settings::set($name, (string) ($value >= 10 ? $value : $default));
        }
        $proxy = (string) \Tools::getValue(Settings::PROXY);
        Settings::set(Settings::PROXY, in_array($proxy, Settings::PROXIES, true) ? $proxy : '');
        Settings::set(Settings::TRUSTED, implode("\n", NetList::parse((string) \Tools::getValue(Settings::TRUSTED))));
        Settings::set(Settings::NETS, implode("\n", NetList::parse((string) \Tools::getValue(Settings::NETS))));
        $geo = (string) \Tools::getValue(Settings::GEO_MODE);
        Settings::set(Settings::GEO_MODE, in_array($geo, ['block', 'allow'], true) ? $geo : 'off');
        Settings::set(Settings::GEO_SCOPE, \Tools::getValue(Settings::GEO_SCOPE) === 'site' ? 'site' : 'sensitive');
        Settings::set(Settings::GEO_ACTION, \Tools::getValue(Settings::GEO_ACTION) === 'block' ? 'block' : 'log');
        Settings::set(Settings::GEO_COUNTRIES, implode(', ', \DracoInsomnis\Core\Geo::parseList((string) \Tools::getValue(Settings::GEO_COUNTRIES))));
        Settings::set(Settings::HEADERS, \Tools::getValue(Settings::HEADERS) ? '1' : '0');
        Settings::set(Settings::HSTS, \Tools::getValue(Settings::HSTS) ? '1' : '0');
    }

    private function intro(): string
    {
        $request = PsHost::request();

        return '<div class="panel"><h3><i class="icon-shield"></i> Draco Insomnis</h3>'
            . '<p><em>Ab insomni custodita dracone.</em> ' . self::h($this->t('Stops fake customer sign-ups without captchas: bots get no account, and every suspicious attempt is kept for 90 days as evidence for an abuse report. Nothing is ever sent back to the attacker.')) . '</p>'
            . '<p>' . self::h($this->t('Your address as the module sees it:')) . ' <code>' . self::h($request->via(PsHost::get())) . '</code> '
            . self::h($this->t('(connection address:')) . ' <code>' . self::h($request->remote()) . '</code>). '
            . self::h($this->t('If the shop is behind Cloudflare or another proxy and these differ from your real address, choose the matching option in "Visitor address".')) . '</p>'
            . ($request->proxyHeaderIgnored(Settings::get(Settings::PROXY), Settings::get(Settings::TRUSTED))
                ? '<p class="alert alert-warning">' . self::h(sprintf($this->t('The header is ignored: this connection (%s) does not come from Cloudflare or from a trusted proxy. If your proxy is on the internet, add its addresses in "Trusted proxies".'), $request->remote())) . '</p>'
                : '')
            . '</div>';
    }

    private function form(): string
    {
        $modes = [
            ['id' => 'off', 'name' => $this->t('Off')],
            ['id' => 'log', 'name' => $this->t('Log only: record what it would stop')],
            ['id' => 'block', 'name' => $this->t('Block')],
        ];
        $fields = [
            'form' => [
                'legend' => ['title' => $this->t('Settings'), 'icon' => 'icon-cogs'],
                'input' => [
                    [
                        'type' => 'switch',
                        'label' => $this->t('Protect customer sign-ups'),
                        'name' => 'DRACO_SHIELD',
                        'is_bool' => true,
                        'desc' => $this->t('Adds an invisible trap and a signed page stamp to the sign-up form (account page and checkout). Bots get no account; three bot attempts in a day block the address for a week.'),
                        'values' => [['id' => 'on', 'value' => 1, 'label' => $this->t('Yes')], ['id' => 'off', 'value' => 0, 'label' => $this->t('No')]],
                    ],
                    [
                        'type' => 'select',
                        'label' => $this->t('Firewall'),
                        'name' => Settings::WAF_MODE,
                        'desc' => $this->t('Stops requests with the shape of an attack (database injection, reading server files, running code, scripts in links) and scanners such as sqlmap or Nikto. Start with "Log only" and move to "Block" after a few days. Five attacks in 10 minutes block the address for a week; blocked addresses can still browse, but not post. Emergency exit: define(\'DRACO_WAF_OFF\', true); in config/defines_custom.inc.php.'),
                        'options' => ['query' => $modes, 'id' => 'id', 'name' => 'name'],
                    ],
                    [
                        'type' => 'select',
                        'label' => $this->t('Anti-copy pace limit'),
                        'name' => Settings::PACE_MODE,
                        'desc' => $this->t('More pages per minute than a person reads get "429 Too many requests" until the minute ends. Logged-in customers, your own addresses and search engines verified by DNS (Google, Bing, Apple, Yandex) are never limited.'),
                        'options' => ['query' => $modes, 'id' => 'id', 'name' => 'name'],
                    ],
                    ['type' => 'text', 'label' => $this->t('Pages per minute, per address'), 'name' => Settings::RATE_IP, 'class' => 'fixed-width-sm'],
                    ['type' => 'text', 'label' => $this->t('Pages per minute, per network'), 'name' => Settings::RATE_NET, 'class' => 'fixed-width-sm', 'desc' => $this->t('A /24 network for IPv4 or a /64 for IPv6: what a scraper gets when it rotates addresses next to each other.')],
                    [
                        'type' => 'select',
                        'label' => $this->t('Visitor address'),
                        'name' => Settings::PROXY,
                        'desc' => $this->t('Leave "Connection address" unless the shop is behind a proxy: a header can be forged by anyone.'),
                        'options' => ['query' => [
                            ['id' => '', 'name' => $this->t('Connection address (recommended)')],
                            ['id' => 'cf', 'name' => $this->t('Cloudflare (CF-Connecting-IP)')],
                            ['id' => 'xff', 'name' => $this->t('Other proxy (X-Forwarded-For)')],
                        ], 'id' => 'id', 'name' => 'name'],
                    ],
                    [
                        'type' => 'select',
                        'label' => $this->t('Countries'),
                        'name' => Settings::GEO_MODE,
                        'desc' => $this->t('Most of your customers may come from many countries, and an attacker changes country with a VPN. Filter only logging in, signing up and forms, and start with "Log only". Employees, people you let through and search engines are never filtered. Needs the firewall on (log or block).'),
                        'options' => ['query' => [
                            ['id' => 'off', 'name' => $this->t('Off')],
                            ['id' => 'block', 'name' => $this->t('Refuse the countries listed')],
                            ['id' => 'allow', 'name' => $this->t('Only the countries listed')],
                        ], 'id' => 'id', 'name' => 'name'],
                    ],
                    [
                        'type' => 'select',
                        'label' => $this->t('Where'),
                        'name' => Settings::GEO_SCOPE,
                        'options' => ['query' => [
                            ['id' => 'sensitive', 'name' => $this->t('Logging in, signing up and forms (recommended)')],
                            ['id' => 'site', 'name' => $this->t('The whole shop')],
                        ], 'id' => 'id', 'name' => 'name'],
                    ],
                    [
                        'type' => 'select',
                        'label' => $this->t('What to do'),
                        'name' => Settings::GEO_ACTION,
                        'options' => ['query' => [
                            ['id' => 'log', 'name' => $this->t('Log only: record what it would stop')],
                            ['id' => 'block', 'name' => $this->t('Block')],
                        ], 'id' => 'id', 'name' => 'name'],
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->t('Countries (two-letter codes, e.g. ES, FR, DE)'),
                        'name' => Settings::GEO_COUNTRIES,
                        'desc' => $this->t('IP geolocation by DB-IP (db-ip.com, CC BY 4.0), downloaded when you switch the filter on and looked up on your own server: no address is sent anywhere.'),
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->t('Security headers'),
                        'name' => Settings::HEADERS,
                        'is_bool' => true,
                        'desc' => $this->t('On shop pages: no sniffing of file types, no framing by other sites, less referrer data, no camera, microphone or location for embedded content. Never one already sent.'),
                        'values' => [['id' => 'h_on', 'value' => 1, 'label' => $this->t('Yes')], ['id' => 'h_off', 'value' => 0, 'label' => $this->t('No')]],
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->t('Force HTTPS for 6 months (HSTS)'),
                        'name' => Settings::HSTS,
                        'is_bool' => true,
                        'desc' => $this->t('Only when the whole shop works on HTTPS and will keep working: browsers remember it and refuse plain HTTP until it expires.'),
                        'values' => [['id' => 's_on', 'value' => 1, 'label' => $this->t('Yes')], ['id' => 's_off', 'value' => 0, 'label' => $this->t('No')]],
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->t('Trusted proxies'),
                        'name' => Settings::TRUSTED,
                        'rows' => 2,
                        'desc' => $this->t('Only connections from these addresses may set the visitor address through a header. One address or range per line. Empty: this server and private networks. Cloudflare\'s own ranges are already known.'),
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->t('Rented-server networks'),
                        'name' => Settings::NETS,
                        'rows' => 4,
                        'desc' => $this->t('One range per line (CIDR), added to the ones the module already knows. Being on this list only adds points: on its own it never makes anyone a bot.'),
                    ],
                ],
                'submit' => ['title' => $this->t('Save'), 'name' => 'submitDracoSettings'],
            ],
        ];

        $helper = new \HelperForm();
        $helper->module = $this->module;
        $helper->table = $this->module->name;
        $helper->name_controller = $this->module->name;
        $helper->token = \Tools::getAdminTokenLite('AdminModules');
        $helper->currentIndex = \AdminController::$currentIndex . '&' . http_build_query(['configure' => $this->module->name]);
        $helper->default_form_language = (int) \Configuration::get('PS_LANG_DEFAULT');
        $helper->submit_action = 'submitDracoSettings';
        $helper->fields_value = [
            'DRACO_SHIELD' => Settings::get(Settings::SHIELD) === '1',
            Settings::WAF_MODE => Settings::mode(Settings::WAF_MODE),
            Settings::PACE_MODE => Settings::mode(Settings::PACE_MODE),
            Settings::RATE_IP => Settings::get(Settings::RATE_IP) ?: '120',
            Settings::RATE_NET => Settings::get(Settings::RATE_NET) ?: '600',
            Settings::PROXY => Settings::get(Settings::PROXY),
            Settings::TRUSTED => Settings::get(Settings::TRUSTED),
            Settings::GEO_MODE => Settings::get(Settings::GEO_MODE) ?: 'off',
            Settings::GEO_SCOPE => Settings::get(Settings::GEO_SCOPE) ?: 'sensitive',
            Settings::GEO_ACTION => Settings::get(Settings::GEO_ACTION) ?: 'log',
            Settings::GEO_COUNTRIES => Settings::get(Settings::GEO_COUNTRIES),
            Settings::HEADERS => Settings::get(Settings::HEADERS) === '1',
            Settings::HSTS => Settings::get(Settings::HSTS) === '1',
            Settings::NETS => Settings::get(Settings::NETS),
        ];

        return $helper->generateForm([$fields]);
    }

    private function blocks(): string
    {
        $rows = Store::activeBlocks();
        $html = '<div class="panel"><h3><i class="icon-ban"></i> ' . self::h($this->t('Blocked addresses')) . ' (' . count($rows) . ')</h3>';
        $days = ['7' => $this->t('7 days'), '15' => $this->t('15 days'), '30' => $this->t('30 days'), '90' => $this->t('90 days'), '0' => $this->t('Forever')];
        $html .= '<form method="post" action="' . self::h($this->url()) . '" class="form-inline" style="margin-bottom:15px">'
            . '<input type="text" name="draco_block_value" class="form-control" required placeholder="' . self::h($this->t('IP or range (e.g. 203.0.113.0/24)')) . '" aria-label="' . self::h($this->t('IP or range (e.g. 203.0.113.0/24)')) . '"> '
            . '<select name="draco_block_days" class="form-control" aria-label="' . self::h($this->t('For')) . '">';
        foreach ($days as $value => $label) {
            $html .= '<option value="' . $value . '"' . ($value === '30' ? ' selected' : '') . '>' . self::h($label) . '</option>';
        }
        $html .= '</select> <input type="text" name="draco_block_reason" class="form-control" placeholder="' . self::h($this->t('Reason')) . '" aria-label="' . self::h($this->t('Reason')) . '"> '
            . '<button class="btn btn-default" name="draco_block" value="1">' . self::h($this->t('Block')) . '</button>'
            . '<p class="help-block">' . self::h($this->t('Never an employee, nor your own address. Ranges no wider than /16 (IPv4) or /32 (IPv6).')) . '</p></form>';
        if ($rows === []) {
            return $html . '<p>' . self::h($this->t('Nothing blocked right now.')) . '</p></div>';
        }
        $html .= '<table class="table"><thead><tr><th>' . self::h($this->t('Address or e-mail')) . '</th><th>' . self::h($this->t('Reason')) . '</th><th>' . self::h($this->t('Until (UTC)')) . '</th><th></th></tr></thead><tbody>';
        foreach ($rows as $row) {
            $html .= '<tr><td><code>' . self::h((string) $row['value']) . '</code></td><td>' . self::h((string) $row['reason']) . '</td><td>' . self::h(\DracoInsomnis\Core\Blocklist::isForever((string) $row['until_at']) ? $this->t('Forever') : (string) $row['until_at']) . '</td>'
                . '<td class="text-right"><form method="post" action="' . self::h($this->url()) . '" style="margin:0"><button class="btn btn-default btn-sm" name="draco_unblock" value="' . (int) $row['id_block'] . '">' . self::h($this->t('Unblock')) . '</button></form></td></tr>';
        }

        return $html . '</tbody></table></div>';
    }

    private function events(): string
    {
        $rows = Store::recent(50);
        $html = '<div class="panel"><h3><i class="icon-list"></i> ' . self::h($this->t('Last suspicious attempts')) . '</h3>'
            . '<p class="help-block">' . self::h($this->t('Kept for 90 days. Never passwords. The CSV of an address holds everything it did, ready to attach to an abuse report to its network provider.')) . '</p>';
        if ($rows === []) {
            return $html . '<p>' . self::h($this->t('Nothing yet.')) . '</p></div>';
        }
        $html .= '<table class="table"><thead><tr><th>' . self::h($this->t('Date (UTC)')) . '</th><th>' . self::h($this->t('Address')) . '</th><th>' . self::h($this->t('Where')) . '</th><th>' . self::h($this->t('Verdict')) . '</th><th>' . self::h($this->t('Signs')) . '</th><th>' . self::h($this->t('Data')) . '</th><th></th></tr></thead><tbody>';
        foreach ($rows as $row) {
            $fields = json_decode((string) $row['fields'], true);
            $data = is_array($fields) ? implode(' · ', array_filter(array_map('strval', $fields))) : '';
            $html .= '<tr><td>' . self::h((string) $row['created_at']) . '</td><td><code>' . self::h((string) $row['ip']) . '</code></td><td>' . self::h((string) $row['endpoint']) . '</td>'
                . '<td><span class="badge ' . ($row['verdict'] === 'bot' ? 'badge-danger' : 'badge-warning') . '">' . self::h((string) $row['verdict']) . '</span></td>'
                . '<td><small>' . self::h(str_replace(',', ', ', (string) $row['reasons'])) . '</small></td><td><small>' . self::h($data) . '</small></td>'
                . '<td class="text-right"><a class="btn btn-default btn-sm" href="' . self::h($this->url(['draco_csv' => (string) $row['ip']])) . '">CSV</a></td></tr>';
        }

        return $html . '</tbody></table></div>';
    }

    /** Everything one address did, for an abuse report. */
    private function csv(string $ip): void
    {
        $rows = Store::byIp($ip);
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="draco-evidence-' . str_replace(':', '-', $ip) . '.csv"');
        $out = fopen('php://output', 'w');
        fputcsv($out, ['created_at_utc', 'ip', 'remote_addr', 'endpoint', 'verdict', 'score', 'reasons', 'user_agent', 'fields'], ',', '"', '\\');
        foreach ($rows as $row) {
            fputcsv($out, [$row['created_at'], $row['ip'], $row['remote_addr'], $row['endpoint'], $row['verdict'], $row['score'], $row['reasons'], $row['user_agent'], $row['fields']], ',', '"', '\\');
        }
        fclose($out);
        exit;
    }
}
