<?php

declare(strict_types=1);

namespace Drupal\draco_insomnis\Form;

use DracoInsomnis\Core\NetList;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\draco_insomnis\DrupalHost;
use Drupal\draco_insomnis\Store;

/**
 * Settings, the block list and the evidence of the last attempts (with a CSV per address).
 */
final class SettingsForm extends ConfigFormBase {

  public function getFormId(): string {
    return 'draco_insomnis_settings';
  }

  protected function getEditableConfigNames(): array {
    return [DrupalHost::CONFIG];
  }

  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config(DrupalHost::CONFIG);
    $request = DrupalHost::request($this->getRequest());
    $modes = [
      'off' => $this->t('Off'),
      'log' => $this->t('Log only: record what it would stop'),
      'block' => $this->t('Block'),
    ];

    $form['intro'] = [
      '#type' => 'container',
      'text' => ['#markup' => '<p><em>Ab insomni custodita dracone.</em> ' . $this->t('Stops fake sign-ups without captchas: bots get no account, and every suspicious attempt is kept for 90 days as evidence for an abuse report. Nothing is ever sent back to the attacker.') . '</p>'],
      'ip' => [
        '#markup' => '<p>' . $this->t('Your address as the module sees it: %ip (connection address: %remote). If the site is behind Cloudflare or another proxy and these differ from your real address, choose the matching option in "Visitor address".', [
          '%ip' => $request->ip((string) $config->get('proxy_header'), (string) $config->get('trusted_proxies')),
          '%remote' => $request->remote(),
        ]) . '</p>',
      ],
    ];
    if ($request->proxyHeaderIgnored((string) $config->get('proxy_header'), (string) $config->get('trusted_proxies'))) {
      $form['intro']['ignored'] = [
        '#markup' => '<p class="messages messages--warning">' . $this->t('The header is ignored: this connection (%remote) does not come from Cloudflare or from a trusted proxy. If your proxy is on the internet, add its addresses in "Trusted proxies".', ['%remote' => $request->remote()]) . '</p>',
      ];
    }
    $form['shield'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Protect user sign-ups'),
      '#description' => $this->t('Adds an invisible trap and a signed page stamp to the public sign-up form. Bots get no account; three bot attempts in a day block the address for a week.'),
      '#default_value' => (bool) $config->get('shield'),
    ];
    $form['waf_mode'] = [
      '#type' => 'select',
      '#title' => $this->t('Firewall'),
      '#options' => $modes,
      '#default_value' => DrupalHost::mode('waf_mode'),
      '#description' => $this->t('Stops requests with the shape of an attack (database injection, reading server files, running code, scripts in links) and scanners such as sqlmap or Nikto. Start with "Log only" and move to "Block" after a few days. Five attacks in 10 minutes block the address for a week; blocked addresses can still read the site, but not post or log in. Users with the "Bypass the Draco Insomnis firewall" permission are never inspected. Emergency exit: $settings[\'draco_waf_off\'] = TRUE; in settings.php.'),
    ];
    $form['pace_mode'] = [
      '#type' => 'select',
      '#title' => $this->t('Anti-copy pace limit'),
      '#options' => $modes,
      '#default_value' => DrupalHost::mode('pace_mode'),
      '#description' => $this->t('More pages per minute than a person reads get "429 Too many requests" until the minute ends. Logged-in users, your own addresses and search engines verified by DNS (Google, Bing, Apple, Yandex) are never limited.'),
    ];
    $form['anticopy_rate_ip'] = [
      '#type' => 'number',
      '#title' => $this->t('Pages per minute, per address'),
      '#min' => 10,
      '#default_value' => (int) ($config->get('anticopy_rate_ip') ?: 120),
    ];
    $form['anticopy_rate_net'] = [
      '#type' => 'number',
      '#title' => $this->t('Pages per minute, per network'),
      '#min' => 10,
      '#default_value' => (int) ($config->get('anticopy_rate_net') ?: 600),
      '#description' => $this->t('A /24 network for IPv4 or a /64 for IPv6: what a scraper gets when it rotates addresses next to each other.'),
    ];
    $form['proxy_header'] = [
      '#type' => 'select',
      '#title' => $this->t('Visitor address'),
      '#options' => [
        '' => $this->t('Connection address (recommended)'),
        'cf' => $this->t('Cloudflare (CF-Connecting-IP)'),
        'xff' => $this->t('Other proxy (X-Forwarded-For)'),
      ],
      '#default_value' => (string) $config->get('proxy_header'),
      '#description' => $this->t('Leave "Connection address" unless the site is behind a proxy: a header can be forged by anyone.'),
    ];
    $form['trusted_proxies'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Trusted proxies'),
      '#rows' => 2,
      '#default_value' => (string) $config->get('trusted_proxies'),
      '#description' => $this->t("Only connections from these addresses may set the visitor address through a header. One address or range per line. Empty: this server and private networks. Cloudflare's own ranges are already known."),
    ];
    $built = \DracoInsomnis\Core\Geo::built(DrupalHost::get()->setting('geo_file'));
    $form['geo'] = [
      '#type' => 'details',
      '#title' => $this->t('Countries'),
      '#open' => (string) $config->get('geo_mode') !== '' && (string) $config->get('geo_mode') !== 'off',
      'help' => ['#markup' => '<p>' . $this->t('Most of your visitors may come from many countries, and an attacker changes country with a VPN. Filter only logging in, signing up and forms, and start with "Log only". Administrators, people you let through and search engines are never filtered.') . '</p>'],
      'geo_mode' => [
        '#type' => 'select',
        '#title' => $this->t('Filter'),
        '#options' => ['off' => $this->t('Off'), 'block' => $this->t('Refuse the countries listed'), 'allow' => $this->t('Only the countries listed')],
        '#default_value' => (string) ($config->get('geo_mode') ?: 'off'),
      ],
      'geo_scope' => [
        '#type' => 'select',
        '#title' => $this->t('Where'),
        '#options' => ['sensitive' => $this->t('Logging in, signing up and forms (recommended)'), 'site' => $this->t('The whole site')],
        '#default_value' => (string) ($config->get('geo_scope') ?: 'sensitive'),
      ],
      'geo_action' => [
        '#type' => 'select',
        '#title' => $this->t('What to do'),
        '#options' => ['log' => $this->t('Log only'), 'block' => $this->t('Block')],
        '#default_value' => (string) ($config->get('geo_action') ?: 'log'),
      ],
      'geo_countries' => [
        '#type' => 'textfield',
        '#title' => $this->t('Countries (two-letter codes, e.g. ES, FR, DE)'),
        '#default_value' => (string) $config->get('geo_countries'),
      ],
      'status' => ['#markup' => '<p>' . ($built === '' ? $this->t('Country list: not downloaded yet (it is downloaded when you switch the filter on).') : $this->t('Country list of @date.', ['@date' => substr($built, 0, 4) . '-' . substr($built, 4, 2) . '-' . substr($built, 6, 2)])) . ' ' . $this->t('IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a> (CC BY 4.0). Looked up on your own server: no address is sent anywhere.') . '</p>'],
    ];
    $form['headers'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Send security headers on public pages'),
      '#description' => $this->t('No sniffing of file types, no framing by other sites, less referrer data, no camera, microphone or location for embedded content. Never one the server already sends.'),
      '#default_value' => (bool) $config->get('headers'),
    ];
    $form['hsts'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Force HTTPS in browsers for 6 months (HSTS)'),
      '#description' => $this->t('Only when the whole site works on HTTPS and will keep working: browsers remember it and refuse plain HTTP until it expires.'),
      '#default_value' => (bool) $config->get('hsts'),
    ];
    $form['pwd_min'] = [
      '#type' => 'number',
      '#title' => $this->t('Minimum password length'),
      '#min' => 0,
      '#max' => 64,
      '#default_value' => (int) $config->get('pwd_min'),
      '#description' => $this->t('From 8 to 64 characters; 0 = no minimum. Applied when an account is created or a password is changed.'),
    ];
    $form['pwd_breached'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Refuse passwords found in data breaches'),
      '#description' => $this->t('Asks Have I Been Pwned with k-anonymity: only 5 characters of the password’s SHA-1 leave the site, never the password. If the service does not answer in 3 seconds, the password is accepted.'),
      '#default_value' => (bool) $config->get('pwd_breached'),
    ];
    $form['block_add'] = [
      '#type' => 'details',
      '#title' => $this->t('Block an address or range'),
      'block_value' => ['#type' => 'textfield', '#title' => $this->t('IP or range (e.g. 203.0.113.0/24)'), '#description' => $this->t('Never an administrator, nor your own address. Ranges no wider than /16 (IPv4) or /32 (IPv6).')],
      'block_days' => ['#type' => 'select', '#title' => $this->t('For'), '#options' => [7 => $this->t('7 days'), 15 => $this->t('15 days'), 30 => $this->t('30 days'), 90 => $this->t('90 days'), 0 => $this->t('Forever')], '#default_value' => 30],
      'block_reason' => ['#type' => 'textfield', '#title' => $this->t('Reason'), '#maxlength' => 190],
    ];
    $form['hosting_nets'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Rented-server networks'),
      '#rows' => 4,
      '#default_value' => (string) $config->get('hosting_nets'),
      '#description' => $this->t('One range per line (CIDR), added to the ones the module already knows. Being on this list only adds points: on its own it never makes anyone a bot.'),
    ];

    $form = parent::buildForm($form, $form_state);
    $form['summary'] = $this->summary() + ['#weight' => 190];
    $form['reviews'] = $this->reviewsTable() + ['#weight' => 195];
    $form['blocks'] = $this->blocksTable() + ['#weight' => 200];
    $form['events'] = $this->eventsTable() + ['#weight' => 210];
    return $form;
  }

  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $mode = static fn ($value): string => in_array($value, ['off', 'log', 'block'], TRUE) ? $value : 'off';
    $rate = static fn ($value, int $default): int => (int) $value >= 10 ? (int) $value : $default;
    $proxy = (string) $form_state->getValue('proxy_header');
    $this->config(DrupalHost::CONFIG)
      ->set('shield', (bool) $form_state->getValue('shield'))
      ->set('waf_mode', $mode($form_state->getValue('waf_mode')))
      ->set('pace_mode', $mode($form_state->getValue('pace_mode')))
      ->set('anticopy_rate_ip', $rate($form_state->getValue('anticopy_rate_ip'), 120))
      ->set('anticopy_rate_net', $rate($form_state->getValue('anticopy_rate_net'), 600))
      ->set('proxy_header', in_array($proxy, ['', 'cf', 'xff'], TRUE) ? $proxy : '')
      ->set('trusted_proxies', implode("\n", NetList::parse((string) $form_state->getValue('trusted_proxies'))))
      ->set('geo_mode', in_array($form_state->getValue('geo_mode'), ['block', 'allow'], TRUE) ? (string) $form_state->getValue('geo_mode') : 'off')
      ->set('geo_scope', $form_state->getValue('geo_scope') === 'site' ? 'site' : 'sensitive')
      ->set('geo_action', $form_state->getValue('geo_action') === 'block' ? 'block' : 'log')
      ->set('geo_countries', implode(', ', \DracoInsomnis\Core\Geo::parseList((string) $form_state->getValue('geo_countries'))))
      ->set('headers', (bool) $form_state->getValue('headers'))
      ->set('hsts', (bool) $form_state->getValue('hsts'))
      ->set('pwd_min', max(0, min(64, (int) $form_state->getValue('pwd_min'))))
      ->set('pwd_breached', (bool) $form_state->getValue('pwd_breached'))
      ->set('hosting_nets', implode("\n", NetList::parse((string) $form_state->getValue('hosting_nets'))))
      ->save();
    parent::submitForm($form, $form_state);
    $host = DrupalHost::get();
    if ($host->setting('geo_mode') !== 'off' && \DracoInsomnis\Core\Geo::built($host->setting('geo_file')) === '') {
      $error = \DracoInsomnis\Core\GeoUpdate::update($host->setting('geo_file'));
      $this->messenger()->{$error === '' ? 'addStatus' : 'addError'}($error === '' ? $this->t('Country list downloaded.') : $this->t('The country list could not be downloaded. The filter does nothing until it is there; try again later.'));
    }
    $value = trim((string) $form_state->getValue('block_value'));
    if ($value !== '') {
      $done = (new Store())->block('ip', $value, (int) $form_state->getValue('block_days'), (string) $form_state->getValue('block_reason'));
      $done ? $this->messenger()->addStatus($this->t('Blocked: @value', ['@value' => $value])) : $this->messenger()->addError($this->t('Nothing was blocked: the value is not valid, belongs to an administrator, or is your own address.'));
    }
  }

  private function summary(): array {
    $sum = \DracoInsomnis\Core\Summary::waf(Store::wafRows(7 * 86400));
    $items = [];
    foreach ($sum['rules'] as $rule => $n) {
      $items[] = str_replace('waf_', '', $rule) . ': ' . $n;
    }
    $ips = [];
    foreach ($sum['ips'] as $ip => $n) {
      $ips[] = $ip . ': ' . $n;
    }
    return [
      '#type' => 'details',
      '#title' => $this->t('Firewall: last 7 days'),
      '#open' => TRUE,
      'line' => ['#markup' => '<p>' . $this->t('@total attacks seen, @blocked blocked.', ['@total' => $sum['total'], '@blocked' => $sum['blocked']]) . '</p>'],
      'rules' => ['#theme' => 'item_list', '#title' => $this->t('What'), '#items' => $items],
      'ips' => ['#theme' => 'item_list', '#title' => $this->t('Busiest addresses'), '#items' => $ips],
      'test' => [
        '#type' => 'link',
        '#title' => $this->t('Test the firewall'),
        '#url' => Url::fromRoute('draco_insomnis.test'),
        '#attributes' => ['class' => ['button']],
        '#suffix' => '<p class="description">' . $this->t('Sends a harmless attack-shaped request to the site and tells you what happened. It is not logged.') . '</p>',
      ],
    ];
  }

  private function reviewsTable(): array {
    $rows = [];
    $states = ['approved' => $this->t('Let through'), 'denied' => $this->t('Denied'), 'attacker' => $this->t('Attacker: blocked')];
    foreach (Store::reviews(50) as $row) {
      $fields = json_decode((string) $row['fields'], TRUE);
      $actions = $states[(string) $row['verdict']] ?? '';
      if ($row['verdict'] === 'pending') {
        $link = fn (string $title, string $decision, int $days = 0): array => ['#type' => 'link', '#title' => $title, '#url' => Url::fromRoute('draco_insomnis.review', ['id' => $row['id'], 'decision' => $decision, 'days' => $days]), '#suffix' => ' '];
        $actions = ['data' => [
          $link((string) $this->t('Let through 24 hours'), 'approve', 1),
          $link((string) $this->t('7 days'), 'approve', 7),
          $link((string) $this->t('30 days'), 'approve', 30),
          $link((string) $this->t('Forever'), 'approve', 0),
          $link((string) $this->t('Deny'), 'deny'),
          $link((string) $this->t('Attacker'), 'attacker'),
        ]];
      }
      $rows[] = [$row['created_at'], $row['ip'], is_array($fields) ? (string) ($fields['email'] ?? '') : '', is_array($fields) ? (string) ($fields['referer'] ?? '') : '', $actions];
    }
    return [
      '#type' => 'details',
      '#title' => $this->t('Review requests'),
      '#open' => TRUE,
      '#attributes' => ['id' => 'draco-reviews'],
      'help' => ['#markup' => '<p>' . $this->t('People the firewall stopped can ask from the block page. Let them through for a while if it was a mistake. Draco never writes to them: answer from your own mail if you want.') . '</p>'],
      'table' => [
        '#type' => 'table',
        '#header' => [$this->t('Date (UTC)'), $this->t('Address'), $this->t('E-mail'), $this->t('Message'), ''],
        '#rows' => $rows,
        '#empty' => $this->t('No requests.'),
      ],
    ];
  }

  private function blocksTable(): array {
    $rows = [];
    foreach (Store::activeBlocks() as $block) {
      $rows[] = [
        $block['value'],
        $block['reason'],
        \DracoInsomnis\Core\Blocklist::isForever((string) $block['until_at']) ? $this->t('Forever') : $block['until_at'],
        ['data' => ['#type' => 'link', '#title' => $this->t('Unblock'), '#url' => Url::fromRoute('draco_insomnis.unblock', ['id' => $block['id']])]],
      ];
    }
    return [
      '#type' => 'details',
      '#title' => $this->t('Blocked addresses (@count)', ['@count' => count($rows)]),
      '#open' => TRUE,
      'table' => [
        '#type' => 'table',
        '#header' => [$this->t('Address or e-mail'), $this->t('Reason'), $this->t('Until (UTC)'), ''],
        '#rows' => $rows,
        '#empty' => $this->t('Nothing blocked right now.'),
      ],
    ];
  }

  private function eventsTable(): array {
    $rows = [];
    foreach (Store::recent(50) as $event) {
      $fields = json_decode((string) $event['fields'], TRUE);
      $rows[] = [
        $event['created_at'],
        $event['ip'],
        $event['endpoint'],
        $event['verdict'],
        str_replace(',', ', ', (string) $event['reasons']),
        is_array($fields) ? implode(' · ', array_filter(array_map('strval', $fields))) : '',
        ['data' => ['#type' => 'link', '#title' => 'CSV', '#url' => Url::fromRoute('draco_insomnis.evidence', ['ip' => $event['ip']])]],
      ];
    }
    return [
      '#type' => 'details',
      '#title' => $this->t('Last suspicious attempts'),
      '#open' => TRUE,
      'help' => ['#markup' => '<p>' . $this->t('Kept for 90 days. Never passwords. The CSV of an address holds everything it did, ready to attach to an abuse report to its network provider.') . '</p>'],
      'table' => [
        '#type' => 'table',
        '#header' => [$this->t('Date (UTC)'), $this->t('Address'), $this->t('Where'), $this->t('Verdict'), $this->t('Signs'), $this->t('Data'), ''],
        '#rows' => $rows,
        '#empty' => $this->t('Nothing yet.'),
      ],
    ];
  }

}
