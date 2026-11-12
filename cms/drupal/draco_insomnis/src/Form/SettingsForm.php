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
          '%ip' => $request->ip((string) $config->get('proxy_header')),
          '%remote' => $request->remote(),
        ]) . '</p>',
      ],
    ];
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
        'xff' => $this->t('Other proxy (first X-Forwarded-For)'),
      ],
      '#default_value' => (string) $config->get('proxy_header'),
      '#description' => $this->t('Leave "Connection address" unless the site is behind a proxy: a header can be forged by anyone.'),
    ];
    $form['hosting_nets'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Rented-server networks'),
      '#rows' => 4,
      '#default_value' => (string) $config->get('hosting_nets'),
      '#description' => $this->t('One range per line (CIDR), added to the ones the module already knows. Being on this list only adds points: on its own it never makes anyone a bot.'),
    ];

    $form = parent::buildForm($form, $form_state);
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
      ->set('hosting_nets', implode("\n", NetList::parse((string) $form_state->getValue('hosting_nets'))))
      ->save();
    parent::submitForm($form, $form_state);
  }

  private function blocksTable(): array {
    $rows = [];
    foreach (Store::activeBlocks() as $block) {
      $rows[] = [
        $block['value'],
        $block['reason'],
        $block['until_at'],
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
