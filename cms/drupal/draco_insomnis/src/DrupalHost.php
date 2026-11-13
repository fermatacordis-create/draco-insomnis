<?php

declare(strict_types=1);

namespace Drupal\draco_insomnis;

use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\Host;
use DracoInsomnis\Core\Request;
use DracoInsomnis\Core\WafRules;
use Symfony\Component\HttpFoundation\Request as HttpRequest;

require_once dirname(__DIR__) . '/lib/autoload.php';

/**
 * The engines in lib/Core, running in Drupal.
 */
final class DrupalHost implements Host {

  public const CONFIG = 'draco_insomnis.settings';
  private const MODES = ['off', 'log', 'block'];

  private static ?self $instance = NULL;

  public static function get(): self {
    return self::$instance ??= new self();
  }

  public static function shieldOn(): bool {
    return (bool) \Drupal::config(self::CONFIG)->get('shield');
  }

  public static function mode(string $key): string {
    $mode = (string) \Drupal::config(self::CONFIG)->get($key);
    return in_array($mode, self::MODES, TRUE) ? $mode : 'off';
  }

  /**
   * One visitor request as plain values.
   */
  public static function request(HttpRequest $r): Request {
    $clean = static fn ($value): string => is_string($value) ? trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', strip_tags($value))) : '';
    $method = $r->getMethod();
    $post = [];
    foreach ($r->request->all() as $name => $value) {
      if (is_string($name) && is_string($value)) {
        $post[$name] = $clean($value);
      }
    }
    $uri = (string) $r->server->get('REQUEST_URI', '/');

    return new Request(
      $method,
      rawurldecode((string) parse_url($uri, PHP_URL_PATH)),
      urldecode((string) parse_url($uri, PHP_URL_QUERY)),
      WafRules::flatten(array_merge($r->query->all(), $method === 'POST' ? $r->request->all() : [])),
      $post,
      $clean($r->headers->get('User-Agent', '')),
      (string) $r->headers->get('User-Agent', ''),
      $clean($r->server->get('REMOTE_ADDR', '')),
      $clean($r->headers->get('CF-Connecting-IP', '')),
      $clean($r->headers->get('X-Forwarded-For', '')),
      $clean((string) filter_var((string) $r->headers->get('Referer', ''), FILTER_SANITIZE_URL)),
    );
  }

  public function secret(): string {
    $state = \Drupal::state();
    $secret = (string) $state->get('draco_insomnis.secret', '');
    if (strlen($secret) !== 64) {
      $secret = bin2hex(random_bytes(32));
      $state->set('draco_insomnis.secret', $secret);
    }
    return $secret;
  }

  public function setting(string $name): string {
    $value = \Drupal::config(self::CONFIG)->get($name);
    if ($name === 'geo_file' && (!is_string($value) || $value === '')) {
      return self::geoFile();
    }
    return is_scalar($value) ? (string) $value : '';
  }

  /** The country list lives in the public files folder: it is public data, refreshed monthly. */
  public static function geoFile(): string {
    $dir = (string) \Drupal::service('file_system')->realpath('public://');
    return ($dir !== '' ? $dir : sys_get_temp_dir()) . '/draco_insomnis/draco-geo.bin';
  }

  public function adminIps(): array {
    $list = \Drupal::state()->get('draco_insomnis.admin_ips', []);
    $list = is_array($list) ? array_values(array_filter($list, 'is_string')) : [];
    // Plus the addresses a person let through after a review.
    return array_values(array_unique(array_merge($list, Store::activeValues('allow'))));
  }

  /**
   * The last ten addresses administrators worked from: never blocked, never limited.
   */
  public function rememberAdminIp(string $ip): void {
    $list = $this->adminIps();
    if (($list[0] ?? NULL) === $ip) {
      return;
    }
    \Drupal::state()->set('draco_insomnis.admin_ips', array_slice(array_values(array_unique(array_merge([$ip], $list))), 0, 10));
  }

  public function bump(string $key, int $ttl): int {
    return Store::bump($key, $ttl);
  }

  public function recall(string $key): ?string {
    return Store::recall($key);
  }

  public function remember(string $key, string $value, int $ttl): void {
    Store::remember($key, $value, $ttl);
  }

  /**
   * Site code changes values with hook_draco_insomnis_NAME_alter(&$value, $args).
   */
  public function filter(string $name, $value, ...$args) {
    \Drupal::moduleHandler()->alter('draco_insomnis_' . $name, $value, $args);
    return $value;
  }

  public function text(string $id, int $number): string {
    if ($id === 'review_subject') {
      return (string) t('[@site] Someone asks you to review a firewall block', ['@site' => (string) \Drupal::config('system.site')->get('name')]);
    }
    if ($id === 'review_body') {
      return (string) t('A visitor stopped by the firewall asks for a review. Open Draco Insomnis to let them through or not:') . "\n\n"
        // Built from $base_url: this runs in the middleware, before the router knows the site's address.
        . rtrim((string) ($GLOBALS['base_url'] ?? ''), '/') . '/' . \Drupal\Core\Url::fromRoute('draco_insomnis.settings')->getInternalPath();
    }
    if ($id === 'waf_block') {
      return (string) t('Firewall: @count attacks in 10 minutes', ['@count' => $number]);
    }
    return (string) t('Automatic: @count bot attempts in 24 h', ['@count' => $number]);
  }

  public function events(): EventStore {
    return new Store();
  }

  public function notifyOwner(string $subject, string $body): void {
    $to = (string) \Drupal::config('system.site')->get('mail');
    if ($to === '') {
      return;
    }
    try {
      \Drupal::service('plugin.manager.mail')->mail('draco_insomnis', 'notice', $to, \Drupal::languageManager()->getDefaultLanguage()->getId(), ['subject' => $subject, 'body' => $body]);
    }
    catch (\Throwable $e) {
      // A notice that cannot be sent never breaks the visitor's request.
    }
  }

}
