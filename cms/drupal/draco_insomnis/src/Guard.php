<?php

declare(strict_types=1);

namespace Drupal\draco_insomnis;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Pace;
use Drupal\Core\Site\Settings;
use Symfony\Component\HttpFoundation\Request as HttpRequest;
use Symfony\Component\HttpFoundation\Response;

/**
 * Firewall and pace limit for one request. Returns the answer that stops it, or NULL to go on.
 *
 * Emergency exit for the owner: $settings['draco_waf_off'] = TRUE; in settings.php.
 */
final class Guard {

  public static function check(HttpRequest $http, bool $pace): ?Response {
    $host = DrupalHost::get();
    $request = DrupalHost::request($http);

    $waf = DrupalHost::mode('waf_mode');
    if ($waf !== 'off' && !Settings::get('draco_waf_off', FALSE)) {
      $firewall = new Firewall($host, $waf === 'block');
      if (!$firewall->exempt($request)) {
        // Addresses on the block list may read the site, but not post or log in.
        if ($firewall->refusedAsBlocked($request, ['/user/login'])) {
          return self::deny('blocked');
        }
        $rule = $firewall->inspect($request);
        if ($rule !== NULL && $firewall->blocking()) {
          return self::deny($rule);
        }
      }
    }

    $mode = DrupalHost::mode('pace_mode');
    if ($pace && $mode !== 'off') {
      $engine = new Pace($host);
      $count = $engine->count($request, time());
      if ($count['over'] !== '' && !$engine->exempt($request)) {
        $block = $mode === 'block';
        // One line per address and minute is enough evidence; the rest only counts.
        if ($count['first']) {
          $engine->record($request, 'rate_' . $count['over'], $block, $request->path);
        }
        if ($block) {
          return new Response('Too many requests. Please wait a minute.', 429, [
            'Retry-After' => (string) max(1, $count['retry']),
            'Content-Type' => 'text/plain; charset=UTF-8',
            'Cache-Control' => 'no-store',
            'X-Robots-Tag' => 'noindex',
          ]);
        }
      }
    }

    return NULL;
  }

  /**
   * No details for the attacker: what matched stays in the log.
   */
  private static function deny(string $why): Response {
    $page = Firewall::page(
      (string) t('Request blocked'),
      (string) t('This request was stopped for security reasons. If you think this is a mistake, contact the owner of the site.'),
      $why
    );
    return new Response($page, 403, [
      'Content-Type' => 'text/html; charset=UTF-8',
      'Cache-Control' => 'no-store',
      'X-Robots-Tag' => 'noindex, nofollow',
    ]);
  }

  /**
   * Whether the request carries a Drupal session cookie.
   */
  public static function hasSession(HttpRequest $request): bool {
    foreach (array_keys($request->cookies->all()) as $name) {
      if (str_starts_with((string) $name, 'SESS') || str_starts_with((string) $name, 'SSESS')) {
        return TRUE;
      }
    }
    return FALSE;
  }

}
