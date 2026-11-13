<?php

declare(strict_types=1);

namespace Drupal\draco_insomnis;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Gatekeeper;
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
    $waf = Settings::get('draco_waf_off', FALSE) ? 'off' : DrupalHost::mode('waf_mode');
    $answer = (new Gatekeeper($host))->decide(DrupalHost::request($http), $waf, DrupalHost::mode('pace_mode'), ['/user/login', '/user/register', '/user/password'], $pace);
    if ($answer === NULL) {
      return NULL;
    }
    if ($answer['status'] === 429) {
      return new Response('Too many requests. Please wait a minute.', 429, [
        'Retry-After' => (string) $answer['retry'],
        'Content-Type' => 'text/plain; charset=UTF-8',
        'Cache-Control' => 'no-store',
        'X-Robots-Tag' => 'noindex',
      ]);
    }
    return self::deny($answer['why']);
  }

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
