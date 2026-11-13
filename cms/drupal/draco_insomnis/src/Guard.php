<?php

declare(strict_types=1);

namespace Drupal\draco_insomnis;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Gatekeeper;
use DracoInsomnis\Core\Review;
use DracoInsomnis\Core\TestProbe;
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
    $request = DrupalHost::request($http);
    $probe = TestProbe::answer($host, (string) $http->headers->get(TestProbe::HEADER, ''), $waf, time());
    if ($probe !== NULL) {
      return new Response('', $probe['status'], [TestProbe::RESULT => $probe['result'], 'Cache-Control' => 'no-store']);
    }
    if (Review::isRequest($request, $http->request->all())) {
      (new Review($host))->accept($request, $http->request->all(), time());
      return self::page((string) t('Request sent'), (string) t('Thank you. The owner of the site will look at it and, if it was a mistake, let you through.'), 'review', '', 200);
    }
    $answer = (new Gatekeeper($host))->decide($request, $waf, DrupalHost::mode('pace_mode'), ['/user/login', '/user/register', '/user/password'], $pace);
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
    $form = (new Review(DrupalHost::get()))->form(DrupalHost::request(\Drupal::request()), $why, time(), [
      'email' => (string) t('Your e-mail'),
      'message' => (string) t('What were you doing?'),
      'button' => (string) t('Ask for a review'),
    ]);
    return self::page((string) t('Request blocked'), (string) t('This request was stopped for security reasons. If you think this is a mistake, tell the owner of the site what you were doing:'), $why, $form, 403);
  }

  private static function page(string $title, string $text, string $why, string $form, int $status): Response {
    return new Response(Firewall::page($title, $text, $why, $form), $status, [
      'Content-Type' => 'text/html; charset=UTF-8',
      'Cache-Control' => 'no-store',
      'X-Robots-Tag' => 'noindex, nofollow',
    ]);
  }

  public static function hasSession(HttpRequest $request): bool {
    foreach (array_keys($request->cookies->all()) as $name) {
      if (str_starts_with((string) $name, 'SESS') || str_starts_with((string) $name, 'SSESS')) {
        return TRUE;
      }
    }
    return FALSE;
  }

}
