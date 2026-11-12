<?php

declare(strict_types=1);

namespace Drupal\draco_insomnis\EventSubscriber;

use Drupal\draco_insomnis\DrupalHost;
use Drupal\draco_insomnis\Guard;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Requests with a session cookie, once the user is known (authentication runs at 300):
 * - a cookie that logs nobody in is treated like any anonymous request;
 * - users with "bypass draco insomnis firewall" are never inspected;
 * - other logged-in users go through the firewall, but never the pace limit.
 * Also remembers the addresses administrators work from.
 */
final class DracoSubscriber implements EventSubscriberInterface {

  public static function getSubscribedEvents(): array {
    return [KernelEvents::REQUEST => ['onRequest', 290]];
  }

  public function onRequest(RequestEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    $request = $event->getRequest();
    if (!Guard::hasSession($request)) {
      // Already checked by DracoMiddleware.
      return;
    }
    $account = \Drupal::currentUser();
    if ($account->hasPermission('administer site configuration')) {
      DrupalHost::get()->rememberAdminIp(DrupalHost::request($request)->via(DrupalHost::get()));
    }
    if ($account->hasPermission('bypass draco insomnis firewall')) {
      return;
    }
    $answer = Guard::check($request, $account->isAnonymous());
    if ($answer !== NULL) {
      $event->setResponse($answer);
    }
  }

}
