<?php

declare(strict_types=1);

namespace Drupal\draco_insomnis\StackMiddleware;

use Drupal\draco_insomnis\Guard;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Checks anonymous requests before the page cache, so cached pages are counted and inspected too.
 * Requests with a session go on to DracoSubscriber, which knows who the user is.
 */
final class DracoMiddleware implements HttpKernelInterface {

  public function __construct(private HttpKernelInterface $httpKernel) {
  }

  public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = TRUE): Response {
    if ($type === self::MAIN_REQUEST && !Guard::hasSession($request)) {
      $answer = Guard::check($request, TRUE);
      if ($answer !== NULL) {
        return $answer;
      }
    }
    return $this->httpKernel->handle($request, $type, $catch);
  }

}
