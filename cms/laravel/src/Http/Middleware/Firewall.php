<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Http\Middleware;

use Closure;
use DracoInsomnis\Laravel\Guard;
use DracoInsomnis\Laravel\LaravelHost;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\Response;

/**
 * Firewall and pace limit, in two places:
 * - "global" (before routing): requests without a session cookie, so unknown paths such as /.env
 *   are inspected too;
 * - "group" (inside the web and api groups): requests with a session, once the user is known.
 *   Users who pass the bypass ability are not inspected; other logged-in users go through the
 *   firewall but never the pace limit.
 */
final class Firewall
{
    public function handle(Request $request, Closure $next, string $stage = 'global'): Response
    {
        $hasSession = $request->cookies->has((string) config('session.cookie'));
        if ($stage === 'global') {
            if (!$hasSession && ($answer = Guard::check($request, true)) !== null) {
                return $answer;
            }

            return $next($request);
        }
        if ($hasSession) {
            $user = $request->user();
            $ability = config('draco.bypass_ability');
            if ($user !== null && $ability && Gate::forUser($user)->allows($ability)) {
                $host = Guard::host();
                $host->rememberAdminIp(LaravelHost::request($request)->via($host));

                return $next($request);
            }
            if (($answer = Guard::check($request, $user === null)) !== null) {
                return $answer;
            }
        }

        return $next($request);
    }
}
