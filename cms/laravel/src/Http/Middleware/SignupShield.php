<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Http\Middleware;

use Closure;
use DracoInsomnis\Core\Shield;
use DracoInsomnis\Laravel\Guard;
use DracoInsomnis\Laravel\LaravelHost;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Put it on the registration route ('draco.signup') and @dracoFields inside its form. A sign-up that
 * looks like a bot gets an ordinary validation error after a short wait, and the account is never
 * created. The endpoint name in the evidence can be given: 'draco.signup:newsletter'.
 */
final class SignupShield
{
    public function handle(Request $request, Closure $next, string $endpoint = 'laravel_register'): Response
    {
        if (!config('draco.shield') || $request->getMethod() !== 'POST' || $request->user() !== null) {
            return $next($request);
        }
        $fields = (array) config('draco.signup_fields', []);
        $username = (string) $request->input($fields['username'] ?? 'name', '');
        $emailField = (string) ($fields['email'] ?? 'email');
        $shield = new Shield(Guard::host());
        $result = $shield->judge(LaravelHost::request($request), substr($endpoint, 0, 40), [
            'username' => substr(strip_tags($username), 0, 120),
            'email' => substr(strip_tags((string) $request->input($emailField, '')), 0, 190),
            'role' => '',
        ], null, time());
        if ($result['verdict'] === 'bot') {
            $shield->slowDown();
            throw ValidationException::withMessages([$emailField => (string) __('draco::messages.rejected')]);
        }

        return $next($request);
    }
}
