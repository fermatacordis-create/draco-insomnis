<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Rules;

use Closure;
use DracoInsomnis\Core\Passwords;
use DracoInsomnis\Laravel\LaravelHost;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * The password rules of config/draco.php (pwd_min, pwd_breached) as a validation rule:
 *   'password' => ['required', 'confirmed', new DracoPassword()]   or   'password' => 'draco_password'
 * Nothing is refused while both rules are off.
 */
final class DracoPassword implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $problem = is_string($value) ? Passwords::problem(new LaravelHost(), $value) : '';
        if ($problem !== '') {
            $fail($problem);
        }
    }
}
