<?php

declare(strict_types=1);

namespace DracoInsomnis\Shield;

use DracoInsomnis\Core\EventStore;

defined('ABSPATH') || exit;

/** The engines' evidence and block list, in WordPress's own tables (see Store). */
final class Events implements EventStore
{
    public function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void
    {
        Store::log($ip, $remoteAddr, $endpoint, $result, $userAgent, $fields);
    }

    public function botAttemptsSince(string $ip, int $seconds): int
    {
        return Store::botAttemptsSince($ip, $seconds);
    }

    public function isBlocked(string $email, string $ip): bool
    {
        return Store::isBlocked($email, $ip);
    }

    public function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool
    {
        return Store::block($kind, $value, $days, $reason, $automatic);
    }
}
