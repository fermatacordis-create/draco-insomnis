<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\Host;

foreach (['Host', 'EventStore', 'Request', 'BotScore', 'FormStamp', 'NetList', 'Crawler', 'WafRules', 'Shield', 'Firewall', 'Pace'] as $class) {
    require_once dirname(__DIR__, 2) . '/src/Core/' . $class . '.php';
}

/** A CMS in memory: what any adapter (WordPress, PrestaShop…) must behave like. */
final class MemoryHost implements Host, EventStore
{
    /** @var array<string, string> */
    public array $settings = [];
    /** @var list<string> */
    public array $admins = [];
    /** @var array<string, string> */
    public array $cache = [];
    /** @var list<array<string, mixed>> */
    public array $logged = [];
    /** @var list<array{kind: string, value: string, days: int, reason: string}> */
    public array $blocks = [];
    /** @var array<string, \Closure> */
    public array $filters = [];

    public function secret(): string
    {
        return str_repeat('ab', 32);
    }

    public function setting(string $name): string
    {
        return $this->settings[$name] ?? '';
    }

    public function adminIps(): array
    {
        return $this->admins;
    }

    public function bump(string $key, int $ttl): int
    {
        $this->cache[$key] = (string) ((int) ($this->cache[$key] ?? 0) + 1);

        return (int) $this->cache[$key];
    }

    public function recall(string $key): ?string
    {
        return $this->cache[$key] ?? null;
    }

    public function remember(string $key, string $value, int $ttl): void
    {
        $this->cache[$key] = $value;
    }

    public function filter(string $name, $value, ...$args)
    {
        return isset($this->filters[$name]) ? ($this->filters[$name])($value, ...$args) : $value;
    }

    public function text(string $id, int $number): string
    {
        return $id . ':' . $number;
    }

    public function events(): EventStore
    {
        return $this;
    }

    public function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void
    {
        $this->logged[] = ['ip' => $ip, 'endpoint' => $endpoint, 'verdict' => $result['verdict'], 'reasons' => $result['reasons'], 'fields' => $fields];
    }

    public function botAttemptsSince(string $ip, int $seconds): int
    {
        return count(array_filter($this->logged, static fn (array $row): bool => $row['ip'] === $ip && $row['verdict'] === 'bot'));
    }

    public function isBlocked(string $email, string $ip): bool
    {
        foreach ($this->blocks as $block) {
            if (($block['kind'] === 'ip' && $block['value'] === $ip) || ($block['kind'] === 'email' && $email !== '' && $block['value'] === strtolower($email))) {
                return true;
            }
        }

        return false;
    }

    public function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool
    {
        if ($kind === 'ip' && in_array($value, $this->admins, true)) {
            return false;
        }
        $this->blocks[] = ['kind' => $kind, 'value' => $value, 'days' => $days, 'reason' => $reason];

        return true;
    }
}
