<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel;

use DracoInsomnis\Core\EventStore;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

/**
 * Evidence and block list in the draco_events and draco_blocks tables.
 * Never stores passwords or anything beyond the fields the engines pass.
 */
final class Store implements EventStore
{
    public const KEEP_DAYS = 90;
    public const BLOCK_DAYS = [7, 15, 30, 90];
    /** One flood must not fill the database: past this, attempts from that IP in the hour are only counted. */
    private const MAX_ROWS_PER_IP_HOUR = 30;

    private static function db(): ConnectionInterface
    {
        return DB::connection(config('draco.connection'));
    }

    private static function now(): string
    {
        return gmdate('Y-m-d H:i:s');
    }

    public function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void
    {
        $cache = LaravelHost::cache();
        $key = 'draco_rows_' . md5($ip);
        $cache->add($key, 0, 3600);
        if ((int) $cache->increment($key) > self::MAX_ROWS_PER_IP_HOUR) {
            return;
        }
        self::db()->table('draco_events')->insert([
            'created_at' => self::now(),
            'ip' => $ip,
            'remote_addr' => $remoteAddr,
            'endpoint' => substr($endpoint, 0, 40),
            'score' => min(65535, max(0, (int) $result['score'])),
            'verdict' => (string) $result['verdict'],
            'reasons' => substr(implode(',', $result['reasons']), 0, 190),
            'user_agent' => substr($userAgent, 0, 255),
            'fields' => (string) json_encode($fields, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
    }

    public function botAttemptsSince(string $ip, int $seconds): int
    {
        return self::db()->table('draco_events')->where('ip', $ip)->where('verdict', 'bot')
            ->where('created_at', '>', gmdate('Y-m-d H:i:s', time() - $seconds))->count();
    }

    public function isBlocked(string $email, string $ip): bool
    {
        return self::db()->table('draco_blocks')->where('until_at', '>', self::now())
            ->where(function ($q) use ($email, $ip) {
                $q->where(fn ($w) => $w->where('kind', 'email')->where('value', strtolower($email)))
                    ->orWhere(fn ($w) => $w->where('kind', 'ip')->where('value', strtolower($ip)));
            })->exists();
    }

    /** Never blocks the addresses of exempt users, nor the e-mail of a user who passes the bypass ability. */
    public function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool
    {
        $value = strtolower(trim($value));
        if (!in_array($days, self::BLOCK_DAYS, true)) {
            return false;
        }
        if ($kind === 'ip') {
            if (filter_var($value, FILTER_VALIDATE_IP) === false || in_array($value, (new LaravelHost())->adminIps(), true)) {
                return false;
            }
        } elseif ($kind === 'email') {
            if (filter_var($value, FILTER_VALIDATE_EMAIL) === false || self::exemptEmail($value)) {
                return false;
            }
        } else {
            return false;
        }
        self::db()->table('draco_blocks')->insert([
            'kind' => $kind,
            'value' => $value,
            'reason' => substr($reason, 0, 190),
            'created_at' => self::now(),
            'until_at' => gmdate('Y-m-d H:i:s', time() + $days * 86400),
        ]);

        return true;
    }

    private static function exemptEmail(string $email): bool
    {
        $ability = config('draco.bypass_ability');
        $model = config('auth.providers.users.model');
        if (!$ability || !is_string($model) || !class_exists($model)) {
            return false;
        }
        $user = $model::query()->whereRaw('LOWER(email) = ?', [$email])->first();

        return $user !== null && Gate::forUser($user)->allows($ability);
    }

    public static function unblock(int $id): bool
    {
        return self::db()->table('draco_blocks')->where('id', $id)->delete() > 0;
    }

    /** @return list<object> */
    public static function recent(int $limit = 50): array
    {
        return self::db()->table('draco_events')->orderByDesc('id')->limit($limit)->get()->all();
    }

    /** @return list<object> */
    public static function activeBlocks(): array
    {
        return self::db()->table('draco_blocks')->where('until_at', '>', self::now())->orderByDesc('until_at')->limit(200)->get()->all();
    }

    /** Everything from one address, oldest first, for an abuse report. @return list<object> */
    public static function byIp(string $ip): array
    {
        return self::db()->table('draco_events')->where(fn ($q) => $q->where('ip', $ip)->orWhere('remote_addr', $ip))
            ->orderBy('id')->limit(2000)->get()->all();
    }

    public static function cleanup(): int
    {
        $old = self::db()->table('draco_events')->where('created_at', '<', gmdate('Y-m-d H:i:s', time() - self::KEEP_DAYS * 86400))->delete();
        $done = self::db()->table('draco_blocks')->where('until_at', '<', self::now())->delete();

        return $old + $done;
    }
}
