<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel;

use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\Host;
use DracoInsomnis\Core\Request as DracoRequest;
use DracoInsomnis\Core\WafRules;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache as CacheFacade;

/** The engines in core/ (src/Core of the repository), running in Laravel. */
final class LaravelHost implements Host
{
    public const MODES = ['off', 'log', 'block'];

    public static function mode(string $name): string
    {
        $mode = (string) config('draco.' . $name, 'off');

        return in_array($mode, self::MODES, true) ? $mode : 'off';
    }

    /** One visitor request as plain values. The connection address is read as is, not through TrustProxies. */
    public static function request(Request $r): DracoRequest
    {
        $clean = static fn ($value): string => is_string($value) ? trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', strip_tags($value))) : '';
        $method = $r->getMethod();
        $post = [];
        foreach ($r->request->all() as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $post[$name] = $clean($value);
            }
        }
        $uri = (string) $r->server->get('REQUEST_URI', '/');

        return new DracoRequest(
            $method,
            rawurldecode((string) parse_url($uri, PHP_URL_PATH)),
            urldecode((string) parse_url($uri, PHP_URL_QUERY)),
            WafRules::flatten(array_merge($r->query->all(), $method === 'POST' ? $r->request->all() : [])),
            $post,
            $clean($r->headers->get('User-Agent', '')),
            (string) $r->headers->get('User-Agent', ''),
            $clean((string) $r->server->get('REMOTE_ADDR', '')),
            $clean($r->headers->get('CF-Connecting-IP', '')),
            $clean($r->headers->get('X-Forwarded-For', '')),
            $clean((string) filter_var((string) $r->headers->get('Referer', ''), FILTER_SANITIZE_URL)),
        );
    }

    public static function cache(): Cache
    {
        return CacheFacade::store(config('draco.cache_store'));
    }

    /** Derived from APP_KEY: nothing extra to store, and different on every app. */
    public function secret(): string
    {
        return hash('sha256', 'draco-insomnis|' . (string) config('app.key'));
    }

    public function setting(string $name): string
    {
        $value = config('draco.' . $name);
        if ($name === 'geo_file' && (!is_string($value) || $value === '')) {
            return storage_path('app/draco/draco-geo.bin');
        }

        return is_scalar($value) ? (string) $value : '';
    }

    public function adminIps(): array
    {
        $remembered = self::cache()->get('draco_admin_ips', []);

        return array_values(array_unique(array_filter(array_merge(
            (array) config('draco.admin_ips', []),
            is_array($remembered) ? $remembered : []
        ), 'is_string')));
    }

    /** The last ten addresses of users who pass the bypass ability: never blocked, never limited. */
    public function rememberAdminIp(string $ip): void
    {
        $list = self::cache()->get('draco_admin_ips', []);
        $list = is_array($list) ? $list : [];
        if (($list[0] ?? null) === $ip) {
            return;
        }
        self::cache()->forever('draco_admin_ips', array_slice(array_values(array_unique(array_merge([$ip], $list))), 0, 10));
    }

    public function bump(string $key, int $ttl): int
    {
        $cache = self::cache();
        $cache->add($key, 0, $ttl);

        return (int) $cache->increment($key);
    }

    public function recall(string $key): ?string
    {
        $value = self::cache()->get($key);

        return $value === null ? null : (string) $value;
    }

    public function remember(string $key, string $value, int $ttl): void
    {
        self::cache()->put($key, $value, $ttl);
    }

    /** Listeners of DracoFilter can change $event->value. */
    public function filter(string $name, $value, ...$args)
    {
        $event = new DracoFilter($name, $value, $args);
        event($event);

        return $event->value;
    }

    public function text(string $id, int $number): string
    {
        return (string) __('draco::messages.' . ($id === 'waf_block' ? 'waf_block' : 'auto_block'), ['count' => $number]);
    }

    public function events(): EventStore
    {
        return new Store();
    }
}
