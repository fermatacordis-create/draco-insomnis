<?php

declare(strict_types=1);

namespace DracoInsomnis\Server;

use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\Host;
use DracoInsomnis\Core\Request;
use DracoInsomnis\Core\WafRules;

/**
 * The engines in core/, running before any PHP application on the server (auto_prepend_file).
 * Settings come from draco.ini; evidence, blocks and the secret live in a folder of the PHP user that
 * runs the site (state_dir/u<uid>), so one pool never reads or writes another's.
 */
final class ServerHost implements Host
{
    /** @var array<string, string> */
    private array $settings;
    private string $dir;
    private ?Store $store = null;
    private ?string $secret = null;

    /** @param array<string, string>|null $settings @param string|null $dir The state folder (CLI picks one). */
    public function __construct(?array $settings = null, ?string $dir = null)
    {
        $this->settings = $settings ?? Config::forHost((string) ($_SERVER['HTTP_HOST'] ?? ''));
        $this->dir = $dir ?? self::userDir($this->settings['state_dir'] ?? Config::STATE);
    }

    public static function userDir(string $base): string
    {
        $uid = function_exists('posix_geteuid') ? posix_geteuid() : (int) getmyuid();

        return rtrim($base, '/') . '/u' . $uid;
    }

    /** Creates the state folder on first use (0700). False when it cannot be written: Draco then stays out of the way. */
    public function ready(): bool
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            return false;
        }

        return is_writable($this->dir);
    }

    public function dir(): string
    {
        return $this->dir;
    }

    public function store(): Store
    {
        return $this->store ??= new Store($this->dir . '/draco.sqlite', $this->configuredAdminIps());
    }

    /** One random secret per state folder, made on first use. */
    public function secret(): string
    {
        if ($this->secret !== null) {
            return $this->secret;
        }
        $file = $this->dir . '/secret';
        $value = is_readable($file) ? trim((string) file_get_contents($file)) : '';
        if (!preg_match('/^[a-f0-9]{64}$/', $value)) {
            $value = bin2hex(random_bytes(32));
            $tmp = $file . '.' . getmypid();
            if (@file_put_contents($tmp, $value) !== false) {
                Store::own($tmp);
                // Two first requests at once: the first rename wins and both read the winner.
                if (!is_file($file)) {
                    @rename($tmp, $file);
                }
                @unlink($tmp);
                $stored = is_readable($file) ? trim((string) file_get_contents($file)) : '';
                $value = preg_match('/^[a-f0-9]{64}$/', $stored) ? $stored : $value;
            }
        }

        return $this->secret = $value;
    }

    public function setting(string $name): string
    {
        $value = $this->settings[$name] ?? '';
        if ($name === 'geo_file' && $value === '') {
            // Shared and public data (DB-IP Lite), refreshed monthly by the root timer.
            return rtrim($this->settings['state_dir'] ?? Config::STATE, '/') . '/draco-geo.bin';
        }
        if (in_array($name, ['headers', 'hsts'], true)) {
            return in_array(strtolower($value), ['1', 'yes', 'on', 'true'], true) ? '1' : '';
        }

        return $value;
    }

    public static function mode(string $value): string
    {
        return in_array($value, ['off', 'log', 'block'], true) ? $value : 'off';
    }

    /** @return list<string> */
    private function configuredAdminIps(): array
    {
        return Config::list($this->settings['admin_ips'] ?? '');
    }

    public function adminIps(): array
    {
        // Plus the addresses a person let through after a review.
        return array_values(array_unique(array_merge($this->configuredAdminIps(), $this->store()->activeValues('allow'))));
    }

    public function bump(string $key, int $ttl): int
    {
        if (self::apcu()) {
            $key = $this->apcuKey($key);
            apcu_add($key, 0, $ttl);
            $value = apcu_inc($key);
            if (is_int($value)) {
                return $value;
            }
        }

        return $this->store()->bump($key, $ttl);
    }

    public function recall(string $key): ?string
    {
        if (self::apcu()) {
            $value = apcu_fetch($this->apcuKey($key), $ok);

            return $ok ? (string) $value : null;
        }

        return $this->store()->recall($key);
    }

    public function remember(string $key, string $value, int $ttl): void
    {
        if (self::apcu()) {
            apcu_store($this->apcuKey($key), $value, $ttl);

            return;
        }
        $this->store()->remember($key, $value, $ttl);
    }

    private static function apcu(): bool
    {
        return function_exists('apcu_enabled') && apcu_enabled() && PHP_SAPI !== 'cli';
    }

    private function apcuKey(string $key): string
    {
        return 'draco|' . $this->dir . '|' . $key;
    }

    public function filter(string $name, $value, ...$args)
    {
        return $value;
    }

    public function text(string $id, int $number): string
    {
        return sprintf(Texts::get($this->setting('lang'), $id), $number);
    }

    public function events(): EventStore
    {
        return $this->store();
    }

    public function notifyOwner(string $subject, string $body): void
    {
        $to = trim($this->setting('notify'));
        if ($to === '' || filter_var($to, FILTER_VALIDATE_EMAIL) === false || !function_exists('mail')) {
            return;
        }
        $from = 'draco@' . (preg_replace('/[^a-z0-9.-]/', '', strtolower((string) ($_SERVER['HTTP_HOST'] ?? 'localhost'))) ?: 'localhost');
        @mail($to, $subject, $body, ['From' => $from, 'Content-Type' => 'text/plain; charset=UTF-8']);
    }

    /** This request as plain values. */
    public static function request(): Request
    {
        $clean = static fn ($value): string => is_string($value) ? trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', strip_tags($value))) : '';
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $post = [];
        foreach ($method === 'POST' ? $_POST : [] as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $post[$name] = $clean($value);
            }
        }
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $agent = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');

        return new Request(
            $method,
            rawurldecode((string) parse_url($uri, PHP_URL_PATH)),
            urldecode((string) parse_url($uri, PHP_URL_QUERY)),
            WafRules::flatten(array_merge($_GET, $method === 'POST' ? $_POST : [])),
            $post,
            $clean($agent),
            $agent,
            $clean((string) ($_SERVER['REMOTE_ADDR'] ?? '')),
            $clean((string) ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? '')),
            $clean((string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '')),
            $clean((string) filter_var((string) ($_SERVER['HTTP_REFERER'] ?? ''), FILTER_SANITIZE_URL)),
        );
    }
}
