<?php

declare(strict_types=1);

namespace DracoInsomnis\Server;

/**
 * /etc/draco-insomnis/draco.ini (or DRACO_CONFIG): global settings, and [site:<host>] sections that
 * override them for one host name ("example.com" also matches "www.example.com").
 */
final class Config
{
    public const FILE = '/etc/draco-insomnis/draco.ini';
    public const STATE = '/var/lib/draco-insomnis';

    /** Defaults: everything that blocks is off or in "log" until the owner decides. */
    public const DEFAULTS = [
        'waf_mode' => 'log',
        'pace_mode' => 'off',
        'anticopy_rate_ip' => '120',
        'anticopy_rate_net' => '600',
        'proxy_header' => '',
        'trusted_proxies' => '',
        'hosting_nets' => '',
        'geo_mode' => 'off',
        'geo_countries' => '',
        'geo_scope' => 'sensitive',
        'geo_action' => 'log',
        'geo_file' => '',
        'headers' => '0',
        'hsts' => '0',
        'admin_ips' => '',
        'notify' => '',
        'lang' => 'en',
        'except' => '',
        'sensitive' => '/wp-login.php, /login, /register, /signup, /user/login, /user/register, /login/index.php, /login/signup.php, /administrator/index.php, /Special:UserLogin, /Special:CreateAccount, /typo3/, /admin, /customer/account/login, /customer/account/create',
        'state_dir' => self::STATE,
    ];

    /** @var array<string, array<string, string>>|null */
    private static ?array $parsed = null;
    private static string $parsedFile = '';

    public static function file(): string
    {
        $env = getenv('DRACO_CONFIG');

        return is_string($env) && $env !== '' ? $env : self::FILE;
    }

    /** Settings for one host name: defaults, then the global part, then its [site:…] section. @return array<string, string> */
    public static function forHost(string $host): array
    {
        $all = self::load();
        $values = array_merge(self::DEFAULTS, $all['*'] ?? []);
        $host = strtolower(preg_replace('/:\d+$/', '', $host) ?? '');
        foreach ($all as $section => $site) {
            if ($section === '*' || $host === '') {
                continue;
            }
            if ($host === $section || str_ends_with($host, '.' . $section)) {
                $values = array_merge($values, $site);
            }
        }

        return $values;
    }

    /** @return array<string, array<string, string>> '*' = global part, else host name => settings */
    public static function load(): array
    {
        $file = self::file();
        if (self::$parsed !== null && self::$parsedFile === $file) {
            return self::$parsed;
        }
        $raw = is_readable($file) ? @parse_ini_file($file, true, INI_SCANNER_RAW) : false;
        $out = ['*' => []];
        foreach (is_array($raw) ? $raw : [] as $key => $value) {
            if (is_array($value)) {
                if (str_starts_with((string) $key, 'site:')) {
                    $out[strtolower(trim(substr((string) $key, 5)))] = self::flat($value);
                } else {
                    // Any other [section] is part of the global settings (e.g. [firewall], [geo]).
                    $out['*'] = array_merge($out['*'], self::flat($value));
                }
            } else {
                $out['*'][(string) $key] = trim((string) $value);
            }
        }
        self::$parsed = $out;
        self::$parsedFile = $file;

        return $out;
    }

    /** @param array<mixed> $values @return array<string, string> */
    private static function flat(array $values): array
    {
        $out = [];
        foreach ($values as $k => $v) {
            $out[(string) $k] = is_array($v) ? implode(', ', array_map('strval', $v)) : trim((string) $v);
        }

        return $out;
    }

    /** "a, b\nc" → ['a', 'b', 'c'] @return list<string> */
    public static function list(string $value): array
    {
        return array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', $value) ?: []), static fn ($v) => $v !== ''));
    }

    /**
     * Changes one key of the global part in the file, keeping the rest as written. Returns false when
     * the file cannot be written.
     */
    public static function set(string $key, string $value, string $site = ''): bool
    {
        if (!preg_match('/^[a-z_]+$/', $key) || ($site !== '' && !preg_match('/^[a-z0-9.-]+$/', $site))) {
            return false;
        }
        $file = self::file();
        $lines = is_readable($file) ? (file($file, FILE_IGNORE_NEW_LINES) ?: []) : [];
        $line = $key . ' = "' . str_replace(['"', "\n", "\r"], ['', ' ', ' '], $value) . '"';
        $want = $site === '' ? '' : 'site:' . $site;
        $section = '';
        $insertAt = null;
        foreach ($lines as $i => $text) {
            if (preg_match('/^\s*\[([^\]]+)\]/', $text, $m)) {
                if ($section === $want && $insertAt === null) {
                    $insertAt = $i;
                }
                $section = trim($m[1]);
                continue;
            }
            $inScope = $want === '' ? !str_starts_with($section, 'site:') : $section === $want;
            if ($inScope && preg_match('/^\s*;?\s*' . preg_quote($key, '/') . '\s*=/', $text)) {
                $lines[$i] = $line;
                self::$parsed = null;

                return file_put_contents($file, implode("\n", $lines) . "\n") !== false;
            }
        }
        if ($want !== '' && $section !== $want && !in_array('[' . $want . ']', array_map('trim', $lines), true)) {
            $lines[] = '';
            $lines[] = '[' . $want . ']';
            $lines[] = $line;
        } elseif ($want === '') {
            // Before the first section, so it stays global.
            $first = null;
            foreach ($lines as $i => $text) {
                if (preg_match('/^\s*\[/', $text)) {
                    $first = $i;
                    break;
                }
            }
            array_splice($lines, $first ?? count($lines), 0, [$line]);
        } else {
            array_splice($lines, $insertAt ?? count($lines), 0, [$line]);
        }
        self::$parsed = null;

        return file_put_contents($file, implode("\n", $lines) . "\n") !== false;
    }
}
