<?php

declare(strict_types=1);

namespace DracoInsomnis\Server;

use DracoInsomnis\Core\Geo;
use DracoInsomnis\Core\GeoUpdate;
use DracoInsomnis\Core\Summary;
use DracoInsomnis\Core\TestProbe;

/**
 * The "draco" command. Each PHP user that runs sites has its own state folder (u<uid>); commands
 * that act on one take --user=<name> (or the only folder there is).
 */
final class Cli
{
    private const PHP_INI = 'draco-insomnis.ini';

    /** @var array<string, string> */
    private array $opt = [];
    /** @var list<string> */
    private array $args = [];

    /** @param list<string> $argv */
    public static function main(array $argv): int
    {
        $cli = new self();
        foreach (array_slice($argv, 1) as $a) {
            if (preg_match('/^--([a-z-]+)(?:=(.*))?$/', $a, $m)) {
                $cli->opt[$m[1]] = $m[2] ?? '1';
            } else {
                $cli->args[] = $a;
            }
        }
        $cmd = array_shift($cli->args) ?? 'help';
        try {
            return match ($cmd) {
                'status' => $cli->status(),
                'enable' => $cli->enable(true),
                'disable' => $cli->enable(false),
                'set' => $cli->set(),
                'get' => $cli->get(),
                'events' => $cli->events(),
                'evidence' => $cli->evidence(),
                'blocks' => $cli->blocks(),
                'block' => $cli->block(),
                'unblock' => $cli->unblock(),
                'reviews' => $cli->reviews(),
                'test' => $cli->test(),
                'cleanup' => $cli->cleanup(),
                'geo-update' => $cli->geoUpdate(),
                'version' => $cli->out(DRACO_SERVER_VERSION),
                default => $cli->help(),
            };
        } catch (\Throwable $e) {
            fwrite(STDERR, 'draco: ' . $e->getMessage() . "\n");

            return 1;
        }
    }

    private function out(string $text): int
    {
        echo $text, "\n";

        return 0;
    }

    private function fail(string $text): int
    {
        fwrite(STDERR, $text . "\n");

        return 1;
    }

    private function help(): int
    {
        return $this->out(<<<TXT
            Draco Insomnis Server {$this->version()} — a firewall before every PHP site on this server.

              draco status                      What is on, and what was stopped in 7 days, per PHP user
              draco enable | disable            Load Draco in every PHP (FPM, Apache) and reload it
              draco set <key> <value> [--site=example.com]   Change a setting in /etc/draco-insomnis/draco.ini
              draco get [key] [--site=example.com]
              draco events [n]                  Last attempts      draco evidence <ip>   Everything from one address
              draco blocks                      Blocks in force    draco block <ip|range> [7|15|30|90|0] [reason]
              draco unblock <id>
              draco reviews [<id> --approve=1|7|30|0 | --deny | --attacker]
              draco test <url>                  Sends a harmless attack-shaped request and says what happened
              draco cleanup                     Old evidence out; country list refreshed (daily timer)
              draco geo-update                  Downloads the country list (DB-IP Lite, CC BY 4.0)

            Options: --user=<php user> picks whose evidence (default: the only one there is).
            TXT);
    }

    private function version(): string
    {
        return defined('DRACO_SERVER_VERSION') ? DRACO_SERVER_VERSION : '?';
    }

    private function base(): string
    {
        return Config::stateDir(Config::forHost(''));
    }

    /** @return array<string, string> folder => user name */
    private function dirs(): array
    {
        $out = [];
        foreach (glob($this->base() . '/u*', GLOB_ONLYDIR) ?: [] as $dir) {
            $uid = (int) substr(basename($dir), 1);
            $name = function_exists('posix_getpwuid') ? ((posix_getpwuid($uid) ?: [])['name'] ?? (string) $uid) : (string) $uid;
            $out[$dir] = $name;
        }

        return $out;
    }

    private function host(string $site = ''): ServerHost
    {
        $dirs = $this->dirs();
        $want = $this->opt['user'] ?? '';
        if ($want !== '') {
            $dir = array_search($want, $dirs, true);
            if ($dir === false && is_dir($this->base() . '/u' . $want)) {
                $dir = $this->base() . '/u' . $want;
            }
            if ($dir === false) {
                throw new \RuntimeException("No evidence yet for PHP user $want (it appears after the first request Draco sees).");
            }
        } elseif (count($dirs) === 1) {
            $dir = (string) array_key_first($dirs);
        } elseif ($dirs === []) {
            throw new \RuntimeException('No evidence yet: Draco has not seen any web request (is it enabled? draco status).');
        } else {
            throw new \RuntimeException('Several PHP users: say which with --user=' . implode('|', $dirs));
        }

        return new ServerHost(Config::forHost($site), $dir);
    }

    private function status(): int
    {
        $s = Config::forHost('');
        $loaded = $this->phpIniFiles(true);
        echo 'Draco Insomnis Server ', $this->version(), "\n";
        echo 'Loaded in: ', $loaded === [] ? 'nowhere (draco enable)' : implode(', ', $loaded), "\n";
        echo 'Settings: ', Config::file(), (is_readable(Config::file()) ? '' : ' (missing: defaults)'), "\n";
        printf("Firewall: %s · pace limit: %s · country filter: %s · headers: %s\n", $s['waf_mode'], $s['pace_mode'], $s['geo_mode'], $s['headers'] === '1' ? 'on' : 'off');
        $built = Geo::built((new ServerHost($s, $this->base()))->setting('geo_file'));
        echo 'Country list: ', $built === '' ? 'not downloaded' : $built, "\n";
        foreach ($this->dirs() as $dir => $user) {
            $store = (new ServerHost($s, $dir))->store();
            $sum = Summary::waf($store->wafRows(7 * 86400));
            $pending = count(array_filter($store->reviews(200), static fn ($r) => $r['verdict'] === 'pending'));
            $top = implode(', ', array_map(static fn ($ip, $n) => "$ip ($n)", array_keys($sum['ips']), $sum['ips']));
            printf("  %-14s 7 days: %d attacks seen, %d stopped · %d blocks · %d reviews pending%s\n",
                $user, $sum['total'], $sum['blocked'], count($store->activeBlocks()), $pending, $top === '' ? '' : ' · most: ' . $top);
        }

        return 0;
    }

    /** conf.d folders of every PHP that serves web requests. @return list<string> */
    private function confDirs(): array
    {
        $dirs = [];
        foreach (glob('/etc/php/*/{fpm,apache2,cgi}/conf.d', GLOB_ONLYDIR | GLOB_BRACE) ?: [] as $d) {
            $dirs[] = $d;
        }
        // Official Docker images of PHP (and WordPress, Drupal, Joomla, MediaWiki… built on them).
        // The Docker volume mode: the app reads /opt/draco/conf.d through PHP_INI_SCAN_DIR.
        if (is_dir(Config::bundle() . '/conf.d')) {
            $dirs[] = Config::bundle() . '/conf.d';
        }
        $docker = getenv('PHP_INI_DIR');
        if (is_string($docker) && $docker !== '' && is_dir($docker . '/conf.d')) {
            $dirs[] = $docker . '/conf.d';
        }
        foreach (['/etc/php.d', '/etc/opt/remi/*/php.d'] as $pattern) {
            foreach (glob($pattern, GLOB_ONLYDIR) ?: [] as $d) {
                $dirs[] = $d;
            }
        }

        return $dirs;
    }

    /** @return list<string> */
    private function phpIniFiles(bool $existing): array
    {
        $out = [];
        foreach ($this->confDirs() as $d) {
            $f = $d . '/99-' . self::PHP_INI;
            if (!$existing || is_file($f)) {
                $out[] = $f;
            }
        }

        return $out;
    }

    private function enable(bool $on): int
    {
        $guard = dirname(__DIR__) . '/guard.php';
        $files = $this->phpIniFiles(!$on);
        if ($files === []) {
            return $on ? $this->fail('No PHP for the web found (/etc/php/*/fpm, apache2 or cgi). Add to php.ini by hand: auto_prepend_file = ' . $guard) : $this->out('Draco was not loaded anywhere.');
        }
        foreach ($files as $f) {
            if ($on) {
                file_put_contents($f, "; Draco Insomnis Server (draco disable removes this file)\nauto_prepend_file = " . $guard . "\n");
            } else {
                @unlink($f);
            }
            echo ($on ? 'loaded: ' : 'removed: '), $f, "\n";
        }
        $base = $this->base();
        if ($on && !is_dir($base)) {
            mkdir($base, 0755, true);
        }
        // Each PHP user makes its own folder inside, like /tmp: sticky and writable by all.
        if ($on) {
            @chmod($base, 01733);
        }
        $this->reload();
        if ($on) {
            echo "Draco is watching. Firewall in \"log\" until you decide: draco set waf_mode block\n";
            echo "A site that sets its own auto_prepend_file (.user.ini, e.g. another firewall) replaces Draco there.\n";
        }

        return 0;
    }

    private function reload(): void
    {
        if (!is_dir('/run/systemd/system')) {
            // A container: PHP-FPM or Apache is usually process 1.
            $one = (string) @file_get_contents('/proc/1/cmdline');
            if (str_contains($one, 'php-fpm')) {
                exec('kill -USR2 1 2>&1', $o, $code);
                echo $code === 0 ? "reloaded: php-fpm\n" : "Reload PHP-FPM yourself (kill -USR2 1).\n";
            } elseif (str_contains($one, 'apache2') || str_contains($one, 'httpd')) {
                exec('apachectl -k graceful 2>&1', $o, $code);
                echo $code === 0 ? "reloaded: apache\n" : "Reload Apache yourself (apachectl -k graceful).\n";
            } else {
                echo "Reload PHP-FPM and Apache yourself for it to take effect.\n";
            }

            return;
        }
        $units = [];
        exec('systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null', $lines);
        foreach ($lines as $line) {
            $unit = strtok($line, ' ');
            if (is_string($unit) && preg_match('/^(php[0-9.]*-fpm|php-fpm|apache2|httpd)\.service$/', $unit)) {
                $units[] = $unit;
            }
        }
        foreach ($units as $unit) {
            exec('systemctl reload ' . escapeshellarg($unit) . ' 2>&1', $o, $code);
            echo 'reloaded: ', $unit, $code === 0 ? '' : ' (failed: reload it yourself)', "\n";
        }
    }

    private function set(): int
    {
        [$key, $value] = array_pad($this->args, 2, null);
        if ($key === null || $value === null) {
            return $this->fail('draco set <key> <value> [--site=example.com]');
        }
        if (!array_key_exists($key, Config::DEFAULTS)) {
            return $this->fail("Unknown setting $key. Known: " . implode(', ', array_keys(Config::DEFAULTS)));
        }
        if (in_array($key, ['waf_mode', 'pace_mode'], true) && !in_array($value, ['off', 'log', 'block'], true)) {
            return $this->fail("$key is off, log or block");
        }
        if (!Config::set($key, $value, $this->opt['site'] ?? '')) {
            return $this->fail('Could not write ' . Config::file() . ' (run with sudo).');
        }
        if ($key === 'geo_mode' && $value !== 'off') {
            $this->geoUpdate();
        }

        return $this->out("$key = $value" . (isset($this->opt['site']) ? ' for ' . $this->opt['site'] : '') . ' (applies to the next request)');
    }

    private function get(): int
    {
        $s = Config::forHost($this->opt['site'] ?? '');
        $key = $this->args[0] ?? null;
        if ($key !== null) {
            return $this->out($s[$key] ?? '');
        }
        foreach ($s as $k => $v) {
            echo $k, ' = ', $v, "\n";
        }

        return 0;
    }

    /** @param list<array<string, mixed>> $rows @param list<string> $cols */
    private function table(array $rows, array $cols): void
    {
        foreach ($rows as $r) {
            $cells = [];
            foreach ($cols as $c) {
                $v = $r[$c] ?? '';
                if (in_array($c, ['created_at', 'until_at'], true)) {
                    $v = (int) $v >= \DracoInsomnis\Core\Blocklist::FOREVER_TS ? 'forever' : gmdate('Y-m-d H:i', (int) $v);
                }
                $cells[] = (string) $v;
            }
            echo implode("\t", $cells), "\n";
        }
    }

    private function events(): int
    {
        $this->table(array_reverse($this->host()->store()->recent((int) ($this->args[0] ?? 30))), ['id', 'created_at', 'ip', 'host', 'endpoint', 'verdict', 'reasons']);

        return 0;
    }

    private function evidence(): int
    {
        $ip = $this->args[0] ?? '';
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return $this->fail('draco evidence <ip>');
        }
        $this->table($this->host()->store()->byIp($ip), ['created_at', 'ip', 'remote_addr', 'host', 'endpoint', 'verdict', 'reasons', 'user_agent', 'fields']);

        return 0;
    }

    private function blocks(): int
    {
        $this->table($this->host()->store()->activeBlocks(), ['id', 'kind', 'value', 'until_at', 'reason']);

        return 0;
    }

    private function block(): int
    {
        [$value, $days, $reason] = array_pad($this->args, 3, null);
        if ($value === null) {
            return $this->fail('draco block <ip|range> [7|15|30|90|0] [reason]');
        }
        $host = $this->host();
        $kind = str_contains($value, '/') ? 'net' : 'ip';
        $ok = $host->store()->block($kind, $value, (int) ($days ?? 30), (string) ($reason ?? 'By hand'));

        return $ok ? $this->out("Blocked: $value") : $this->fail('Refused: not a valid address, an administrator\'s address, a range wider than /16 (IPv4) or /32 (IPv6), or days not 7, 15, 30, 90 or 0.');
    }

    private function unblock(): int
    {
        return $this->host()->store()->unblock((int) ($this->args[0] ?? 0)) ? $this->out('Removed.') : $this->fail('No block with that ID.');
    }

    private function reviews(): int
    {
        $store = $this->host()->store();
        $id = $this->args[0] ?? null;
        if ($id === null) {
            $rows = $store->reviews(50);
            if ($rows === []) {
                return $this->out('No review requests.');
            }
            foreach ($rows as $r) {
                $f = json_decode((string) $r['fields'], true);
                $f = is_array($f) ? $f : [];
                printf("%d\t%s\t%s\t%s\t%s\t%s\n", $r['id'], gmdate('Y-m-d H:i', (int) $r['created_at']), $r['ip'], $f['email'] ?? '', \DracoInsomnis\Core\Review::cut((string) ($f['referer'] ?? ''), 60), $r['verdict']);
            }

            return $this->out('Decide: draco reviews <id> --approve=1|7|30|0, --deny or --attacker (Draco never writes to them)');
        }
        $row = $store->review((int) $id);
        if ($row === null) {
            return $this->fail('No review request with that ID.');
        }
        $f = json_decode((string) $row['fields'], true);
        $reason = 'Review: ' . (is_array($f) ? (string) ($f['email'] ?? '') : '');
        if (isset($this->opt['approve'])) {
            [$done, $verdict] = [$store->allow((string) $row['ip'], (int) $this->opt['approve'], $reason), 'approved'];
        } elseif (isset($this->opt['attacker'])) {
            [$done, $verdict] = [$store->block('ip', (string) $row['ip'], 90, $reason, true), 'attacker'];
        } elseif (isset($this->opt['deny'])) {
            [$done, $verdict] = [true, 'denied'];
        } else {
            return $this->fail('Say what to do: --approve=1|7|30|0, --deny or --attacker.');
        }
        if (!$done) {
            return $this->fail('It could not be done for that address.');
        }
        $store->setVerdict((int) $row['id'], $verdict);

        return $this->out('Done.');
    }

    private function test(): int
    {
        $url = $this->args[0] ?? '';
        if (!preg_match('#^https?://#', $url)) {
            return $this->fail('draco test <url of a PHP page>');
        }
        $host = $this->host((string) parse_url($url, PHP_URL_HOST));
        [$rule, $mode] = array_pad(explode('|', TestProbe::run($host, $url, time()), 2), 2, '');

        return match (true) {
            $rule === 'off' => $this->fail('The firewall is off for that site: draco set waf_mode log (or block).'),
            $rule === 'error', $rule === 'unseen' => $this->fail("The test did not reach Draco at $url: is it a PHP page, and is Draco enabled (draco status)? With several PHP users, pass --user."),
            $rule === 'upstream' => $this->out('Stopped before PHP, by a firewall in front. Good: two layers.'),
            $rule === 'none' => $this->fail('The test attack was not recognised. Please report it to Draco Insomnis.'),
            default => $this->out($mode === 'block' ? 'Works: a database injection was recognised and blocked (403).' : 'Works: a database injection was recognised. In "log" it is written down but not stopped; draco set waf_mode block when you are ready.'),
        };
    }

    private function cleanup(): int
    {
        $total = 0;
        foreach (array_keys($this->dirs()) as $dir) {
            $total += (new ServerHost(Config::forHost(''), $dir))->store()->cleanup();
        }
        echo "Old rows removed: $total\n";
        $uses = false;
        foreach (Config::load() as $site) {
            $uses = $uses || (($site['geo_mode'] ?? 'off') !== 'off');
        }
        $file = (new ServerHost(Config::forHost(''), $this->base()))->setting('geo_file');
        if ($uses && GeoUpdate::stale($file, time())) {
            $this->geoUpdate();
        }

        return 0;
    }

    private function geoUpdate(): int
    {
        $file = (new ServerHost(Config::forHost(''), $this->base()))->setting('geo_file');
        $error = GeoUpdate::update($file);
        if ($error !== '') {
            return $this->fail("Country list not downloaded ($error). The filter does nothing until it is there.");
        }
        @chmod($file, 0644);

        return $this->out('Country list: ' . Geo::built($file) . ' (IP geolocation by DB-IP, CC BY 4.0)');
    }
}
