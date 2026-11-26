<?php

declare(strict_types=1);

namespace DracoInsomnis\Server;

/**
 * "draco audit": asks one's own site, from outside, for the files and tools that must never be
 * public, and says what each answer means. Evidence only: no score and no certificate.
 *
 * A status code alone can lie (an application may answer 403 or 200 to anything), so every answer is
 * compared with the answer to a path that cannot exist.
 */
final class Audit
{
    /** group => paths. Never update.php: sites need it to update. */
    public const PATHS = [
        'dotfiles' => ['/.env', '/.env.local', '/.htaccess', '/.htpasswd'],
        'vcs' => ['/.git/config', '/.git/HEAD', '/.svn/entries'],
        'installers' => ['/install.php', '/core/install.php', '/wp-admin/install.php', '/wp-admin/setup-config.php', '/installation/'],
        'backups' => ['/backup.sql', '/database.sql', '/dump.sql.gz', '/backup.zip', '/backup.tar.gz', '/wp-config.php.bak', '/index.php.bak'],
        'admin tools' => ['/phpmyadmin/', '/phpMyAdmin/', '/pma/', '/adminer.php', '/phppgadmin/'],
        'logs' => ['/error_log', '/debug.log', '/wp-content/debug.log', '/storage/logs/laravel.log', '/var/log/'],
        'tools' => ['/phpinfo.php', '/info.php', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/server-status'],
    ];

    public const PROTECTED = 'protected';
    public const ABSENT = 'absent';
    public const EXPOSED = 'EXPOSED';
    public const RAN = 'RAN';
    public const REVIEW = 'review';
    public const ERROR = 'error';

    /**
     * What one answer means.
     *
     * @param array{code: int, body: string, location?: string} $answer
     * @param array{code: int, body: string} $baseline The answer to a path that cannot exist.
     * @return array{0: string, 1: string} [result, note]
     */
    public static function classify(string $path, array $answer, array $baseline): array
    {
        $code = $answer['code'];
        if ($code === 0) {
            return [self::ERROR, 'no answer'];
        }
        $same = self::alike($answer['body'], $baseline['body']);
        if ($code === 401 || $code === 403 || $code === 451) {
            // The site answers the same to everything: this 403 proves nothing about this path.
            return $baseline['code'] === $code && $same ? [self::REVIEW, 'the site answers ' . $code . ' to everything'] : [self::PROTECTED, ''];
        }
        if ($code === 404 || $code === 410) {
            return [self::ABSENT, 'not there, not refused'];
        }
        if ($code >= 300 && $code < 400) {
            return [self::REVIEW, 'redirects to ' . (($answer['location'] ?? '') !== '' ? $answer['location'] : '?')];
        }
        if ($code >= 500) {
            // A PHP file that fails ran: an error there means code was executed, not refused.
            return str_ends_with(strtolower($path), '.php') || str_ends_with($path, '/') ? [self::RAN, 'server error: the code ran'] : [self::REVIEW, 'server error ' . $code];
        }
        if ($code >= 200 && $code < 300) {
            return $baseline['code'] >= 200 && $baseline['code'] < 300 && $same ? [self::ABSENT, 'same page as a missing path'] : [self::EXPOSED, 'served'];
        }

        return [self::REVIEW, 'answer ' . $code];
    }

    /** Two pages are alike when they are the same once numbers (tokens, times) are taken out. */
    public static function alike(string $a, string $b): bool
    {
        $norm = static fn (string $s): string => (string) preg_replace('/\d+/', '0', substr($s, 0, 20000));
        $a = $norm($a);
        $b = $norm($b);
        if ($a === $b) {
            return true;
        }
        $max = max(strlen($a), strlen($b));

        return $max > 0 && abs(strlen($a) - strlen($b)) / $max < 0.02 && similar_text(substr($a, 0, 4000), substr($b, 0, 4000)) / max(1, min(4000, $max)) > 0.95;
    }

    /**
     * Runs the audit. $fetch(url) returns ['code' => int, 'body' => string, 'location' => string].
     *
     * @param callable(string): array{code: int, body: string, location: string} $fetch
     * @return list<array{group: string, path: string, code: int, result: string, note: string}>
     */
    public static function run(string $base, callable $fetch, int $pauseMs = 150): array
    {
        $base = rtrim($base, '/');
        $baseline = $fetch($base . '/draco-audit-' . bin2hex(random_bytes(6)) . '-missing.php');
        $rows = [];
        foreach (self::PATHS as $group => $paths) {
            foreach ($paths as $path) {
                $answer = $fetch($base . $path);
                [$result, $note] = self::classify($path, $answer, $baseline);
                $rows[] = ['group' => $group, 'path' => $path, 'code' => $answer['code'], 'result' => $result, 'note' => $note];
                usleep($pauseMs * 1000);
            }
        }

        return $rows;
    }

    /** @param list<array{result: string}> $rows */
    public static function failed(array $rows): bool
    {
        foreach ($rows as $r) {
            if ($r['result'] === self::EXPOSED || $r['result'] === self::RAN) {
                return true;
            }
        }

        return false;
    }

    /** @return callable(string): array{code: int, body: string, location: string} */
    public static function curl(string $version): callable
    {
        return static function (string $url) use ($version): array {
            $ch = curl_init($url);
            $body = '';
            curl_setopt_array($ch, [
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT => 15,
                CURLOPT_CONNECTTIMEOUT => 8,
                CURLOPT_USERAGENT => 'Draco-Insomnis-Audit/' . $version . ' (own site check)',
                CURLOPT_HTTPHEADER => ['Accept: text/html,*/*'],
                // At most 64 KB: enough to compare pages, never a whole backup.
                CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body): int {
                    $body .= $chunk;

                    return strlen($body) > 65536 ? 0 : strlen($chunk);
                },
            ]);
            curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $location = (string) curl_getinfo($ch, CURLINFO_REDIRECT_URL);

            return ['code' => $code, 'body' => substr($body, 0, 65536), 'location' => $location];
        };
    }
}
