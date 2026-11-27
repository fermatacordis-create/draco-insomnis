<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

defined('ABSPATH') || exit;

/**
 * Explains a firewall event to a person, from the rule that matched and the address requested.
 * It only reads what is already stored: the rules that decide what is stopped are not touched.
 *
 * - kind(): "looking for sensitive files" is split into what was looked for (secrets, backups,
 *   logs, server information pages, admin tools, installers, known exploits, back doors).
 * - signature(): the name of a well-known attack, when the address is unmistakably one.
 */
final class Explain
{
    private const PROBE_KINDS = [
        'exploit' => '#(^|/)(vendor/phpunit/|eval-stdin\.php$|cgi-bin/)#i',
        'shell' => '#(^|/)(wso|c99|r57|alfa[\w-]*|shell|webshell|b374k)\.php$#i',
        'secrets' => '#(^|/)(\.env(\.[a-z0-9]+)?$|\.git(/|$)|\.svn/|\.hg/|\.aws/|\.ssh/|\.ht(access|passwd)$|wp-config\.)#i',
        'backup' => '#(\.sql(\.gz|\.zip)?$|\.(bak|old|orig|save|swp)$|(^|/)(backup|backups|dump|database)[\w.-]*\.(zip|tar|tgz|gz|bz2|7z|rar)$)#i',
        'log' => '#(\.log(\.\d+|\.gz)?$|(^|/)error_log$|(storage|var)/logs?/)#i',
        'info' => '#(^|/)(phpinfo\.php|info\.php|server-status)$#i',
        'admin_tool' => '#(^|/)(adminer[\w.-]*\.php$|(phpmyadmin|phppgadmin)[\w.-]*(/|$)|pma(/|$))#i',
        'installer' => '#(^|/)(core/install\.php|wp-admin/(install|setup-config)\.php)$#i',
    ];

    /** A finer kind for waf_probe events ('probe' when none fits); the rule itself for the others. */
    public static function kind(string $rule, string $requested): string
    {
        if ($rule !== 'waf_probe') {
            return $rule;
        }
        $path = strtolower((string) strtok($requested, '?'));
        foreach (self::PROBE_KINDS as $kind => $pattern) {
            if (preg_match($pattern, $path) === 1) {
                return $kind;
            }
        }

        return 'probe';
    }

    /** The name of a well-known attack the address matches, or ''. Never a guess: exact traits only. */
    public static function signature(string $requested): string
    {
        $raw = rawurldecode($requested);
        $low = strtolower($raw);
        if (str_contains($low, 'vendor/phpunit/') || str_contains($low, 'eval-stdin.php')) {
            return 'PHPUnit CVE-2017-9841';
        }
        if (str_contains($low, 'cgi-bin/php') || (str_contains($low, 'allow_url_include') && str_contains($low, 'auto_prepend_file'))) {
            return 'PHP-CGI CVE-2012-1823 / CVE-2024-4577';
        }
        if (str_contains($low, 'x-spip-filtre') || preg_match('/[?&]page=recherche&recherche=.*<\?php/', $low) === 1) {
            return 'SPIP';
        }
        if (preg_match('#(^|/)(wso|c99|r57|alfa[\w-]*|b374k)\.php(\?|$)#', $low, $m) === 1) {
            return ucfirst(preg_replace('/[-_].*$/', '', $m[2]) ?? $m[2]) . ' shell';
        }
        if (str_contains($low, 'proc/self/environ')) {
            return '/proc/self/environ';
        }

        return '';
    }

    /** The HTTP answer the visitor got: 403 when blocked; '' when the request went on (log only). */
    public static function answer(string $verdict): string
    {
        return $verdict === 'bot' ? '403' : '';
    }
}
