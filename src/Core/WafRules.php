<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Attack signatures for one request. Plain PHP, no WordPress.
 *
 * Precise on purpose: words like "select" or "update" appear in ordinary messages, so only shapes
 * that real visitors never send are matched. Text bodies (forms) are only checked for SQL and code
 * injection shapes; HTML-looking input is only checked in the URL, where nobody types it by hand.
 */
final class WafRules
{
    private const SCANNERS = '/\b(sqlmap|nikto|wpscan|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|whatweb|openvas|netsparker|jaeles|hydra)\b/i';

    private const PROBES = '#(^|/)(\.env(\.[a-z0-9]+)?$|\.git(/|$)|\.svn/|\.hg/|\.aws/|\.ssh/|\.ds_store$|wp-config\.php[^/]+$|wp-config\.(bak|old|txt|orig|save|swp)$|phpinfo\.php$|info\.php$|adminer[\w.-]*\.php$|eval-stdin\.php$|vendor/phpunit/|[\w.-]+\.sql(\.gz|\.zip)?$|debug\.log$|server-status$|cgi-bin/|(wso|c99|r57|alfa[\w-]*|shell|webshell|b374k)\.php$)#i';

    private const SQLI = [
        // "union select" followed by a column list, not by a word: "European Union Select Committee" passes.
        '/\bunion\b(\s|\/\*.*?\*\/|\+)+(all(\s|\/\*.*?\*\/|\+)+|distinct(\s|\/\*.*?\*\/|\+)+)?select(\s|\/\*.*?\*\/|\+)*(\d|null\b|@@|\*|0x|[\'"(]|concat|char\s*\(|group_concat|[a-z_.`]+\s*,)/is',
        // A single column: "1' union select user_pass from wp_users-- ". Only right after a quote, a
        // whole number value or a bracket, which is where injected SQL starts and ordinary sentences do not.
        '/([\'")]|(^|[=&])-?\d+)(\s|\/\*.*?\*\/|\+)*\bunion\b(\s|\/\*.*?\*\/|\+)+(all(\s|\/\*.*?\*\/|\+)+)?select(\s|\/\*.*?\*\/|\+)+[a-z_.`]+(\s|\/\*.*?\*\/|\+)+from\b/is',
        '/\bselect\b.{1,120}\bfrom\b.{1,120}\b(information_schema|mysql\.user|pg_catalog)\b/is',
        '/\b(sleep|benchmark|pg_sleep)\s*\(\s*\d/i',
        '/\bwaitfor\s+delay\s+\'/i',
        '/\'\s*(or|and)\s+\'?\d+\'?\s*=\s*\'?\d+/i',
        '/\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#|\/\*)/i',
        '/;\s*(drop|truncate|alter)\s+table\b/i',
    ];

    private const TRAVERSAL = [
        '#(\.\.[/\\\\]){2,}#',
        '#\b(etc/passwd|etc/shadow|proc/self/environ|boot\.ini|win\.ini)\b#i',
        '#\b(php|expect|phar|zip|data)://#i',
    ];

    private const CODE = [
        '/\$\{\s*jndi\s*:/i',
        '/\b(base64_decode|eval|assert|system|shell_exec|passthru|proc_open|popen)\s*\(/i',
        '/\b(wget|curl)\s+(-[a-z]+\s+)*https?:\/\//i',
        '/<\?php/i',
    ];

    private const XSS_URL = [
        '/<\s*script\b/i',
        '/\bjavascript\s*:/i',
        '/<\s*(svg|img|iframe|body|details)\b[^>]*\bon[a-z]+\s*=/i',
        '/["\'\s]on(error|load|mouseover|focus|toggle)\s*=/i',
    ];

    /**
     * @param array{path?: string, query?: string, params?: list<string>, user_agent?: string} $r
     *        path and query already URL-decoded; params are the decoded GET and POST values.
     * @return string|null The rule that matched, or null.
     */
    public static function inspect(array $r): ?string
    {
        $path = (string) ($r['path'] ?? '');
        $query = (string) ($r['query'] ?? '');
        $params = (array) ($r['params'] ?? []);

        if (preg_match(self::SCANNERS, (string) ($r['user_agent'] ?? '')) === 1) {
            return 'scanner';
        }
        if (preg_match(self::PROBES, $path) === 1) {
            return 'probe';
        }
        // Encoded twice (%2527 → %27 → '): the request arrives decoded once, so look at the second
        // decoding too. Nothing is changed, only inspected.
        $path2 = self::decodedAgain($path);
        $query2 = self::decodedAgain($query);
        $everything = array_merge([$path, $query, $path2, $query2], array_map('strval', $params), array_map(static fn ($v): string => self::decodedAgain((string) $v), $params));
        foreach (['sqli' => self::SQLI, 'traversal' => self::TRAVERSAL, 'code' => self::CODE] as $rule => $patterns) {
            foreach ($everything as $value) {
                if ($value !== '' && self::any($patterns, $value)) {
                    return $rule;
                }
            }
        }
        foreach ([$path, $query, $path2, $query2] as $value) {
            if ($value !== '' && self::any(self::XSS_URL, $value)) {
                return 'xss';
            }
        }

        return null;
    }

    /** The value decoded once more when it still holds %XX sequences; '' when there is nothing more to decode. */
    private static function decodedAgain(string $value): string
    {
        if (preg_match('/%[0-9a-f]{2}/i', $value) !== 1) {
            return '';
        }
        $again = rawurldecode($value);

        return $again === $value ? '' : $again;
    }

    /** @param list<string> $patterns */
    private static function any(array $patterns, string $value): bool
    {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value) === 1) {
                return true;
            }
        }

        return false;
    }

    /** Flattens nested request values into strings, at most $limit of them. @param array<mixed> $values @return list<string> */
    public static function flatten(array $values, int $limit = 200): array
    {
        $out = [];
        $walk = static function ($value, int $depth) use (&$walk, &$out, $limit): void {
            if (count($out) >= $limit) {
                return;
            }
            if (is_array($value) && $depth < 5) {
                foreach ($value as $key => $item) {
                    if (is_string($key) && $key !== '') {
                        $out[] = $key;
                    }
                    $walk($item, $depth + 1);
                }
            } elseif (is_scalar($value)) {
                $out[] = (string) $value;
            }
        };
        $walk($values, 0);

        return array_slice($out, 0, $limit);
    }
}
