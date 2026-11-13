<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

// phpcs:disable WordPress.WP.AlternativeFunctions -- this engine also runs outside WordPress; the WordPress plugin sends its test through wp_remote_get() instead (Firewall\Admin).

/**
 * The "Test the firewall" button: a harmless attack-shaped request to the site itself with a signed
 * header (valid one minute). The site judges it with the same rules but logs and counts nothing (it
 * would otherwise block the server's own address), and answers what would have happened.
 */
final class TestProbe
{
    public const HEADER = 'X-Draco-Test';
    public const RESULT = 'X-Draco-Test-Result';
    public const ATTACK = "1' union select user_pass from users-- ";

    public static function token(Host $host, int $ts): string
    {
        return $ts . '.' . hash_hmac('sha256', 'waf-test|' . $ts, $host->secret());
    }

    /**
     * The answer to a test request, or null when the header is missing or not ours.
     *
     * @return array{status: int, result: string}|null
     */
    public static function answer(Host $host, string $token, string $wafMode, int $now): ?array
    {
        if ($token === '') {
            return null;
        }
        $ts = (int) strtok($token, '.');
        if (abs($now - $ts) > 60 || !hash_equals(self::token($host, $ts), $token)) {
            return null;
        }
        if ($wafMode === 'off') {
            return ['status' => 200, 'result' => 'off'];
        }
        $rule = WafRules::inspect(['path' => '/', 'query' => 'draco_test=' . self::ATTACK, 'params' => [self::ATTACK], 'user_agent' => 'Draco test']);

        return ['status' => $rule !== null && $wafMode === 'block' ? 403 : 200, 'result' => ($rule ?? 'none') . '|' . $wafMode];
    }

    /**
     * Sends the test to $home and returns "rule|mode", "off", or what went wrong: "upstream" (stopped
     * before the CMS, by the hosting's own firewall), "unseen" or "error".
     */
    public static function run(Host $host, string $home, int $now): string
    {
        $url = $home . (str_contains($home, '?') ? '&' : '?') . 'draco_test=' . rawurlencode(self::ATTACK) . '&cb=' . bin2hex(random_bytes(4));
        $headers = [self::HEADER . ': ' . self::token($host, $now), 'Cache-Control: no-cache'];
        $status = 0;
        $result = '';
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_NOBODY => false, CURLOPT_TIMEOUT => 15,
                CURLOPT_HTTPHEADER => $headers, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_USERAGENT => 'Draco-Insomnis test']);
            $raw = curl_exec($ch);
            if (!is_string($raw)) {
                return 'error';
            }
            $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $head = substr($raw, 0, (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE));
        } else {
            $ctx = stream_context_create(['http' => ['header' => implode("\r\n", $headers), 'timeout' => 15, 'ignore_errors' => true, 'user_agent' => 'Draco-Insomnis test'],
                'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
            $body = @file_get_contents($url, false, $ctx);
            if ($body === false) {
                return 'error';
            }
            // PHP 8.4+ has http_get_last_response_headers(); before, the stream fills $http_response_header here.
            $lines = function_exists('http_get_last_response_headers') ? (array) http_get_last_response_headers() : (array) ($http_response_header ?? []);
            $head = implode("\n", $lines);
            $status = preg_match('#^HTTP/\S+ (\d{3})#', $lines[0] ?? '', $m) === 1 ? (int) $m[1] : 0;
        }
        if (preg_match('/^' . preg_quote(self::RESULT, '/') . ':\s*(\S+)/mi', $head, $m) === 1) {
            $result = trim($m[1]);
        }
        if ($result !== '') {
            return $result;
        }

        return $status === 403 ? 'upstream' : 'unseen';
    }
}
