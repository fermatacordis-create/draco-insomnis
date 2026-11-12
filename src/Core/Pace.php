<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Anti-copy pace limit: more pages per minute than a person reads, from one address or one network,
 * get a 429 for the rest of that minute. Search engines verified by reverse DNS, and the addresses an
 * administrator used, are never limited. The CMS adapter skips logged-in people, cron and the back office.
 */
final class Pace
{
    public const DEFAULT_RATE_IP = 120;
    public const DEFAULT_RATE_NET = 600;
    public const WINDOW = 60;
    private const VERIFIED_FOR = 86400;

    public function __construct(private Host $host)
    {
    }

    /**
     * Counts this request.
     *
     * @return array{over: string, first: bool, retry: int} over: '', 'ip' or 'net'; first: the first
     *         request past the limit this minute (the one worth recording); retry: seconds left.
     */
    public function count(Request $r, int $now): array
    {
        $ip = $r->ip($this->host->setting('proxy_header'));
        $minute = intdiv($now, self::WINDOW);
        $ipHits = $this->host->bump('draco_rl_i_' . md5($ip) . '_' . $minute, self::WINDOW * 2);
        $netHits = $this->host->bump('draco_rl_n_' . md5(Crawler::network($ip)) . '_' . $minute, self::WINDOW * 2);
        $ipLimit = $this->limit('anticopy_rate_ip', self::DEFAULT_RATE_IP);
        $netLimit = $this->limit('anticopy_rate_net', self::DEFAULT_RATE_NET);

        return [
            'over' => $ipHits > $ipLimit ? 'ip' : ($netHits > $netLimit ? 'net' : ''),
            'first' => $ipHits === $ipLimit + 1 || $netHits === $netLimit + 1,
            'retry' => self::WINDOW - ($now % self::WINDOW),
        ];
    }

    private function limit(string $setting, int $default): int
    {
        $value = (int) $this->host->setting($setting);

        return $value >= 10 ? $value : $default;
    }

    /** The addresses an administrator used, and search engines verified by DNS. */
    public function exempt(Request $r): bool
    {
        $ip = $r->ip($this->host->setting('proxy_header'));
        if (in_array($ip, $this->host->adminIps(), true)) {
            return true;
        }

        return $this->verifiedCrawler($ip, $r->userAgent);
    }

    /**
     * Reverse DNS, then forward DNS back to the same address. Only runs for an address that claims to
     * be a crawler and has hit a limit, and the answer is kept for a day.
     */
    public function verifiedCrawler(string $ip, string $userAgent): bool
    {
        $claimed = Crawler::claimed($userAgent);
        if ($claimed === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $forced = $this->host->filter('crawler_verified', null, $ip, $claimed);
        if (is_bool($forced)) {
            return $forced;
        }
        $key = 'draco_crawler_' . md5($ip . '|' . $claimed);
        $cached = $this->host->recall($key);
        if ($cached === 'y' || $cached === 'n') {
            return $cached === 'y';
        }
        $ok = self::resolvesBack($ip, $claimed);
        $this->host->remember($key, $ok ? 'y' : 'n', self::VERIFIED_FOR);

        return $ok;
    }

    private static function resolvesBack(string $ip, string $claimed): bool
    {
        $host = (string) gethostbyaddr($ip);
        if (!Crawler::hostMatches($claimed, $host)) {
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return in_array($ip, (array) gethostbynamel($host), true);
        }
        $want = inet_pton($ip);
        foreach ((array) dns_get_record($host, DNS_AAAA) as $record) {
            if (isset($record['ipv6']) && inet_pton((string) $record['ipv6']) === $want) {
                return true;
            }
        }

        return false;
    }

    /** Never counts towards the shield's bot verdicts: a fast reader or a shared office is not a bot. */
    public function record(Request $r, string $kind, bool $block, string $path): void
    {
        $this->host->events()->log($r->ip($this->host->setting('proxy_header')), $r->remote(), 'anticopy:' . $kind, ['score' => 0, 'verdict' => 'doubtful', 'reasons' => ['anticopy_' . $kind . '_' . ($block ? 'block' : 'log')]], substr($r->userAgent, 0, 255), [
            'username' => '',
            'email' => '',
            'role' => '',
            'referer' => substr($path, 0, 200),
        ]);
    }
}
