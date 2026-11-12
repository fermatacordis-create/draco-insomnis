<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Application firewall. "Log only" records what it would stop; "block" also refuses it, and five
 * attacks in ten minutes put the address on the block list for a week.
 *
 * The CMS adapter decides who is never inspected (people who can edit the site, cron, CLI) and which
 * paths a blocked address may not use (its login and XML-RPC-like endpoints).
 */
final class Firewall
{
    private const HITS_TO_BLOCK = 5;
    private const HIT_WINDOW = 600;
    private const BLOCK_DAYS = 7;

    public function __construct(private Host $host, private bool $blocking)
    {
    }

    /** Addresses an administrator used are never inspected. */
    public function exempt(Request $r): bool
    {
        return in_array($r->ip($this->host->setting('proxy_header')), $this->host->adminIps(), true);
    }

    /**
     * Addresses on the block list may read the site, but not post or use the sensitive paths.
     *
     * @param list<string> $sensitiveEndings Path endings such as "/wp-login.php".
     */
    public function refusedAsBlocked(Request $r, array $sensitiveEndings): bool
    {
        $sensitive = $r->method === 'POST';
        foreach ($sensitiveEndings as $ending) {
            $sensitive = $sensitive || str_ends_with($r->path, $ending);
        }

        return $sensitive && $this->host->events()->isBlocked('', $r->ip($this->host->setting('proxy_header')));
    }

    /** The rule this request breaks, recorded; null when it breaks none. */
    public function inspect(Request $r): ?string
    {
        $rule = WafRules::inspect([
            'path' => $r->path,
            'query' => $r->query,
            'params' => $r->params,
            'user_agent' => $r->rawUserAgent,
        ]);
        if ($rule !== null) {
            $this->record($r, $rule);
        }

        return $rule;
    }

    public function blocking(): bool
    {
        return $this->blocking;
    }

    public function record(Request $r, string $rule): void
    {
        $ip = $r->ip($this->host->setting('proxy_header'));
        $remote = $r->remote();
        $events = $this->host->events();
        $events->log($ip, $remote, 'waf:' . $rule, ['score' => 100, 'verdict' => $this->blocking ? 'bot' : 'doubtful', 'reasons' => ['waf_' . $rule]], substr($r->userAgent, 0, 255), [
            'username' => '',
            'email' => '',
            'role' => '',
            'referer' => substr($r->path . ($r->query !== '' ? '?' . $r->query : ''), 0, 200),
        ]);
        if (!$this->blocking) {
            return;
        }
        $hits = $this->host->bump('draco_waf_hits_' . md5($ip), self::HIT_WINDOW);
        $trusted = $ip === $remote || $this->host->setting('proxy_header') !== '';
        if ($hits >= self::HITS_TO_BLOCK && $trusted && !$events->isBlocked('', $ip)) {
            $events->block('ip', $ip, self::BLOCK_DAYS, $this->host->text('waf_block', $hits), true);
        }
    }

    /** The 403 page: no details for the attacker, only a reference. Texts already translated. */
    public static function page(string $title, string $text, string $why): string
    {
        $h = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
        $ref = substr(hash('sha256', $why . '|' . microtime(true)), 0, 10);

        return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><meta name="viewport" content="width=device-width,initial-scale=1"><title>403</title>'
            . '<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box}main{background:#fff;border-radius:12px;padding:32px;max-width:440px;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}</style></head><body><main>'
            . '<h1 style="font-size:20px">' . $h($title) . '</h1>'
            . '<p>' . $h($text) . '</p>'
            . '<p style="color:#64748b;font-size:13px">Ref. ' . $h($ref) . '</p></main></body></html>';
    }
}
