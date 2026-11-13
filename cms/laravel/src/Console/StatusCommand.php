<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Console;

use DracoInsomnis\Laravel\LaravelHost;
use DracoInsomnis\Laravel\Store;
use Illuminate\Console\Command;

/** Settings, blocked addresses and the last suspicious attempts. */
final class StatusCommand extends Command
{
    protected $signature = 'draco:status {--limit=20 : How many attempts to show}';

    protected $description = 'Draco Insomnis: settings, blocked addresses and the last suspicious attempts';

    public function handle(): int
    {
        $this->line('<info>Draco Insomnis</info> — ab insomni custodita dracone');
        $this->table(['Part', 'Mode'], [
            ['Sign-up shield', config('draco.shield') ? 'on' : 'off'],
            ['Firewall', LaravelHost::mode('waf_mode') . (config('draco.waf_off') ? ' (DRACO_WAF_OFF)' : '')],
            ['Anti-copy pace limit', LaravelHost::mode('pace_mode') . ' (' . (int) config('draco.anticopy_rate_ip') . '/min per address)'],
            ['Visitor address', (string) config('draco.proxy_header') ?: 'connection address'],
            ['Trusted proxies', (string) config('draco.trusted_proxies') ?: 'this machine and private networks' . (config('draco.proxy_header') === 'cf' ? ', Cloudflare' : '')],
        ]);

        $sum = \DracoInsomnis\Core\Summary::waf(Store::wafRows(7 * 86400));
        $this->line('<info>Firewall: last 7 days</info> — ' . $sum['total'] . ' attacks seen, ' . $sum['blocked'] . ' blocked');
        foreach (['What' => $sum['rules'], 'Busiest addresses' => $sum['ips']] as $title => $counts) {
            if ($counts !== []) {
                $this->line('  ' . $title . ': ' . implode(' · ', array_map(static fn ($k, $n) => str_replace('waf_', '', (string) $k) . ': ' . $n, array_keys($counts), $counts)));
            }
        }
        $pending = count(array_filter(Store::reviews(50), static fn ($r) => $r->verdict === 'pending'));
        if ($pending > 0) {
            $this->line("<comment>$pending review request(s) waiting: php artisan draco:reviews</comment>");
        }

        $blocks = Store::activeBlocks();
        $this->line('<info>Blocked addresses</info> (' . count($blocks) . ')');
        if ($blocks !== []) {
            $this->table(['ID', 'Address or e-mail', 'Reason', 'Until (UTC)'], array_map(
                static fn ($b) => [$b->id, $b->value, $b->reason, $b->until_at],
                $blocks
            ));
        }

        $events = Store::recent((int) $this->option('limit'));
        $this->line('<info>Last suspicious attempts</info> (kept 90 days; draco:evidence <ip> for the CSV)');
        if ($events !== []) {
            $this->table(['Date (UTC)', 'Address', 'Where', 'Verdict', 'Signs'], array_map(
                static fn ($e) => [$e->created_at, $e->ip, $e->endpoint, $e->verdict, $e->reasons],
                $events
            ));
        }

        return self::SUCCESS;
    }
}
