<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * What the firewall stopped in the last days, from the event rows a store returns (endpoint "waf:…",
 * with verdict, reasons and ip): totals, by rule, and the busiest addresses.
 */
final class Summary
{
    /**
     * @param iterable<array{ip: string, verdict: string, reasons: string}> $rows
     * @return array{total: int, blocked: int, rules: array<string, int>, ips: array<string, int>}
     */
    public static function waf(iterable $rows): array
    {
        $out = ['total' => 0, 'blocked' => 0, 'rules' => [], 'ips' => []];
        foreach ($rows as $row) {
            $out['total']++;
            $out['blocked'] += (string) $row['verdict'] === 'bot' ? 1 : 0;
            $rule = explode(',', (string) $row['reasons'])[0];
            $out['rules'][$rule] = ($out['rules'][$rule] ?? 0) + 1;
            $out['ips'][(string) $row['ip']] = ($out['ips'][(string) $row['ip']] ?? 0) + 1;
        }
        arsort($out['rules']);
        arsort($out['ips']);
        $out['ips'] = array_slice($out['ips'], 0, 5, true);

        return $out;
    }
}
