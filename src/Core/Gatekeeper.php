<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * One request through the firewall, the country filter and the anti-copy pace limit, in the same
 * order in every CMS. Returns what to answer, or null to let the request through; each CMS only turns
 * that into its own response (Firewall::page() for 403).
 */
final class Gatekeeper
{
    public function __construct(private Host $host)
    {
    }

    /**
     * @param string $wafMode off | log | block
     * @param string $paceMode off | log | block
     * @param list<string> $sensitive Path endings of the login and sign-up pages.
     * @return array{status: int, why: string, retry: int}|null
     */
    public function decide(Request $r, string $wafMode, string $paceMode, array $sensitive, bool $withPace = true): ?array
    {
        if ($wafMode !== 'off') {
            $firewall = new Firewall($this->host, $wafMode === 'block');
            if (!$firewall->exempt($r)) {
                // Addresses on the block list may read the site, but not post or log in.
                if ($firewall->refusedAsBlocked($r, $sensitive)) {
                    return ['status' => 403, 'why' => 'blocked', 'retry' => 0];
                }
                $geo = new GeoPolicy($this->host);
                $country = $geo->refusedCountry($r, $sensitive);
                if ($country !== '') {
                    $geo->log($r, $country);
                    if ($geo->blocking()) {
                        return ['status' => 403, 'why' => 'geo', 'retry' => 0];
                    }
                }
                $rule = $firewall->inspect($r);
                if ($rule !== null && $firewall->blocking()) {
                    return ['status' => 403, 'why' => $rule, 'retry' => 0];
                }
            }
        }
        if ($withPace && $paceMode !== 'off') {
            $engine = new Pace($this->host);
            $count = $engine->count($r, time());
            if ($count['over'] !== '' && !$engine->exempt($r)) {
                $block = $paceMode === 'block';
                // One line per address and minute is enough evidence; the rest only counts.
                if ($count['first']) {
                    $engine->record($r, 'rate_' . $count['over'], $block, $r->path);
                }
                if ($block) {
                    return ['status' => 429, 'why' => 'pace', 'retry' => max(1, (int) $count['retry'])];
                }
            }
        }

        return null;
    }
}
