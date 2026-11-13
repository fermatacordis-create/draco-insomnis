<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Country filter, off by default. Settings: geo_mode (off | block = refuse the listed countries |
 * allow = only the listed ones), geo_countries ("ES, FR"), geo_scope (sensitive | site), geo_action
 * (log | block) and geo_file (where the country list is). Administrators, people let through after a
 * review (both in adminIps()), search engines verified by DNS and addresses without a country are
 * never filtered, and a country never puts an address on the block list.
 */
final class GeoPolicy
{
    public function __construct(private Host $host)
    {
    }

    public function mode(): string
    {
        $mode = $this->host->setting('geo_mode');

        return in_array($mode, ['block', 'allow'], true) ? $mode : 'off';
    }

    public function blocking(): bool
    {
        return $this->host->setting('geo_action') === 'block';
    }

    /**
     * The country this request is refused for, or '' when it passes.
     *
     * @param list<string> $sensitive Parts of the address (path or query) of the login and sign-up pages.
     */
    public function refusedCountry(Request $r, array $sensitive): string
    {
        $mode = $this->mode();
        $list = Geo::parseList($this->host->setting('geo_countries'));
        if ($mode === 'off' || $list === []) {
            return '';
        }
        if ($this->host->setting('geo_scope') !== 'site' && !self::sensitive($r, $sensitive)) {
            return '';
        }
        $country = Geo::country($this->host->setting('geo_file'), $r->via($this->host));
        if ($country === null) {
            return '';
        }
        $listed = in_array($country, $list, true);
        if (($mode === 'block' && !$listed) || ($mode === 'allow' && $listed)) {
            return '';
        }
        // Last: it may ask the DNS, and only matters for a request that would be refused.
        if ((new Pace($this->host))->exempt($r)) {
            return '';
        }

        return $country;
    }

    /** Written down without counting towards the automatic block: a person may simply try again. */
    public function log(Request $r, string $country): void
    {
        $this->host->events()->log($r->via($this->host), $r->remote(), 'waf:geo', ['score' => 0, 'verdict' => $this->blocking() ? 'bot' : 'doubtful', 'reasons' => ['waf_geo']], substr($r->userAgent, 0, 255), [
            'username' => '',
            'email' => '',
            'role' => '',
            'referer' => substr($country . ' ' . $r->path, 0, 200),
        ]);
    }

    /** @param list<string> $sensitive */
    private static function sensitive(Request $r, array $sensitive): bool
    {
        if ($r->method === 'POST') {
            return true;
        }
        $where = $r->path . '?' . $r->query;
        foreach ($sensitive as $ending) {
            if ($ending !== '' && str_contains($where, $ending)) {
                return true;
            }
        }

        return false;
    }
}
