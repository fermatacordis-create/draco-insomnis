<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia\Advisories;

use DracoInsomnis\Guardia\Diff;

/**
 * Known vulnerabilities, without WordPress: which advisories apply to an installed version.
 *
 * An advisory is normalised to: uuid, name, min/max version with their operators, unfixed, CVE ids,
 * CVSS severity, score and vector, and a reference link. Versions are compared here, on the site: the
 * provider only ever learns the slug that was asked about.
 */
final class Matcher
{
    /**
     * Normalises one WPVulnerability record.
     *
     * @param array<string, mixed> $r
     * @return array{uuid: string, name: string, min: ?string, min_op: ?string, max: ?string, max_op: ?string, unfixed: bool, cve: list<string>, severity: string, score: float, unauth: bool, link: string}
     */
    public static function fromWpVulnerability(array $r): array
    {
        $op = is_array($r['operator'] ?? null) ? $r['operator'] : [];
        $cvss = is_array($r['impact']['cvss'] ?? null) ? $r['impact']['cvss'] : [];
        $cve = [];
        $link = '';
        foreach (is_array($r['source'] ?? null) ? $r['source'] : [] as $s) {
            $id = (string) ($s['id'] ?? '');
            if (preg_match('/^CVE-\d{4}-\d{4,}$/', $id) === 1) {
                $cve[] = $id;
            }
            if ($link === '' && is_string($s['link'] ?? null)) {
                $link = (string) $s['link'];
            }
        }

        return [
            'uuid' => (string) ($r['uuid'] ?? md5((string) ($r['name'] ?? ''))),
            'name' => (string) ($r['name'] ?? ''),
            'min' => self::str($op['min_version'] ?? null),
            'min_op' => self::str($op['min_operator'] ?? null),
            'max' => self::str($op['max_version'] ?? null),
            'max_op' => self::str($op['max_operator'] ?? null),
            'unfixed' => (string) ($op['unfixed'] ?? '0') === '1',
            'cve' => array_values(array_unique($cve)),
            'severity' => self::severity(self::str($cvss['severity'] ?? null), (float) ($cvss['score'] ?? 0)),
            'score' => (float) ($cvss['score'] ?? 0),
            'unauth' => strtolower((string) ($cvss['pr'] ?? '')) === 'n',
            'link' => $link,
        ];
    }

    /** CVSS letter (c, h, m, l) to Guardia's levels; unknown counts as medium, never as nothing. */
    public static function severity(?string $letter, float $score): string
    {
        $letter = strtolower((string) $letter);
        if ($letter === '' && $score > 0) {
            $letter = $score >= 9 ? 'c' : ($score >= 7 ? 'h' : ($score >= 4 ? 'm' : 'l'));
        }

        return match ($letter) {
            'c' => Diff::CRITICAL_LEVEL,
            'h' => Diff::HIGH,
            'l', 'n' => Diff::INFO,
            default => Diff::MEDIUM,
        };
    }

    /**
     * Whether $installed falls in the advisory's range. No upper bound and «unfixed»: every version from
     * the lower bound on.
     *
     * @param array{min: ?string, min_op: ?string, max: ?string, max_op: ?string, unfixed: bool} $a
     */
    public static function affects(array $a, string $installed): bool
    {
        $installed = self::clean($installed);
        if ($installed === '') {
            return false;
        }
        if ($a['min'] !== null && !version_compare($installed, self::clean($a['min']), self::op($a['min_op'], 'ge'))) {
            return false;
        }
        if ($a['max'] !== null) {
            return version_compare($installed, self::clean($a['max']), self::op($a['max_op'], 'lt'));
        }

        return $a['unfixed'];
    }

    /**
     * The version that fixes it, or '' when none is known («unfixed», or only «up to and including»).
     *
     * @param array{max: ?string, max_op: ?string, unfixed: bool} $a
     */
    public static function fixedIn(array $a): string
    {
        if (isset($a['fixed']) && is_string($a['fixed'])) {
            return $a['fixed']; // the source names the patched version itself (Wordfence)
        }

        return !$a['unfixed'] && $a['max'] !== null && self::op($a['max_op'], 'lt') === 'lt' ? $a['max'] : '';
    }

    /**
     * The update to propose for $installed: with a list of patched versions (one per branch for WordPress
     * core), the lowest one above the installed version; otherwise what fixedIn() knows.
     *
     * @param array<string, mixed> $a
     */
    public static function fixFor(array $a, string $installed): string
    {
        if (!isset($a['patched']) || !is_array($a['patched']) || $a['patched'] === []) {
            return self::fixedIn($a);
        }
        $installed = self::clean($installed);
        foreach ($a['patched'] as $p) { // sorted ascending
            if (version_compare((string) $p, $installed, '>')) {
                return (string) $p;
            }
        }

        return '';
    }

    /**
     * One record of the OPNV index of Wordfence Intelligence (format 1): one normalised advisory per affected
     * range. «*» is any version; the fix is the lowest patched version above the range.
     *
     * @param array<string, mixed> $r {id, t, r: list<[from, from_inclusive, to, to_inclusive]>, p, sev, s, u, cve, l, c}
     * @return list<array<string, mixed>>
     */
    public static function fromOpnvIndex(array $r): array
    {
        $patched = array_values(array_filter(array_map('strval', (array) ($r['p'] ?? [])), static fn (string $v): bool => $v !== ''));
        usort($patched, 'version_compare');
        $sev = in_array($r['sev'] ?? '', [Diff::INFO, Diff::MEDIUM, Diff::HIGH, Diff::CRITICAL_LEVEL], true) ? (string) $r['sev'] : Diff::MEDIUM;
        $out = [];
        foreach ((array) ($r['r'] ?? []) as $range) {
            if (!is_array($range) || count($range) < 4) {
                continue;
            }
            [$from, $fromIn, $to, $toIn] = [(string) $range[0], (bool) $range[1], (string) $range[2], (bool) $range[3]];
            $fixed = '';
            foreach ($patched as $p) {
                if ($to === '*' || version_compare($p, $to, $toIn ? '>' : '>=')) {
                    $fixed = $p;
                    break;
                }
            }
            $out[] = [
                'uuid' => (string) ($r['id'] ?? ''),
                'name' => (string) ($r['t'] ?? ''),
                'min' => $from === '*' ? null : $from,
                'min_op' => $fromIn ? 'ge' : 'gt',
                'max' => $to === '*' ? null : $to,
                'max_op' => $toIn ? 'le' : 'lt',
                'unfixed' => $to === '*',
                'fixed' => $fixed,
                'patched' => $patched,
                'cve' => preg_match('/^CVE-\d{4}-\d{4,}$/', (string) ($r['cve'] ?? '')) === 1 ? [(string) $r['cve']] : [],
                'severity' => $sev,
                'score' => (float) ($r['s'] ?? 0),
                'unauth' => (bool) ($r['u'] ?? false),
                'link' => (string) ($r['l'] ?? ''),
                'notices' => array_values(array_map('intval', (array) ($r['c'] ?? []))),
            ];
        }

        return $out;
    }

    /**
     * Every advisory that applies to every installed item, worst first.
     *
     * @param list<array{type: string, slug: string, version: string, name: string, active: bool}> $installed
     * @param array<string, list<array<string, mixed>>> $advisories «type|slug» => normalised advisories
     * @return list<array{type: string, slug: string, name: string, version: string, active: bool, uuid: string, title: string, severity: string, score: float, unauth: bool, cve: list<string>, fixed: string, link: string}>
     */
    public static function match(array $installed, array $advisories): array
    {
        $out = [];
        $seen = [];
        foreach ($installed as $item) {
            foreach ($advisories[$item['type'] . '|' . $item['slug']] ?? [] as $a) {
                $once = $item['type'] . '|' . $item['slug'] . '|' . (string) $a['uuid'];
                if (isset($seen[$once]) || !self::affects($a, $item['version'])) {
                    continue; // a record with several ranges is listed once
                }
                $seen[$once] = true;
                $out[] = [
                    'type' => $item['type'], 'slug' => $item['slug'], 'name' => $item['name'], 'version' => $item['version'], 'active' => $item['active'],
                    'uuid' => (string) $a['uuid'], 'title' => (string) $a['name'], 'severity' => (string) $a['severity'], 'score' => (float) $a['score'],
                    'unauth' => (bool) $a['unauth'], 'cve' => $a['cve'], 'fixed' => self::fixFor($a, $item['version']), 'link' => (string) $a['link'],
                    'notices' => (array) ($a['notices'] ?? []),
                ];
            }
        }
        $order = [Diff::CRITICAL_LEVEL => 3, Diff::HIGH => 2, Diff::MEDIUM => 1, Diff::INFO => 0];
        usort($out, static fn (array $x, array $y): int => [$order[$y['severity']] ?? 0, $y['score']] <=> [$order[$x['severity']] ?? 0, $x['score']]);

        return $out;
    }

    private static function op(?string $op, string $default): string
    {
        $op = strtolower((string) $op);

        return in_array($op, ['lt', 'le', 'gt', 'ge', 'eq'], true) ? $op : $default;
    }

    private static function clean(string $v): string
    {
        return trim(ltrim(trim($v), 'vV'));
    }

    private static function str(mixed $v): ?string
    {
        return is_scalar($v) && (string) $v !== '' ? (string) $v : null;
    }
}
