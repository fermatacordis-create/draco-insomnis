<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia;

defined('ABSPATH') || exit;

/** One Guardia scan: inventory → compare with what is stored → store (docs/adr/0001). Read only on the site. */
final class Scanner
{
    private const LOCK = 'draco_guardia_lock';
    private const LOCK_TTL = 300;

    /**
     * @return array{at: int, baseline: bool, restore: bool, truncated: bool, items: int, events: array<string, int>, worst: string}|null
     *         null when another scan is running
     */
    public static function run(): ?array
    {
        if (get_transient(self::LOCK) !== false) {
            return null;
        }
        set_transient(self::LOCK, time(), self::LOCK_TTL);
        try {
            Store::ensure();
            $seen = Inventory::collect();
            $known = Store::known();
            $baseline = $known === [];
            $partial = Inventory::partial();
            // A list this scan could not complete says nothing about what it did not reach.
            foreach ($known as $id => $_) {
                if (isset($partial[Diff::kindOf($id)]) && !isset($seen[$id])) {
                    unset($known[$id]);
                }
            }
            $coreChecked = !isset($partial[Diff::CORE]);
            $coreFirst = !$baseline && $coreChecked && get_option(Store::OPTION_CORE, '') === '';
            $events = $coreFirst ? self::withCoreBaseline($known, $seen) : Diff::compare($known, $seen, $baseline);
            $restore = !$baseline && Diff::looksLikeRestore($events);
            Store::apply($events, $seen, Inventory::labels(), $restore);
            $mailed = Alerts::send($events, Inventory::labels(), $restore);
            $summary = [
                'at' => time(),
                'baseline' => $baseline,
                'restore' => $restore,
                'truncated' => Inventory::truncated(),
                'items' => count($seen),
                'events' => array_count_values(array_column($events, 'event')),
                'worst' => $restore ? Diff::MEDIUM : self::worst(array_column($events, 'severity')),
                'partial' => $partial,
                'mailed' => $mailed,
            ];
            if ($baseline || ($coreFirst && in_array(Diff::BASELINE, array_column($events, 'event'), true))) {
                delete_option(Store::OPTION_REVIEWED);
            }
            if ($coreChecked) {
                update_option(Store::OPTION_CORE, (string) $GLOBALS['wp_version'], false);
            }
            update_option(Store::OPTION_LAST, $summary, false);

            return $summary;
        } finally {
            delete_transient(self::LOCK);
        }
    }

    /**
     * Core files were never checked before (wordpress.org was out of reach, or Guardia predates the check):
     * what is found now is their baseline, not news.
     *
     * @param array<string, array{state: string, fp: string, back: int}> $known
     * @param array<string, array{fp: string, danger?: bool}>             $seen
     * @return list<array{id: string, event: string, state: string, back: int, severity: string, fp: string}>
     */
    private static function withCoreBaseline(array $known, array $seen): array
    {
        $isCore = static fn (string $id): bool => Diff::kindOf($id) === Diff::CORE;
        $pick = static fn (array $a, bool $core): array => array_filter($a, static fn (string $id): bool => $isCore($id) === $core, ARRAY_FILTER_USE_KEY);

        return array_merge(Diff::compare($pick($known, false), $pick($seen, false), false), Diff::compare($pick($known, true), $pick($seen, true), true));
    }

    /** @param list<string> $severities */
    public static function worst(array $severities): string
    {
        $order = [Diff::INFO => 0, Diff::MEDIUM => 1, Diff::HIGH => 2, Diff::CRITICAL_LEVEL => 3];
        $worst = Diff::INFO;
        foreach ($severities as $s) {
            if (($order[$s] ?? 0) > $order[$worst]) {
                $worst = $s;
            }
        }

        return $worst;
    }

    /** @return array{at: int, baseline: bool, restore: bool, truncated: bool, items: int, events: array<string, int>, worst: string}|null */
    public static function last(): ?array
    {
        $last = get_option(Store::OPTION_LAST, null);

        return is_array($last) && isset($last['at']) ? $last : null;
    }
}
