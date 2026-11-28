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
            $events = Diff::compare($known, $seen, $baseline);
            $restore = !$baseline && Diff::looksLikeRestore($events);
            Store::apply($events, $seen, Inventory::labels(), $restore);
            $summary = [
                'at' => time(),
                'baseline' => $baseline,
                'restore' => $restore,
                'truncated' => Inventory::truncated(),
                'items' => count($seen),
                'events' => array_count_values(array_column($events, 'event')),
                'worst' => $restore ? Diff::MEDIUM : self::worst(array_column($events, 'severity')),
            ];
            if ($baseline) {
                delete_option(Store::OPTION_REVIEWED);
            }
            update_option(Store::OPTION_LAST, $summary, false);

            return $summary;
        } finally {
            delete_transient(self::LOCK);
        }
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
