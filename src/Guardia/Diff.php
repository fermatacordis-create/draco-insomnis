<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia;

/**
 * Guardia's core, without WordPress (docs/adr/0001): what one scan means for each watched item.
 *
 * Persistence is a sequence, not a difference between two snapshots: an item has to be seen, then
 * found missing, then seen again. The first scan is the baseline: what is there is accepted and listed
 * once for review; afterwards only what is new, changes or comes back is reported.
 */
final class Diff
{
    /** Kinds of item. */
    public const ADMIN = 'admin';
    public const PLUGIN = 'plugin';
    public const MU_PLUGIN = 'mu_plugin';
    public const DROPIN = 'dropin';
    public const CRITICAL = 'critical';
    public const UPLOAD_PHP = 'upload_php';
    public const CRON = 'cron';

    /** States. */
    public const PRESENT = 'present';
    public const MISSING = 'missing';
    public const REAPPEARED = 'reappeared';

    /** Events of one scan. */
    public const BASELINE = 'baseline';
    public const NEW = 'new';
    public const CHANGED = 'changed';
    public const GONE = 'gone';
    public const BACK = 'back';
    public const RESTORE = 'restore';

    /** Severities. */
    public const INFO = 'info';
    public const MEDIUM = 'medium';
    public const HIGH = 'high';
    public const CRITICAL_LEVEL = 'critical';

    /** This many items back in the same scan look like a restored backup: one finding to review. */
    public const RESTORE_AT = 5;

    /**
     * @param array<string, array{state: string, fp: string, back: int}> $known   «kind|key» => what was stored
     * @param array<string, array{fp: string, danger?: bool}>             $seen    «kind|key» => what this scan found
     * @param bool $baseline true when nothing is stored yet (first scan)
     * @return list<array{id: string, event: string, state: string, back: int, severity: string, fp: string}>
     */
    public static function compare(array $known, array $seen, bool $baseline): array
    {
        $out = [];
        foreach ($seen as $id => $now) {
            $fp = (string) $now['fp'];
            $danger = !empty($now['danger']);
            if (!isset($known[$id])) {
                $event = $baseline ? self::BASELINE : self::NEW;
                $out[] = ['id' => $id, 'event' => $event, 'state' => self::PRESENT, 'back' => 0, 'severity' => $baseline ? ($danger ? self::HIGH : self::INFO) : self::newSeverity(self::kindOf($id), $danger), 'fp' => $fp];
                continue;
            }
            $was = $known[$id];
            if ($was['state'] === self::MISSING) {
                $back = (int) $was['back'] + 1;
                $out[] = ['id' => $id, 'event' => self::BACK, 'state' => self::REAPPEARED, 'back' => $back, 'severity' => self::backSeverity($back), 'fp' => $fp];
                continue;
            }
            if ($fp !== '' && $was['fp'] !== '' && $fp !== $was['fp'] && self::fingerprintMatters(self::kindOf($id))) {
                $out[] = ['id' => $id, 'event' => self::CHANGED, 'state' => $was['state'], 'back' => (int) $was['back'], 'severity' => self::changedSeverity(self::kindOf($id), $danger), 'fp' => $fp];
            }
        }
        foreach ($known as $id => $was) {
            if (!isset($seen[$id]) && $was['state'] !== self::MISSING) {
                $out[] = ['id' => $id, 'event' => self::GONE, 'state' => self::MISSING, 'back' => (int) $was['back'], 'severity' => self::INFO, 'fp' => $was['fp']];
            }
        }

        return $out;
    }

    /**
     * Many items back at once is a restored backup, not an attack that brings each one back: the
     * individual events stay (states and counts must be right) but are not alerted one by one.
     *
     * @param list<array{event: string}> $events
     */
    public static function looksLikeRestore(array $events): bool
    {
        return count(array_filter($events, static fn (array $e): bool => $e['event'] === self::BACK)) >= self::RESTORE_AT;
    }

    public static function kindOf(string $id): string
    {
        return (string) strstr($id, '|', true);
    }

    public static function keyOf(string $id): string
    {
        return (string) substr((string) strstr($id, '|'), 1);
    }

    /** Something new after the baseline. */
    private static function newSeverity(string $kind, bool $danger): string
    {
        if ($danger || in_array($kind, [self::ADMIN, self::MU_PLUGIN, self::DROPIN], true)) {
            return self::HIGH;
        }

        return $kind === self::UPLOAD_PHP || $kind === self::CRON ? self::MEDIUM : self::INFO;
    }

    /** Once medium, twice high, three times or more critical. */
    public static function backSeverity(int $back): string
    {
        return $back >= 3 ? self::CRITICAL_LEVEL : ($back === 2 ? self::HIGH : self::MEDIUM);
    }

    private static function changedSeverity(string $kind, bool $danger): string
    {
        if ($danger) {
            return self::HIGH;
        }

        return in_array($kind, [self::CRITICAL, self::MU_PLUGIN, self::DROPIN], true) ? self::MEDIUM : self::INFO;
    }

    /** A plugin's version changes with every update; an administrator's e-mail is worth a note. */
    private static function fingerprintMatters(string $kind): bool
    {
        return $kind !== self::PLUGIN;
    }

    /** Dangerous calls in a PHP file found where only images and documents belong. */
    public static function dangerous(string $code): bool
    {
        return preg_match('/\b(eval|assert|gzinflate|gzuncompress|str_rot13|shell_exec|passthru|proc_open|popen|system)\s*\(|base64_decode\s*\(\s*\$|preg_replace\s*\(\s*[\'"].*\/e[\'"]|\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\(/i', $code) === 1;
    }
}
