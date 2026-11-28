<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia;

defined('ABSPATH') || exit;

/**
 * One Guardia scan: inventory → compare with what is stored → store → e-mail (docs/adr/0001). Read only
 * on the site. «Scan now» does it in one request; the scheduled scan (twice a day) reads files in slices
 * of a few seconds, one request after another, and finishes in the request that reads the last one.
 */
final class Scanner
{
    public const HOOK = 'draco_guardia_scan';
    public const HOOK_STEP = 'draco_guardia_step';
    public const OPTION_AUTO = 'draco_guardia_auto';
    private const OPTION_JOB = 'draco_guardia_job';
    private const LOCK = 'draco_guardia_lock';
    private const LOCK_TTL = 300;
    /** Seconds of reading per scheduled request, at most. */
    private const BUDGET = 20;
    /** A job older than this is started again (a step was lost, or the files changed under it for too long). */
    private const JOB_MAX_AGE = 6 * HOUR_IN_SECONDS;

    public static function register(): void
    {
        add_action(self::HOOK, [self::class, 'tick']);
        add_action(self::HOOK_STEP, [self::class, 'step']);
        add_action('init', [self::class, 'schedule']);
    }

    public static function autoEnabled(): bool
    {
        return get_option(self::OPTION_AUTO, 'yes') === 'yes';
    }

    /** Twice a day once there is a baseline (taken by a person, who then reviews it) and it is switched on. */
    public static function schedule(): void
    {
        $wanted = self::autoEnabled() && self::last() !== null;
        $next = wp_next_scheduled(self::HOOK);
        if ($wanted && $next === false) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'twicedaily', self::HOOK);
        } elseif (!$wanted && $next !== false) {
            self::unschedule();
        }
    }

    public static function unschedule(): void
    {
        wp_clear_scheduled_hook(self::HOOK);
        wp_clear_scheduled_hook(self::HOOK_STEP);
        delete_option(self::OPTION_JOB);
    }

    /** @return int|false when the next scheduled scan starts */
    public static function next()
    {
        return wp_next_scheduled(self::HOOK);
    }

    /** True while a scheduled scan is half done. */
    public static function inProgress(): bool
    {
        return is_array(get_option(self::OPTION_JOB, null));
    }

    /**
     * The whole scan now («Scan now»).
     *
     * @return array<string, mixed>|null null when another scan is running
     */
    public static function run(): ?array
    {
        if (!self::lock()) {
            return null;
        }
        try {
            delete_option(self::OPTION_JOB);
            wp_clear_scheduled_hook(self::HOOK_STEP);
            $job = Inventory::start();
            Inventory::advance($job, INF);

            return self::finish($job, false);
        } finally {
            delete_transient(self::LOCK);
        }
    }

    /** A follow-up slice only resumes a job: one left over after the job finished must not start a new scan. */
    public static function step(): void
    {
        if (self::inProgress()) {
            self::tick();
        }
    }

    /** One scheduled slice: start or resume the job, read for a few seconds, finish or schedule the next slice. */
    public static function tick(): void
    {
        if (!self::autoEnabled() || !self::lock()) {
            return;
        }
        try {
            $job = get_option(self::OPTION_JOB, null);
            if (!is_array($job) || (int) ($job['started'] ?? 0) < time() - self::JOB_MAX_AGE) {
                $job = Inventory::start();
            }
            if (Inventory::advance($job, microtime(true) + self::budget())) {
                delete_option(self::OPTION_JOB);
                wp_clear_scheduled_hook(self::HOOK_STEP);
                self::finish($job, true);

                return;
            }
            update_option(self::OPTION_JOB, $job, false);
            if (!wp_next_scheduled(self::HOOK_STEP)) {
                wp_schedule_single_event(time() + MINUTE_IN_SECONDS, self::HOOK_STEP);
            }
        } finally {
            delete_transient(self::LOCK);
        }
    }

    /** Half of PHP's time limit, at most BUDGET seconds; hosts with a short limit can lower it with a filter. */
    private static function budget(): float
    {
        $limit = (int) ini_get('max_execution_time');
        $default = (float) ($limit > 0 ? max(5, min(self::BUDGET, intdiv($limit, 2))) : self::BUDGET);

        /**
         * Seconds of reading per scheduled request.
         *
         * @param float $default Half of max_execution_time, at most 20.
         */
        return max(0.01, (float) apply_filters('draco_insomnis_guardia_budget', $default));
    }

    private static function lock(): bool
    {
        if (get_transient(self::LOCK) !== false) {
            return false;
        }
        set_transient(self::LOCK, time(), self::LOCK_TTL);

        return true;
    }

    /**
     * @param array<string, mixed> $job a complete inventory
     * @return array<string, mixed> the summary kept as the last scan
     */
    private static function finish(array $job, bool $auto): array
    {
        Store::ensure();
        /** @var array<string, array{fp: string, danger?: bool}> $seen */
        $seen = $job['items'];
        /** @var array<string, string> $labels */
        $labels = $job['labels'];
        /** @var array<string, string> $partial */
        $partial = $job['partial'];
        $known = Store::known();
        $baseline = $known === [];
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
        Store::apply($events, $seen, $labels, $restore);
        $mailed = Alerts::send($events, $labels, $restore);
        $summary = [
            'at' => time(),
            'auto' => $auto,
            'baseline' => $baseline,
            'restore' => $restore,
            'truncated' => (bool) $job['truncated'],
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

    /** @return array<string, mixed>|null */
    public static function last(): ?array
    {
        $last = get_option(Store::OPTION_LAST, null);

        return is_array($last) && isset($last['at']) ? $last : null;
    }
}
