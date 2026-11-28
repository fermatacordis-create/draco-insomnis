<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia;

/**
 * Guardia's e-mail (docs/adr/0001): one message per scan that found something worth a look, to the
 * site's address and the administrators' recovery addresses. Also written to Draco's log.
 */
final class Alerts
{
    public const OPTION = 'draco_guardia_alerts';
    /** E-mails a day at most: the findings stay on screen anyway. */
    private const PER_DAY = 6;
    /** Lines listed in the e-mail. */
    public const LINES = 10;
    private const ORDER = [Diff::INFO => 0, Diff::MEDIUM => 1, Diff::HIGH => 2, Diff::CRITICAL_LEVEL => 3];

    /**
     * Pure: the events worth an e-mail, worst first. In a baseline only what is already high (a modified
     * core file, dangerous code in uploads); afterwards anything medium or worse. Never «gone».
     *
     * @param list<array{id: string, event: string, state: string, back: int, severity: string, fp: string}> $events
     * @return list<array{id: string, event: string, state: string, back: int, severity: string, fp: string}>
     */
    public static function worth(array $events, bool $restore): array
    {
        $out = [];
        foreach ($events as $e) {
            $level = self::ORDER[$e['severity']] ?? 0;
            if ($e['event'] === Diff::GONE || ($restore && $e['event'] === Diff::BACK)) {
                continue;
            }
            if ($e['event'] === Diff::BASELINE ? $level >= self::ORDER[Diff::HIGH] : $level >= self::ORDER[Diff::MEDIUM]) {
                $out[] = $e;
            }
        }
        usort($out, static fn (array $a, array $b): int => (self::ORDER[$b['severity']] ?? 0) <=> (self::ORDER[$a['severity']] ?? 0));

        return $out;
    }

    public static function enabled(): bool
    {
        return get_option(self::OPTION, 'yes') === 'yes';
    }

    /** @return list<string> the site's address and every administrator's recovery addresses, at most 10 */
    public static function recipients(): array
    {
        $out = [];
        $add = static function (string $email) use (&$out): void {
            $email = strtolower(trim($email));
            if (is_email($email) && !in_array($email, $out, true)) {
                $out[] = $email;
            }
        };
        $add((string) get_option('admin_email'));
        foreach (get_users(['role' => 'administrator', 'fields' => 'ID', 'number' => 50]) as $id) {
            foreach (\DracoInsomnis\Login\Recovery::emails((int) $id) as $email) {
                $add($email);
            }
        }

        return array_slice($out, 0, 10);
    }

    /**
     * Sends the e-mail for one scan. Returns how many addresses it went to (0: nothing to say, switched
     * off or over the daily limit).
     *
     * @param list<array{id: string, event: string, state: string, back: int, severity: string, fp: string}> $events all events of the scan
     * @param array<string, string> $labels
     */
    public static function send(array $events, array $labels, bool $restore): int
    {
        $worth = self::worth($events, $restore);
        if (($worth === [] && !$restore) || !self::enabled()) {
            return 0;
        }
        \DracoInsomnis\Shield\Store::ensureTables();
        $ip = '0.0.0.0';
        \DracoInsomnis\Shield\Store::log($ip, $ip, 'guardia:alert', ['score' => 0, 'verdict' => 'human', 'reasons' => ['guardia']], '', [
            'findings' => count($worth),
            'worst' => $worth[0]['severity'] ?? Diff::MEDIUM,
            'restore' => $restore,
            'items' => implode(', ', array_slice(array_column($worth, 'id'), 0, 5)),
        ]);
        if (\DracoInsomnis\Shield\Store::bump('draco_guardia_mail_' . gmdate('Ymd'), DAY_IN_SECONDS) > self::PER_DAY) {
            return 0;
        }
        $to = self::recipients();
        if ($to === []) {
            return 0;
        }
        $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $title = __('Guardia found changes to review', 'draco-insomnis');
        $intro = $restore
            ? __('Many items came back at once: it looks like a restored backup. If you did not restore one, look at the list in Integrity.', 'draco-insomnis')
            /* translators: 1: number of findings, 2: site name */
            : sprintf(__('The last scan of %2$s found %1$d things worth a look:', 'draco-insomnis'), count($worth), $site);
        $lines = [];
        $kinds = Admin::kinds();
        foreach (array_slice($worth, 0, self::LINES) as $e) {
            $lines[] = Admin::severityLabel($e['severity']) . ' · ' . Admin::eventLabel($e['event'], (int) $e['back']) . ' · ' . ($kinds[Diff::kindOf($e['id'])] ?? Diff::kindOf($e['id'])) . ' · ' . ($labels[$e['id']] ?? Diff::keyOf($e['id']));
        }
        if (count($worth) > self::LINES) {
            /* translators: %d: number of findings not listed */
            $lines[] = sprintf(__('… and %d more.', 'draco-insomnis'), count($worth) - self::LINES);
        }
        $tail = __('Guardia only looks: nothing was changed or deleted. If you made these changes yourself, there is nothing to do. Something that comes back after you removed it is the sign of an intrusion that rebuilds itself.', 'draco-insomnis');
        $url = admin_url('admin.php?page=' . Admin::SLUG);
        $plain = $intro . "\n\n" . implode("\n", $lines) . "\n\n" . $tail . "\n\n" . $url;
        $sent = 0;
        foreach ($to as $email) {
            $ok = \DracoInsomnis\Mail\Template::send($email, sprintf('[%s] %s', $site, $title), $plain, $title, array_merge([$intro], $lines), [
                'tone' => 'orange', 'url' => $url, 'button' => __('Open Integrity', 'draco-insomnis'), 'after' => [$tail],
            ]);
            $sent += $ok ? 1 : 0;
        }

        return $sent;
    }
}
