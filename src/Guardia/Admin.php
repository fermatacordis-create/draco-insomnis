<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia;

use DracoInsomnis\Admin\Brand;

defined('ABSPATH') || exit;

/** «Integrity»: take the baseline, review it once, then see only what is new, changes or comes back. */
final class Admin
{
    public const SLUG = 'draco-insomnis-integrity';
    private const ACTION = 'draco_guardia_admin';
    /** Rows of the baseline shown at most (a hacked uploads folder can hold thousands). */
    private const BASELINE_ROWS = 500;

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu'], 11);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
        Scanner::register();
    }

    public static function menu(): void
    {
        if (Brand::nestedParent() !== '') {
            return; // Brand::menuNested() registers it inside the host plugin's menu.
        }
        $title = __('Integrity', 'draco-insomnis');
        add_submenu_page(Brand::PARENT, $title, $title, 'manage_options', self::SLUG, [self::class, 'render']);
    }

    /** The tab's light: off before the first scan, amber until the baseline is reviewed. */
    public static function state(): string
    {
        if (Scanner::last() === null) {
            return 'off';
        }

        return get_option(Store::OPTION_REVIEWED, '') !== '' ? 'on' : 'log';
    }

    public static function save(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'draco-insomnis'), 403);
        }
        check_admin_referer(self::ACTION);
        $do = sanitize_key((string) ($_POST['do'] ?? ''));
        $result = 'ok';
        if ($do === 'scan') {
            $result = Scanner::run() === null ? 'busy' : 'scanned';
        } elseif ($do === 'alerts') {
            update_option(Alerts::OPTION, empty($_POST['alerts']) ? 'no' : 'yes', false);
            update_option(Scanner::OPTION_AUTO, empty($_POST['auto']) ? 'no' : 'yes', false);
            Scanner::schedule();
            $result = 'ok';
        } elseif ($do === 'reviewed') {
            update_option(Store::OPTION_REVIEWED, gmdate('Y-m-d H:i'), false);
            $result = 'reviewed';
        } elseif ($do === 'reset') {
            Store::ensure();
            Store::reset();
            $result = 'reset';
        }
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=' . $result));
        exit;
    }

    public static function render(): void
    {
        $result = sanitize_key((string) ($_GET['result'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        $last = Scanner::last();
        Brand::open(__('Integrity', 'draco-insomnis'), __('Watches administrators, plugins, configuration files, PHP files in uploads and scheduled tasks. The first scan is the baseline, which you review once; after that only what is new, changes or comes back after being removed is shown. Guardia only looks: it never changes or deletes anything.', 'draco-insomnis') . ' ' . __('WordPress core files are compared with the official checksums from wordpress.org.', 'draco-insomnis'));
        if ($result === 'busy') {
            Brand::notice('warning', __('A scan is already running. Try again in a few minutes.', 'draco-insomnis'));
        } elseif ($result === 'scanned' && $last !== null) {
            $mailed = (int) ($last['mailed'] ?? 0);
            /* translators: %d: number of addresses */
            Brand::notice($last['worst'] === Diff::HIGH || $last['worst'] === Diff::CRITICAL_LEVEL ? 'error' : 'success', self::summary($last) . ($mailed > 0 ? ' ' . sprintf(__('An e-mail went to %d addresses.', 'draco-insomnis'), $mailed) : ''));
        } elseif ($result === 'ok') {
            Brand::notice('success', __('Changes saved.', 'draco-insomnis'));
        } elseif ($result === 'reviewed') {
            Brand::notice('success', __('Baseline marked as reviewed.', 'draco-insomnis'));
        } elseif ($result === 'reset') {
            Brand::notice('success', __('Guardia was emptied. The next scan takes a new baseline.', 'draco-insomnis'));
        }
        if ($last !== null && isset($last['partial'][Diff::CORE])) {
            /* translators: %s: reason, such as «wordpress.org answered HTTP 503.» */
            Brand::notice('warning', sprintf(__('WordPress core files were not checked in the last scan: %s They are checked again on the next one.', 'draco-insomnis'), (string) $last['partial'][Diff::CORE]));
        }
        if ($last !== null && $last['truncated']) {
            /* translators: %d: number of files */
            Brand::notice('error', sprintf(__('Uploads holds more than %d PHP files: only the first ones were looked at. Media folders should hold none.', 'draco-insomnis'), Inventory::MAX_UPLOAD_FILES));
        }

        $state = self::state();
        Brand::card('visibility', __('Scan', 'draco-insomnis'), $last === null ? __('No scan yet.', 'draco-insomnis') : self::lastLine($last), Brand::pill(Brand::stateLabel($state), $state));
        echo self::form('scan'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        submit_button($last === null ? __('Take the baseline', 'draco-insomnis') : __('Scan now', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';
        if ($last !== null) {
            $counts = Store::counts();
            echo '<p class="description" style="margin-top:10px">';
            $parts = [];
            foreach (self::kinds() as $kind => $label) {
                $parts[] = esc_html($label) . ': <strong>' . (int) ($counts[$kind] ?? 0) . '</strong>';
            }
            echo implode(' · ', $parts) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above
        }
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:14px">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="alerts">';
        $next = Scanner::next();
        Brand::toggle('auto', Scanner::autoEnabled(), __('Scan by itself twice a day', 'draco-insomnis'), $last === null ? __('Starts after you take the baseline.', 'draco-insomnis') : (Scanner::inProgress() ? __('A scan is going on now, a few seconds at a time.', 'draco-insomnis')
            /* translators: %s: date and time (UTC) */
            : ($next !== false ? sprintf(__('Next one: %s UTC. It reads files a few seconds at a time, so the site does not slow down.', 'draco-insomnis'), gmdate('Y-m-d H:i', (int) $next)) : '')));
        $to = Alerts::recipients();
        /* translators: %s: e-mail addresses */
        Brand::toggle('alerts', Alerts::enabled(), __('E-mail me when a scan finds something medium or worse', 'draco-insomnis'), $to !== [] ? sprintf(__('To %s: the site address and the administrators\' recovery e-mails. At most 6 a day.', 'draco-insomnis'), implode(', ', $to)) : '');
        submit_button(__('Save', 'draco-insomnis'), 'secondary', 'submit', false);
        echo '</form>';
        Brand::cardEnd();

        if ($last !== null && get_option(Store::OPTION_REVIEWED, '') === '') {
            self::baselineCard();
        }
        if ($last !== null) {
            self::findingsCard();
            self::resetCard();
        }
        Brand::close();
    }

    /** @param array{at: int, baseline: bool, restore: bool, truncated: bool, items: int, events: array<string, int>, worst: string} $last */
    private static function summary(array $last): string
    {
        if ($last['baseline']) {
            /* translators: %d: number of items */
            return sprintf(__('Baseline taken: %d items. Review the list below once.', 'draco-insomnis'), $last['items']);
        }
        if ($last['restore']) {
            return __('Many items came back at once: it looks like a restored backup. Check that you restored one.', 'draco-insomnis');
        }
        $e = $last['events'];
        $news = (int) ($e[Diff::NEW] ?? 0) + (int) ($e[Diff::CHANGED] ?? 0) + (int) ($e[Diff::BACK] ?? 0);
        if ($news === 0) {
            return __('Scan finished: nothing new.', 'draco-insomnis');
        }

        /* translators: 1: new items, 2: changed items, 3: items that came back */
        return sprintf(__('Scan finished: %1$d new, %2$d changed, %3$d came back.', 'draco-insomnis'), (int) ($e[Diff::NEW] ?? 0), (int) ($e[Diff::CHANGED] ?? 0), (int) ($e[Diff::BACK] ?? 0));
    }

    /** @param array<string, mixed> $last */
    private static function lastLine(array $last): string
    {
        /* translators: 1: date and time (UTC), 2: number of items */
        return sprintf(__('Last scan: %1$s UTC · %2$d items watched', 'draco-insomnis'), gmdate('Y-m-d H:i', (int) $last['at']), (int) $last['items'])
            . (!empty($last['auto']) ? ' · ' . __('automatic', 'draco-insomnis') : '');
    }

    private static function baselineCard(): void
    {
        $rows = Store::baseline();
        Brand::card('list-view', __('Review the baseline', 'draco-insomnis'), __('What was already on the site at the first scan. Check that you know every administrator, must-use plugin and PHP file in uploads: one you do not recognise may be left over from an old intrusion.', 'draco-insomnis'), '', 'warn');
        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Type', 'draco-insomnis') . '</th><th>' . esc_html__('Item', 'draco-insomnis') . '</th><th>' . esc_html__('Level', 'draco-insomnis') . '</th></tr></thead><tbody>';
        $kinds = self::kinds();
        $shown = 0;
        foreach ($rows as $r) {
            if (++$shown > self::BASELINE_ROWS) {
                break;
            }
            $sev = (string) ($r['severity'] ?? Diff::INFO);
            echo '<tr><td>' . esc_html($kinds[(string) $r['kind']] ?? (string) $r['kind']) . '</td><td><code>' . esc_html((string) ($r['label'] !== '' ? $r['label'] : $r['item_key'])) . '</code></td><td>' . ($sev === Diff::INFO ? '' : self::severityPill($sev)) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill escapes
        }
        if ($rows === []) {
            Brand::emptyRow(3, __('Nothing in the baseline.', 'draco-insomnis'));
        }
        echo '</tbody></table></div>';
        if (count($rows) > self::BASELINE_ROWS) {
            /* translators: %d: number of rows shown */
            echo '<p class="description">' . esc_html(sprintf(__('Only the first %d are shown.', 'draco-insomnis'), self::BASELINE_ROWS)) . '</p>';
        }
        echo '<p style="margin-top:12px">' . self::form('reviewed'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        submit_button(__('I have reviewed this list', 'draco-insomnis'), 'secondary', 'submit', false);
        echo '</form></p>';
        Brand::cardEnd();
    }

    private static function findingsCard(): void
    {
        $rows = Store::findings();
        Brand::card('warning', __('Findings', 'draco-insomnis'), __('What appeared, changed or came back after the baseline, newest first. Something that comes back after being removed rebuilds itself: each return raises the level.', 'draco-insomnis'));
        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>' . esc_html__('What', 'draco-insomnis') . '</th><th>' . esc_html__('Type', 'draco-insomnis') . '</th><th>' . esc_html__('Item', 'draco-insomnis') . '</th><th>' . esc_html__('Level', 'draco-insomnis') . '</th></tr></thead><tbody>';
        $kinds = self::kinds();
        foreach ($rows as $r) {
            echo '<tr><td>' . esc_html(substr((string) $r['observed_at'], 0, 16)) . '</td><td>' . esc_html(self::eventLabel((string) $r['event'], (int) $r['back_count'])) . '</td><td>' . esc_html($kinds[(string) $r['kind']] ?? (string) $r['kind'])
                . '</td><td><code>' . esc_html((string) ($r['details'] !== '' ? $r['details'] : $r['item_key'])) . '</code></td><td>' . self::severityPill((string) $r['severity']) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill escapes
        }
        if ($rows === []) {
            Brand::emptyRow(5, __('Nothing new since the baseline.', 'draco-insomnis'));
        }
        echo '</tbody></table></div>';
        Brand::cardEnd();
    }

    private static function resetCard(): void
    {
        Brand::card('backup', __('Start again', 'draco-insomnis'), __('The next scan takes a new baseline. Only after cleaning the site, or if the baseline was taken on a site you did not trust.', 'draco-insomnis'));
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" onsubmit="return confirm(' . esc_attr(wp_json_encode(__('Empty Guardia and take a new baseline on the next scan?', 'draco-insomnis'))) . ')">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="reset">';
        submit_button(__('Empty Guardia', 'draco-insomnis'), 'secondary', 'submit', false);
        echo '</form>';
        Brand::cardEnd();
    }

    private static function form(string $do): string
    {
        return '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline">'
            . wp_nonce_field(self::ACTION, '_wpnonce', true, false)
            . '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="' . esc_attr($do) . '">';
    }

    /** @return array<string, string> */
    public static function kinds(): array
    {
        return [
            Diff::CORE => __('WordPress core file', 'draco-insomnis'),
            Diff::ADMIN => __('Administrator', 'draco-insomnis'),
            Diff::MU_PLUGIN => __('Must-use plugin', 'draco-insomnis'),
            Diff::DROPIN => __('Drop-in', 'draco-insomnis'),
            Diff::UPLOAD_PHP => __('PHP file in uploads', 'draco-insomnis'),
            Diff::CRON => __('Scheduled task without code', 'draco-insomnis'),
            Diff::CRITICAL => __('Configuration file', 'draco-insomnis'),
            Diff::PLUGIN => __('Active plugin', 'draco-insomnis'),
        ];
    }

    public static function eventLabel(string $event, int $back): string
    {
        if ($event === Diff::BACK) {
            /* translators: %d: how many times it came back */
            return sprintf(__('Came back after being removed (%d×)', 'draco-insomnis'), $back);
        }
        $labels = [
            Diff::NEW => __('New', 'draco-insomnis'),
            Diff::CHANGED => __('Changed', 'draco-insomnis'),
            Diff::RESTORE => __('Back with a restored backup', 'draco-insomnis'),
        ];

        return $labels[$event] ?? $event;
    }

    public static function severityLabel(string $severity): string
    {
        $labels = [
            Diff::INFO => __('Note', 'draco-insomnis'),
            Diff::MEDIUM => __('Medium', 'draco-insomnis'),
            Diff::HIGH => __('High', 'draco-insomnis'),
            Diff::CRITICAL_LEVEL => __('Critical', 'draco-insomnis'),
        ];

        return $labels[$severity] ?? $severity;
    }

    private static function severityPill(string $severity): string
    {
        $tones = [Diff::MEDIUM => 'warn', Diff::HIGH => 'bad', Diff::CRITICAL_LEVEL => 'bad'];

        return Brand::pill(self::severityLabel($severity), $tones[$severity] ?? 'off');
    }

    /**
     * The two lines of the Overview card.
     *
     * @return array{0: string, 1: string}
     */
    public static function facts(): array
    {
        $last = Scanner::last();
        if ($last === null) {
            return [__('No scan yet.', 'draco-insomnis'), __('Takes a baseline of the site, then shows only what is new or comes back.', 'draco-insomnis')];
        }
        $serious = 0;
        foreach (Store::findings(50) as $f) {
            if (in_array($f['severity'], [Diff::HIGH, Diff::CRITICAL_LEVEL], true) && strtotime((string) $f['observed_at'] . ' UTC') > time() - 30 * DAY_IN_SECONDS) {
                $serious++;
            }
        }

        return [
            self::lastLine($last),
            /* translators: %d: number of findings */
            $serious > 0 ? sprintf(__('%d high or critical findings in the last 30 days.', 'draco-insomnis'), $serious) : __('Nothing high or critical in the last 30 days.', 'draco-insomnis'),
        ];
    }
}
