<?php

declare(strict_types=1);

namespace DracoInsomnis\Shield;

use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Core\Abuse;
use DracoInsomnis\Core\Review;

defined('ABSPATH') || exit;

/**
 * Abuse reports, always reviewed by a person: Draco finds the network's abuse contact (RDAP) and
 * writes a draft with the evidence; the administrator reads, edits and sends it. At most
 * Abuse::DAILY_CAP a day and one per address every 30 days. Every report sent is kept as a row of
 * evidence (endpoint "abuse_report").
 */
final class AbuseReport
{
    private const ACTION = 'draco_abuse_send';
    private const VIEW = 'draco_abuse_view';

    public static function register(): void
    {
        add_action('admin_post_' . self::ACTION, [self::class, 'send']);
    }

    /** The link next to "Evidence". */
    public static function url(string $ip): string
    {
        return wp_nonce_url(admin_url('admin.php?page=' . Admin::SLUG . '&report=' . rawurlencode($ip)), self::VIEW);
    }

    /** True when the shield page must show a report instead of its usual content. */
    public static function wanted(): bool
    {
        return isset($_GET['report']); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- render() checks the nonce
    }

    /** @return list<array<string, mixed>> */
    private static function evidence(string $ip): array
    {
        return array_values(array_filter(Store::byIp($ip), static fn (array $r): bool => !in_array((string) $r['endpoint'], [Abuse::ENDPOINT, Review::ENDPOINT], true)));
    }

    /** @return list<array{created_at: string, ip: string}> */
    private static function sent(): array
    {
        return array_map(static fn (array $r): array => ['created_at' => (string) $r['created_at'], 'ip' => (string) $r['ip']], Store::recentWhere(Abuse::ENDPOINT, 200));
    }

    /** RDAP over WordPress's HTTP API (rdap.org forwards to the right regional registry). */
    public static function fetch(string $url): ?string
    {
        $r = wp_remote_get($url, ['timeout' => 15, 'redirection' => 5, 'user-agent' => 'Draco-Insomnis', 'headers' => ['Accept' => 'application/rdap+json']]);

        return !is_wp_error($r) && (int) wp_remote_retrieve_response_code($r) === 200 ? (string) wp_remote_retrieve_body($r) : null;
    }

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'draco-insomnis'), 403);
        }
        check_admin_referer(self::VIEW);
        $ip = (string) filter_var(wp_unslash((string) ($_GET['report'] ?? '')), FILTER_VALIDATE_IP);
        $back = admin_url('admin.php?page=' . Admin::SLUG);
        Brand::open(__('Abuse report', 'draco-insomnis'), __('Tell the network that owns the address what its machine did, so they can look at it. Most attacking machines are compromised: their owners are victims too. Nothing is sent until you press Send.', 'draco-insomnis'));
        $rows = $ip === '' ? [] : self::evidence($ip);
        if ($rows === []) {
            Brand::notice('error', __('There is no evidence from this address.', 'draco-insomnis'));
            echo '<p><a href="' . esc_url($back) . '">' . esc_html__('Back', 'draco-insomnis') . '</a></p>';
            Brand::close();

            return;
        }
        $contact = Abuse::contact($ip, [self::class, 'fetch']);
        $draft = Abuse::draft($ip, $rows, home_url('/'), $contact);
        $refusal = Abuse::refusal($ip, self::sent(), time());

        Brand::card('email-alt', $ip, $contact['network'] !== '' ? $contact['network'] . ($contact['range'] !== '' ? ' · ' . $contact['range'] : '') . ($contact['registry'] !== '' ? ' · ' . $contact['registry'] : '') : '', $refusal === '' ? '' : Brand::pill(__('Not now', 'draco-insomnis'), 'warn'));
        if ($contact['error'] !== '') {
            /* translators: %s: why the registry gave no abuse contact */
            Brand::notice('warning', sprintf(__('The registry gave no abuse contact (%s). Write the address yourself if you know it.', 'draco-insomnis'), $contact['error']));
        }
        if ($refusal !== '') {
            /* translators: %s: why no more reports can be sent now */
            Brand::notice('warning', sprintf(__('Not sent now: %s.', 'draco-insomnis'), $refusal));
        }
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">' . wp_nonce_field(self::ACTION, '_wpnonce', true, false); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="ip" value="' . esc_attr($ip) . '">';
        echo '<div class="draco-field"><label for="draco-ab-to">' . esc_html__('To (abuse contact of the network)', 'draco-insomnis') . '</label><input id="draco-ab-to" type="email" name="to" class="large-text" value="' . esc_attr($contact['email']) . '" required></div>';
        echo '<div class="draco-field"><label for="draco-ab-subject">' . esc_html__('Subject', 'draco-insomnis') . '</label><input id="draco-ab-subject" type="text" name="subject" class="large-text" value="' . esc_attr($draft['subject']) . '" required></div>';
        echo '<div class="draco-field"><label for="draco-ab-body">' . esc_html__('Message (in English, which abuse desks read; edit anything you like)', 'draco-insomnis') . '</label><textarea id="draco-ab-body" name="body" rows="18" class="large-text code" required>' . esc_textarea($draft['body']) . '</textarea></div>';
        /* translators: %s: the site administrator's e-mail */
        echo '<p class="description">' . esc_html(sprintf(__('Replies go to %s. Never more than one report per address every 30 days, nor more than 5 a day.', 'draco-insomnis'), (string) get_option('admin_email'))) . '</p>';
        submit_button(__('Send the report', 'draco-insomnis'), 'primary', 'submit', false, $refusal === '' ? [] : ['disabled' => 'disabled']);
        echo ' <a class="button" href="' . esc_url($back) . '">' . esc_html__('Cancel', 'draco-insomnis') . '</a></form>';
        Brand::cardEnd();
        Brand::close();
    }

    public static function send(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'draco-insomnis'), 403);
        }
        check_admin_referer(self::ACTION);
        $ip = (string) filter_var(wp_unslash((string) ($_POST['ip'] ?? '')), FILTER_VALIDATE_IP);
        $to = sanitize_email(wp_unslash((string) ($_POST['to'] ?? '')));
        $subject = sanitize_text_field(wp_unslash((string) ($_POST['subject'] ?? '')));
        $body = sanitize_textarea_field(wp_unslash((string) ($_POST['body'] ?? '')));
        $back = admin_url('admin.php?page=' . Admin::SLUG);
        if ($ip === '' || !is_email($to) || $subject === '' || $body === '' || Abuse::refusal($ip, self::sent(), time()) !== '') {
            wp_safe_redirect($back . '&result=report_refused');
            exit;
        }
        $ok = wp_mail($to, $subject, $body, ['Reply-To: ' . (string) get_option('admin_email'), 'Content-Type: text/plain; charset=UTF-8']);
        if ($ok) {
            Store::log($ip, $ip, Abuse::ENDPOINT, ['score' => 0, 'verdict' => 'sent', 'reasons' => []], '', ['email' => $to, 'username' => mb_substr($subject, 0, 150)]);
        }
        wp_safe_redirect($back . '&result=' . ($ok ? 'report_sent' : 'report_failed'));
        exit;
    }

    /** The reports already sent, for the shield page. */
    public static function listCard(): void
    {
        $rows = Store::recentWhere(Abuse::ENDPOINT, 20);
        if ($rows === []) {
            return;
        }
        Brand::card('email-alt', __('Abuse reports sent', 'draco-insomnis'), __('The last 20. Replies arrive at the administrator e-mail.', 'draco-insomnis'), '', 'info', 'draco-card--flush');
        echo '<div class="draco-table-wrap"><table class="widefat striped draco-table"><thead><tr><th>' . esc_html__('Date (UTC)', 'draco-insomnis') . '</th><th>IP</th><th>' . esc_html__('To', 'draco-insomnis') . '</th><th>' . esc_html__('Subject', 'draco-insomnis') . '</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $f = json_decode((string) $r['fields'], true);
            $f = is_array($f) ? $f : [];
            echo '<tr><td>' . esc_html((string) $r['created_at']) . '</td><td><span class="draco-code">' . esc_html((string) $r['ip']) . '</span></td><td>' . esc_html((string) ($f['email'] ?? '')) . '</td><td>' . esc_html((string) ($f['username'] ?? '')) . '</td></tr>';
        }
        echo '</tbody></table></div>';
        Brand::cardEnd();
    }
}
