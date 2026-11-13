<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

use DracoInsomnis\Input;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- the plugin's own table; every value goes through prepare().

/**
 * "This is a mistake": a person the firewall stopped asks the owner to look again, from the 403 page.
 *
 * The form is signed for the address and the moment it was shown, has a trap field, and is limited
 * per address and per day, so it cannot be used to fill the queue. Draco never e-mails the person who
 * asks (that would let anyone make the site send mail): the owner sees the address and answers.
 */
final class Review
{
    public const FIELD = 'draco_review';
    private const MAX_PER_IP_DAY = 3;
    private const MAX_PER_DAY = 50;
    private const VALID_FOR = 86400;
    private const NOTIFY_EVERY = 3600;

    /** The form under the 403 text. Every value is escaped here. */
    public static function form(string $why): string
    {
        $ts = (string) time();
        $h = static fn (string $s): string => esc_attr($s);

        return '<form method="post" action="">'
            . '<input type="hidden" name="' . self::FIELD . '" value="1">'
            . '<input type="hidden" name="draco_rule" value="' . $h($why) . '">'
            . '<input type="hidden" name="draco_ts" value="' . $h($ts) . '">'
            . '<input type="hidden" name="draco_sig" value="' . $h(self::sign(Guard::clientIp(), $why, $ts)) . '">'
            . '<p class="hp"><label>Website <input type="text" name="draco_website" tabindex="-1" autocomplete="off"></label></p>'
            . '<label for="draco-r-email">' . esc_html__('Your e-mail', 'draco-insomnis') . '</label>'
            . '<input id="draco-r-email" type="email" name="draco_email" required maxlength="190">'
            . '<label for="draco-r-msg">' . esc_html__('What were you doing?', 'draco-insomnis') . '</label>'
            . '<textarea id="draco-r-msg" name="draco_message" rows="3" maxlength="500" required></textarea>'
            . '<button type="submit">' . esc_html__('Ask for a review', 'draco-insomnis') . '</button>'
            . '</form>';
    }

    /** True when this request is a review request; it is answered and the request ends. */
    public static function handle(): bool
    {
        if (Input::method() !== 'POST' || Input::post(self::FIELD) !== '1') {
            return false;
        }
        self::accept(wp_unslash($_POST), Guard::clientIp()); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput -- signed form; every field is sanitised in accept()
        // The same answer either way: a script learns nothing from it.
        self::answer();

        return true;
    }

    /**
     * Checks a review request and keeps it when it passes: signed for this address in the last day,
     * trap field empty, a real e-mail and a message, and within the limits.
     *
     * @param array<string, mixed> $post Unslashed POST fields.
     */
    public static function accept(array $post, string $ip): bool
    {
        $rule = sanitize_key((string) ($post['draco_rule'] ?? ''));
        $ts = (string) ($post['draco_ts'] ?? '');
        $sig = (string) ($post['draco_sig'] ?? '');
        $email = sanitize_email((string) ($post['draco_email'] ?? ''));
        $message = substr(sanitize_textarea_field((string) ($post['draco_message'] ?? '')), 0, 500);
        $trap = (string) ($post['draco_website'] ?? '');

        $fresh = ctype_digit($ts) && (int) $ts <= time() && time() - (int) $ts < self::VALID_FOR;
        $ok = $fresh && hash_equals(self::sign($ip, $rule, $ts), $sig) && $trap === '' && is_email($email) && $message !== ''
            && Store::bump('draco_review_ip_' . md5($ip), self::VALID_FOR) <= self::MAX_PER_IP_DAY
            && Store::bump('draco_review_day_' . gmdate('Ymd'), self::VALID_FOR) <= self::MAX_PER_DAY;
        if ($ok) {
            self::save($ip, $email, $message, $rule);
        }

        return $ok;
    }

    /** The hidden fields of a form shown to $ip now, for tests and for form(). @return array<string, string> */
    public static function signedFields(string $ip, string $rule, int $ts): array
    {
        return ['draco_rule' => $rule, 'draco_ts' => (string) $ts, 'draco_sig' => self::sign($ip, $rule, (string) $ts)];
    }

    private static function save(string $ip, string $email, string $message, string $rule): void
    {
        global $wpdb;
        Store::ensureTables();
        $wpdb->insert(Store::reviews(), [
            'created_at' => current_time('mysql', true),
            'ip' => $ip,
            'email' => strtolower($email),
            'message' => $message,
            'rule' => substr($rule, 0, 40),
            'status' => 'pending',
        ]);
        if (Store::bump('draco_review_notice', self::NOTIFY_EVERY) === 1) {
            wp_mail(
                (string) get_option('admin_email'),
                /* translators: %s: site name */
                sprintf(__('[%s] Someone asks you to review a firewall block', 'draco-insomnis'), wp_specialchars_decode((string) get_option('blogname'), ENT_QUOTES)),
                __('A visitor stopped by the firewall asks for a review. Open the Firewall screen to let them through or not:', 'draco-insomnis') . "\n\n" . admin_url('admin.php?page=' . Admin::SLUG . '#draco-reviews')
            );
        }
    }

    private static function answer(): void
    {
        nocache_headers();
        status_header(200);
        header('Content-Type: text/html; charset=UTF-8');
        header('X-Robots-Tag: noindex, nofollow');
        $page = \DracoInsomnis\Core\Firewall::page(
            __('Request sent', 'draco-insomnis'),
            __('Thank you. The owner of the site will look at it and, if it was a mistake, let you through.', 'draco-insomnis'),
            'review'
        );
        echo $page; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every text is escaped inside Firewall::page()
        exit;
    }

    private static function sign(string $ip, string $rule, string $ts): string
    {
        return hash_hmac('sha256', 'review|' . $ip . '|' . $rule . '|' . $ts, Plugin::secret());
    }

    /** @return list<array<string, mixed>> */
    public static function recent(int $limit = 50): array
    {
        global $wpdb;

        return (array) $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM %i ORDER BY status = 'pending' DESC, id DESC LIMIT %d",
            Store::reviews(),
            $limit,
        ), ARRAY_A);
    }

    public static function pendingCount(): int
    {
        global $wpdb;

        return (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM %i WHERE status = 'pending'", Store::reviews()));
    }

    /** @return array<string, mixed>|null */
    public static function find(int $id): ?array
    {
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM %i WHERE id = %d', Store::reviews(), $id), ARRAY_A);

        return is_array($row) ? $row : null;
    }

    /** approve (with days), deny or attacker. */
    public static function decide(int $id, string $decision, int $days): bool
    {
        $row = self::find($id);
        if ($row === null) {
            return false;
        }
        $ip = (string) $row['ip'];
        /* translators: %s: e-mail of the person who asked */
        $reason = sprintf(__('Review: %s', 'draco-insomnis'), (string) $row['email']);
        if ($decision === 'approve') {
            $done = Store::allow($ip, $days, $reason);
            $status = 'approved';
        } elseif ($decision === 'attacker') {
            $done = Store::block('ip', $ip, 90, $reason, true);
            $status = 'attacker';
        } elseif ($decision === 'deny') {
            $done = true;
            $status = 'denied';
        } else {
            return false;
        }
        global $wpdb;
        $wpdb->update(Store::reviews(), ['status' => $status, 'decided_at' => current_time('mysql', true)], ['id' => $id]);

        return $done;
    }
}
