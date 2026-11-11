<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store as Blocks;

defined('ABSPATH') || exit;

/**
 * A visitor's comment is not saved, not even as pending, until its author confirms their address.
 *
 * It is stopped in pre_comment_approved, the last step before WordPress writes the comment. Once the
 * author confirms, the comment goes through wp_new_comment again, so the site's own rules (moderation,
 * notice to the author of the post) apply as if it had just arrived. Trackbacks and pingbacks have no
 * address to confirm, so they are dropped.
 */
final class CommentHold
{
    public const QUERY_ARG = 'draco_comment';
    private const FIELDS = ['comment_post_ID', 'comment_author', 'comment_author_email', 'comment_author_url', 'comment_content', 'comment_type', 'comment_parent', 'comment_author_IP', 'comment_agent'];
    private static bool $releasing = false;
    private static ?int $released = null;

    public static function register(): void
    {
        // Late, so a spam filter that already marked it as spam keeps the last word.
        add_filter('pre_comment_approved', [self::class, 'hold'], 99, 2);
        add_action('comment_form_before', [self::class, 'printNotice']);
    }

    /**
     * @param int|string|\WP_Error $approved
     * @param array<string, mixed> $data
     * @return int|string|\WP_Error
     */
    public static function hold($approved, $data)
    {
        $data = is_array($data) ? $data : [];
        if (self::$releasing || is_wp_error($approved) || in_array($approved, ['spam', 'trash'], true)
            || !empty($data['user_id']) || is_user_logged_in() || apply_filters('draco_insomnis_skip_comment', false, $data)) {
            return $approved;
        }
        $type = (string) ($data['comment_type'] ?? '');
        if (in_array($type, ['trackback', 'pingback'], true)) {
            return new \WP_Error('draco_ping', 'Trackbacks and pingbacks are not accepted.', 200);
        }
        if ($type !== '' && $type !== 'comment') {
            return $approved; // Reviews, notes and other types belong to other plugins.
        }
        $email = strtolower(trim((string) ($data['comment_author_email'] ?? '')));
        if (!is_email($email)) {
            return new \WP_Error('draco_email', __('Enter your email to comment: we will send you a link to confirm your comment.', 'draco-insomnis'), 200);
        }
        $ip = Guard::clientIp();
        if (!Blocks::isBlocked($email, $ip) && Mailer::allow($email, $ip)) {
            $created = Store::create('comment', 'comment', $email, $ip);
            if ($created === null) {
                return $approved; // Without the table the comment follows the site's normal moderation.
            }
            Store::setPayload($created['id'], self::pack($data));
            Mailer::send($email, $created['token'], 'comment');
        }
        // A blocked sender sees the same answer, so they cannot tell they are blocked.
        self::answer((int) ($data['comment_post_ID'] ?? 0));

        return new \WP_Error('draco_held', self::notice(), 200);
    }

    /** @param array<string, mixed> $data @return array<string, mixed> */
    private static function pack(array $data): array
    {
        $packed = [];
        foreach (self::FIELDS as $field) {
            $packed[$field] = $data[$field] ?? '';
        }

        return $packed;
    }

    /** The normal comment form goes back to the post, with the notice above the form. */
    private static function answer(int $postId): void
    {
        $script = (string) ($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '');
        if (!str_ends_with($script, 'wp-comments-post.php') || wp_doing_ajax() || $postId <= 0) {
            return;
        }
        $link = get_permalink($postId);
        if (!is_string($link) || $link === '') {
            return;
        }
        wp_safe_redirect(add_query_arg(self::QUERY_ARG, 'held', $link) . '#respond');
        exit;
    }

    public static function printNotice(): void
    {
        if (($_GET[self::QUERY_ARG] ?? '') !== 'held') { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
            return;
        }
        echo '<div class="draco-comment-notice" role="status" style="border-left:4px solid #2271b1;background:#f0f6fc;padding:12px 16px;margin:0 0 1.5em">' . esc_html(self::notice()) . '</div>';
    }

    /** @param array<string, mixed> $row */
    public static function release(array $row): void
    {
        $data = json_decode((string) $row['payload'], true);
        if (!is_array($data) || empty($data['comment_post_ID']) || get_post((int) $data['comment_post_ID']) === null) {
            self::$released = null;

            return;
        }
        $data['comment_post_ID'] = (int) $data['comment_post_ID'];
        $data['comment_parent'] = (int) ($data['comment_parent'] ?? 0);
        $data['user_id'] = 0;
        // An administrator pressing "Deliver now" may post unfiltered HTML; a visitor's comment never should.
        $data['comment_content'] = wp_kses_data((string) ($data['comment_content'] ?? ''));
        $data['comment_author'] = sanitize_text_field((string) ($data['comment_author'] ?? ''));
        $data['comment_author_url'] = esc_url_raw((string) ($data['comment_author_url'] ?? ''));
        self::$releasing = true;
        try {
            $id = wp_new_comment(wp_slash($data), true);
        } finally {
            self::$releasing = false;
        }
        self::$released = is_int($id) && $id > 0 ? $id : null;
    }

    /** What the author sees after confirming: published, or waiting for the owner's review. */
    public static function releasedMessage(): string
    {
        $comment = self::$released !== null ? get_comment(self::$released) : null;
        if (!$comment instanceof \WP_Comment) {
            return __('The comment could not be posted: the post no longer exists or the comment is a duplicate.', 'draco-insomnis');
        }
        if ((string) $comment->comment_approved === '1') {
            return __('Your comment has been published. Thank you.', 'draco-insomnis');
        }

        return __('Your comment has been sent. It will appear once it has been reviewed. Thank you.', 'draco-insomnis');
    }

    public static function notice(): string
    {
        return __('Almost done: we have sent you an email. Your comment will not be sent until you confirm it from that email. If you cannot see it, check your spam folder.', 'draco-insomnis');
    }
}
