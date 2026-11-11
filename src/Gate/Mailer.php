<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

use DracoInsomnis\Mail\Template;

defined('ABSPATH') || exit;

/**
 * The confirmation mail and the limits on sending it.
 *
 * It never carries anything the visitor typed: anyone can write a stranger's address in a form, and
 * this mail must not become a way to send them text. The limits stop it being used to flood a mailbox.
 */
final class Mailer
{
    private const MAX_PER_IP_HOUR = 5;
    private const MAX_PER_EMAIL_DAY = 3;
    private static bool $sending = false;

    public static function isSending(): bool
    {
        return self::$sending;
    }

    /** Counts this attempt and says whether it may go ahead. */
    public static function allow(string $email, string $ip): bool
    {
        $perIp = self::count('draco_gate_ip_' . md5($ip), HOUR_IN_SECONDS);
        $perEmail = self::count('draco_gate_em_' . md5(strtolower($email)), DAY_IN_SECONDS);

        return $perIp <= self::MAX_PER_IP_HOUR && $perEmail <= self::MAX_PER_EMAIL_DAY;
    }

    private static function count(string $key, int $ttl): int
    {
        $hits = (int) get_transient($key) + 1;
        set_transient($key, $hits, $ttl);

        return $hits;
    }

    public static function verifyUrl(string $token): string
    {
        return add_query_arg(['action' => Verify::ACTION, 't' => $token], admin_url('admin-ajax.php'));
    }

    public static function send(string $email, string $token, string $kind): bool
    {
        $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $url = self::verifyUrl($token);
        $hours = Store::PENDING_HOURS;
        if ($kind === 'user') {
            /* translators: %s: site name */
            $subject = sprintf(__('Confirm your account at %s', 'draco-insomnis'), $site);
            /* translators: %s: site name */
            $intro = sprintf(__('We received a request to create an account at %s with this address.', 'draco-insomnis'), $site);
            $ask = __('To activate it, open this link and press the confirm button:', 'draco-insomnis');
            /* translators: %d: hours */
            $outro = sprintf(__('The link expires in %d hours. If this wasn\'t you, ignore this email: the account will not be activated.', 'draco-insomnis'), $hours);
        } elseif ($kind === 'comment') {
            /* translators: %s: site name */
            $subject = sprintf(__('Confirm your comment at %s', 'draco-insomnis'), $site);
            /* translators: %s: site name */
            $intro = sprintf(__('We received a comment at %s with this address.', 'draco-insomnis'), $site);
            $ask = __('It has not been sent yet and nobody has seen it. To send it, open this link and press the confirm button:', 'draco-insomnis');
            /* translators: %d: hours */
            $outro = sprintf(__('The link expires in %d hours. If this wasn\'t you, ignore this email: the comment will be deleted.', 'draco-insomnis'), $hours);
        } else {
            /* translators: %s: site name */
            $subject = sprintf(__('Confirm your message to %s', 'draco-insomnis'), $site);
            /* translators: %s: site name */
            $intro = sprintf(__('We received a message sent through the form at %s with this address.', 'draco-insomnis'), $site);
            $ask = __('It has not been delivered yet. To send it, open this link and press the confirm button:', 'draco-insomnis');
            /* translators: %d: hours */
            $outro = sprintf(__('The link expires in %d hours. If this wasn\'t you, ignore this email: the message will be deleted.', 'draco-insomnis'), $hours);
        }
        $plain = $intro . "\n\n" . $ask . "\n" . $url . "\n\n" . $outro;

        self::$sending = true;
        try {
            return Template::send($email, $subject, $plain, $subject, [$intro, $ask], ['url' => $url, 'button' => __('Confirm', 'draco-insomnis'), 'after' => [$outro]]);
        } finally {
            self::$sending = false;
        }
    }
}
