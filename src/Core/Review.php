<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * "This is a mistake": a person the firewall stopped asks the owner to look again, from the 403 page.
 *
 * The form is signed for the address and the moment it was shown, has a trap field and is limited
 * per address (3 a day) and per site (50 a day), so it cannot be used to fill the queue. Requests are
 * kept in the event store (endpoint "review", verdict "pending") and the owner gets one notice an hour
 * at most. Draco never writes to the person who asks: that would let anyone make the site send mail.
 */
final class Review
{
    public const FIELD = 'draco_review';
    public const ENDPOINT = 'review';
    private const MAX_PER_IP_DAY = 3;
    private const MAX_PER_DAY = 50;
    private const VALID_FOR = 86400;

    public function __construct(private Host $host)
    {
    }

    /**
     * The form under the 403 text, already escaped.
     *
     * @param array{email: string, message: string, button: string} $labels Translated.
     */
    public function form(Request $r, string $why, int $now, array $labels): string
    {
        $h = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
        $ts = (string) $now;
        $rule = preg_replace('/[^a-z0-9_]/', '', strtolower($why)) ?? '';

        return '<form method="post" action="">'
            . '<input type="hidden" name="' . self::FIELD . '" value="1">'
            . '<input type="hidden" name="draco_rule" value="' . $h(self::seal($this->host->secret(), $r->via($this->host), $ts, $rule)) . '">'
            . '<input type="hidden" name="draco_ts" value="' . $h($ts) . '">'
            . '<input type="hidden" name="draco_sig" value="' . $h($this->sign($r->via($this->host), $rule, $ts)) . '">'
            . '<p class="hp"><label>Website <input type="text" name="draco_website" tabindex="-1" autocomplete="off"></label></p>'
            . '<label for="draco-r-email">' . $h($labels['email']) . '</label>'
            . '<input id="draco-r-email" type="email" name="draco_email" required maxlength="190">'
            . '<label for="draco-r-msg">' . $h($labels['message']) . '</label>'
            . '<textarea id="draco-r-msg" name="draco_message" rows="3" maxlength="500" required></textarea>'
            . '<button type="submit">' . $h($labels['button']) . '</button>'
            . '</form>';
    }

    /** True when this POST is a review request (whatever its outcome). */
    public static function isRequest(Request $r, array $post): bool
    {
        return $r->method === 'POST' && (string) ($post[self::FIELD] ?? '') === '1';
    }

    /**
     * Checks a review request and keeps it when it passes; the caller then answers with thanks()
     * either way, so a script learns nothing.
     *
     * @param array<string, mixed> $post Raw POST fields.
     */
    public function accept(Request $r, array $post, int $now): bool
    {
        $ip = $r->via($this->host);
        $ts = (string) ($post['draco_ts'] ?? '');
        $rule = self::open($this->host->secret(), $ip, $ts, (string) ($post['draco_rule'] ?? ''));
        $sig = (string) ($post['draco_sig'] ?? '');
        $email = strtolower(trim((string) ($post['draco_email'] ?? '')));
        // Tags out (the text is always escaped when shown; this only keeps the queue readable).
        $message = (string) preg_replace('@<(script|style)[^>]*?>.*?</\\1>|<[^>]*>@si', '', (string) ($post['draco_message'] ?? ''));
        $message = trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $message) ?? '');
        $message = mb_substr($message, 0, 500);
        $trap = (string) ($post['draco_website'] ?? '');

        $fresh = ctype_digit($ts) && (int) $ts <= $now && $now - (int) $ts < self::VALID_FOR;
        $ok = $fresh && hash_equals($this->sign($ip, $rule, $ts), $sig) && $trap === ''
            && filter_var($email, FILTER_VALIDATE_EMAIL) !== false && strlen($email) <= 190 && $message !== ''
            && $this->host->bump('draco_review_ip_' . md5($ip), self::VALID_FOR) <= self::MAX_PER_IP_DAY
            && $this->host->bump('draco_review_day_' . gmdate('Ymd', $now), self::VALID_FOR) <= self::MAX_PER_DAY;
        if (!$ok) {
            return false;
        }
        $this->host->events()->log($ip, $r->remote(), self::ENDPOINT, ['score' => 0, 'verdict' => 'pending', 'reasons' => ['review_' . ($rule !== '' ? $rule : 'blocked')]], substr($r->userAgent, 0, 255), [
            'username' => '',
            'email' => $email,
            'role' => '',
            'referer' => mb_substr($message, 0, 500),
        ]);
        if ($this->host->bump('draco_review_notice', 3600) === 1) {
            $this->host->notifyOwner($this->host->text('review_subject', 0), $this->host->text('review_body', 0));
        }

        return true;
    }

    /**
     * The rule that stopped the request, hidden from the visitor: the block page never says what
     * matched. XOR with a key from the site secret, the address and the moment; the signature still
     * covers the plain rule, so a changed value is refused.
     */
    public static function seal(string $secret, string $ip, string $ts, string $rule): string
    {
        $rule = substr(preg_replace('/[^a-z0-9_]/', '', strtolower($rule)) ?? '', 0, 32);

        return bin2hex(str_pad($rule, 32, "\0") ^ hash_hmac('sha256', 'review-rule|' . $ip . '|' . $ts, $secret, true));
    }

    /** The rule from seal(), or '' when the value is not one. */
    public static function open(string $secret, string $ip, string $ts, string $sealed): string
    {
        if (strlen($sealed) !== 64 || !ctype_xdigit($sealed)) {
            return '';
        }
        $rule = rtrim((string) hex2bin($sealed) ^ hash_hmac('sha256', 'review-rule|' . $ip . '|' . $ts, $secret, true), "\0");

        return preg_match('/^[a-z0-9_]*$/', $rule) === 1 ? $rule : '';
    }

    private function sign(string $ip, string $rule, string $ts): string
    {
        return hash_hmac('sha256', 'review|' . $ip . '|' . $rule . '|' . $ts, $this->host->secret());
    }

    /** The hidden fields of a form shown to $ip at $ts, for tests. @return array<string, string> */
    public function signedFields(string $ip, string $rule, int $ts): array
    {
        return ['draco_rule' => self::seal($this->host->secret(), $ip, (string) $ts, $rule), 'draco_ts' => (string) $ts, 'draco_sig' => $this->sign($ip, $rule, (string) $ts)];
    }
}
