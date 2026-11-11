<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Scores one sign-up attempt. Plain PHP, no WordPress: OPNV-WP uses it too.
 *
 * No single weak sign is enough to call something a bot; a person on a VPN with an odd username only
 * becomes "doubtful", and doubtful attempts still get through to the e-mail confirmation.
 */
final class BotScore
{
    public const BOT = 70;
    public const DOUBTFUL = 30;

    /** Roles nobody may ask for from a public form. */
    private const PRIVILEGED = ['administrator', 'editor', 'author', 'shop_manager', 'super_admin'];

    /**
     * @param array{
     *   requested_role?: string,
     *   allowed_roles?: list<string>|null,
     *   honeypot?: string,
     *   stamp?: 'missing'|'invalid'|'ok',
     *   elapsed?: int|null,
     *   username?: string,
     *   hosting_network?: bool,
     *   recent_bot_attempts?: int,
     *   user_agent?: string,
     *   blocked?: bool,
     * } $s
     * @return array{score: int, verdict: 'bot'|'doubtful'|'clean', reasons: list<string>}
     */
    public static function evaluate(array $s): array
    {
        $score = 0;
        $reasons = [];
        $add = static function (int $points, string $reason) use (&$score, &$reasons): void {
            $score += $points;
            $reasons[] = $reason;
        };

        if (!empty($s['blocked'])) {
            $add(100, 'blocked');
        }

        $role = strtolower(trim((string) ($s['requested_role'] ?? '')));
        if ($role !== '') {
            $allowed = $s['allowed_roles'] ?? null;
            if (in_array($role, self::PRIVILEGED, true) || str_contains($role, 'admin')) {
                $add(80, 'privileged_role');
            } elseif (is_array($allowed) && !in_array($role, array_map('strtolower', $allowed), true)) {
                // «Tipo de cuenta»: the placeholder text of the select, which a browser never sends.
                $add(60, 'unknown_role');
            }
        }

        if (trim((string) ($s['honeypot'] ?? '')) !== '') {
            $add(80, 'honeypot');
        }

        $stamp = $s['stamp'] ?? 'missing';
        if ($stamp === 'invalid') {
            $add(40, 'stamp_invalid');
        } elseif ($stamp === 'missing') {
            // Posted straight to the endpoint without loading the page; also a person with JS off.
            $add(30, 'stamp_missing');
        } elseif (isset($s['elapsed']) && $s['elapsed'] !== null && $s['elapsed'] < 3) {
            $add(40, 'too_fast');
        }

        if (self::looksRandom((string) ($s['username'] ?? ''))) {
            $add(20, 'random_username');
        }

        if (!empty($s['hosting_network'])) {
            $add(25, 'hosting_network');
        }

        $recent = (int) ($s['recent_bot_attempts'] ?? 0);
        if ($recent > 0) {
            $add(min(30, $recent * 10), 'repeat_offender');
        }

        $ua = strtolower(trim((string) ($s['user_agent'] ?? '')));
        if ($ua === '' || preg_match('/\b(curl|wget|python|go-http|java\/|libwww|httpclient|okhttp|scrapy|headless)/', $ua) === 1) {
            $add(30, 'script_client');
        }

        $verdict = $score >= self::BOT ? 'bot' : ($score >= self::DOUBTFUL ? 'doubtful' : 'clean');

        return ['score' => $score, 'verdict' => $verdict, 'reasons' => $reasons];
    }

    /** usru88w16kx, verifrw8mfsrh, qmqzydgrkv… but not maria1985, juan.perez or christopher. */
    public static function looksRandom(string $name): bool
    {
        $name = strtolower(trim($name));
        if (strlen($name) < 8 || preg_match('/^[a-z0-9]+$/', $name) !== 1) {
            return false;
        }
        // Letters and digits mixed back and forth: u-8, 8-w, w-1, 6-k.
        $switches = preg_match_all('/(?<=[a-z])(?=[0-9])|(?<=[0-9])(?=[a-z])/', $name);
        if ($switches >= 3) {
            return true;
        }
        $letters = (string) preg_replace('/[0-9]/', '', $name);
        // Long runs without a vowel do not happen in names: «mfsrh», «qmqzydgrkv».
        if (preg_match('/[bcdfghjklmnpqrstvwxyz]{5,}/', $letters) === 1) {
            return true;
        }
        $vowels = preg_match_all('/[aeiou]/', $letters);

        return strlen($letters) >= 8 && $vowels / strlen($letters) < 0.2;
    }
}
