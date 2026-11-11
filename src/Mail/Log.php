<?php

declare(strict_types=1);

namespace DracoInsomnis\Mail;

defined('ABSPATH') || exit;

/** The last messages: when, to whom, subject and result. Never the body, where login codes travel. */
final class Log
{
    public const OPTION = 'draco_mail_log';
    private const KEEP = 50;

    /** @param string|array<int, string> $to */
    public static function add(string $transport, $to, string $subject, bool $ok, string $error): void
    {
        $rows = self::rows();
        array_unshift($rows, [
            'at' => time(),
            'transport' => $transport,
            'to' => implode(', ', array_map('strval', (array) $to)),
            'subject' => substr($subject, 0, 120),
            'ok' => $ok,
            'error' => $error,
        ]);
        update_option(self::OPTION, array_slice($rows, 0, self::KEEP), false);
    }

    /** @return list<array<string, mixed>> */
    public static function rows(): array
    {
        $rows = get_option(self::OPTION, []);

        return is_array($rows) ? array_values($rows) : [];
    }
}
