<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Suspicious attempts (the evidence for an abuse report) and blocked senders, wherever the CMS keeps
 * them. Never stores passwords or anything beyond the fields the engines pass.
 */
interface EventStore
{
    /**
     * @param array{score: int, verdict: string, reasons: list<string>} $result
     * @param array<string, string> $fields
     */
    public function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void;

    public function botAttemptsSince(string $ip, int $seconds): int;

    public function isBlocked(string $email, string $ip): bool;

    /** Refuses administrators' e-mails and the addresses they used. */
    public function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool;
}
