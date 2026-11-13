<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * What the engines (Shield, Firewall, Pace) need from the CMS they run in. Each CMS has one small
 * adapter that implements it; the engines never call a CMS function themselves.
 */
interface Host
{
    /** Per-site secret: signs the page stamp and picks this site's field names. */
    public function secret(): string;

    /**
     * A setting by its short name ("proxy_header", "hosting_nets", "anticopy_rate_ip"…), or '' when
     * unset. WordPress keeps them as draco_<name> options.
     */
    public function setting(string $name): string;

    /** Addresses an administrator worked from recently: never blocked, never limited. @return list<string> */
    public function adminIps(): array;

    /** Adds one to a counter that lives $ttl seconds and returns its new value. */
    public function bump(string $key, int $ttl): int;

    public function recall(string $key): ?string;

    public function remember(string $key, string $value, int $ttl): void;

    /**
     * Lets site code change a value (WordPress: the draco_insomnis_<name> filter).
     *
     * @param mixed $value
     * @param mixed ...$args
     * @return mixed
     */
    public function filter(string $name, $value, ...$args);

    /**
     * The few texts the engines store or send, in the site's language: "auto_block" and "waf_block",
     * each with a number of attempts; "review_subject" and "review_body" (number unused).
     */
    public function text(string $id, int $number): string;

    public function events(): EventStore;

    /**
     * One short e-mail to the site's owner or administrators, through the CMS's own mailer. Used for
     * review requests (at most one an hour). Texts come from text('review_subject') and text('review_body').
     */
    public function notifyOwner(string $subject, string $body): void;
}
