<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel;

/**
 * Lets the app change a value Draco is about to use: "verdict" (the shield's result, with the
 * endpoint, fields and ip as args), "hosting_nets" or "crawler_verified" (null, ip, crawler).
 * Listen to it and set $event->value.
 */
final class DracoFilter
{
    /** @param list<mixed> $args */
    public function __construct(public string $name, public mixed $value, public array $args = [])
    {
    }
}
