<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Finds the abuse contact of an address in the public registry (RDAP, through rdap.org, which
 * forwards to the right RIR). Used only by the server edition (`draco report`), on the command of
 * the person who runs it. The WordPress plugin does not carry this file (bin/build-zip.sh): there
 * the administrator writes the abuse address.
 */
final class AbuseLookup
{
    public const RDAP = 'https://rdap.org/ip/';

    /**
     * @param callable(string): ?string $fetch Gets a URL (following redirects), returns the body or null.
     * @return array{email: string, network: string, range: string, registry: string, error: string}
     */
    public static function contact(string $ip, callable $fetch): array
    {
        $out = ['email' => '', 'network' => '', 'range' => '', 'registry' => '', 'error' => ''];
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            $out['error'] = 'not a public address';

            return $out;
        }
        $body = $fetch(self::RDAP . $ip);
        $data = is_string($body) ? json_decode($body, true) : null;
        if (!is_array($data)) {
            $out['error'] = 'the registry did not answer';

            return $out;
        }

        return Abuse::parse($data) + $out;
    }
}
