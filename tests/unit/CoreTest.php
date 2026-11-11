<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\BotScore;
use DracoInsomnis\Core\FormStamp;
use DracoInsomnis\Core\NetList;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/src/Core/BotScore.php';
require_once dirname(__DIR__, 2) . '/src/Core/NetList.php';
require_once dirname(__DIR__, 2) . '/src/Core/FormStamp.php';

final class CoreTest extends TestCase
{
    private const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36';
    private const ROLES = ['agent', 'agency', 'owner', 'buyer'];

    /** @return array<string, array{array<string, mixed>, string}> */
    public static function attempts(): array
    {
        return [
            // Seen in the wild: the placeholder text as role, posted straight to admin-ajax.
            'placeholder role, no page loaded' => [
                ['requested_role' => 'Tipo de cuenta', 'allowed_roles' => self::ROLES, 'stamp' => 'missing', 'username' => 'usru88w16kx', 'user_agent' => self::BROWSER],
                'bot',
            ],
            'asks for administrator' => [
                ['requested_role' => 'administrator', 'allowed_roles' => self::ROLES, 'stamp' => 'ok', 'elapsed' => 40, 'username' => 'wpadmin2025', 'user_agent' => self::BROWSER],
                'bot',
            ],
            'honeypot filled' => [
                ['requested_role' => 'agent', 'allowed_roles' => self::ROLES, 'honeypot' => 'http://spam.example', 'stamp' => 'ok', 'elapsed' => 20, 'username' => 'maria', 'user_agent' => self::BROWSER],
                'bot',
            ],
            'forged stamp from a VPS' => [
                ['requested_role' => 'agent', 'allowed_roles' => self::ROLES, 'stamp' => 'invalid', 'username' => 'qmqzydgrkv', 'hosting_network' => true, 'user_agent' => self::BROWSER],
                'bot',
            ],
            'curl with no stamp' => [
                ['stamp' => 'missing', 'username' => 'pepe', 'user_agent' => 'curl/8.4.0', 'recent_bot_attempts' => 1],
                'bot',
            ],
            'blocked sender' => [
                ['blocked' => true, 'stamp' => 'ok', 'elapsed' => 30, 'username' => 'maria', 'user_agent' => self::BROWSER],
                'bot',
            ],
            'real person' => [
                ['requested_role' => 'buyer', 'allowed_roles' => self::ROLES, 'stamp' => 'ok', 'elapsed' => 45, 'username' => 'maria1985', 'user_agent' => self::BROWSER],
                'clean',
            ],
            'real person without role select' => [
                ['requested_role' => '', 'allowed_roles' => null, 'stamp' => 'ok', 'elapsed' => 12, 'username' => 'juanperez', 'user_agent' => self::BROWSER],
                'clean',
            ],
            'person with JavaScript off' => [
                ['requested_role' => 'agent', 'allowed_roles' => self::ROLES, 'stamp' => 'missing', 'username' => 'juanperez', 'user_agent' => self::BROWSER],
                'doubtful',
            ],
            'person on a VPN with an odd name' => [
                ['requested_role' => 'agent', 'allowed_roles' => self::ROLES, 'stamp' => 'ok', 'elapsed' => 60, 'username' => 'xkcd77b2z9', 'hosting_network' => true, 'user_agent' => self::BROWSER],
                'doubtful',
            ],
            'autofill, very fast' => [
                ['requested_role' => 'agent', 'allowed_roles' => self::ROLES, 'stamp' => 'ok', 'elapsed' => 2, 'username' => 'juanperez', 'user_agent' => self::BROWSER],
                'doubtful',
            ],
        ];
    }

    /** @param array<string, mixed> $signals */
    #[DataProvider('attempts')]
    public function testVerdict(array $signals, string $expected): void
    {
        self::assertSame($expected, BotScore::evaluate($signals)['verdict']);
    }

    public function testReasonsAreListed(): void
    {
        $r = BotScore::evaluate(['requested_role' => 'Tipo de cuenta', 'allowed_roles' => self::ROLES, 'stamp' => 'missing', 'user_agent' => self::BROWSER]);
        self::assertSame(['unknown_role', 'stamp_missing'], $r['reasons']);
        self::assertSame(90, $r['score']);
    }

    /** @return array<string, array{string, bool}> */
    public static function names(): array
    {
        return [
            'usru88w16kx' => ['usru88w16kx', true],
            'verifrw8mfsrh' => ['verifrw8mfsrh', true],
            'wpadmpja56r2k' => ['wpadmpja56r2k', true],
            'qmqzydgrkv' => ['qmqzydgrkv', true],
            'maria1985' => ['maria1985', false],
            'juanperez' => ['juanperez', false],
            'christopher' => ['christopher', false],
            'juan.perez' => ['juan.perez', false],
            'short' => ['ab12cd3', false],
            'wpadmin2025' => ['wpadmin2025', false],
        ];
    }

    #[DataProvider('names')]
    public function testLooksRandom(string $name, bool $expected): void
    {
        self::assertSame($expected, BotScore::looksRandom($name));
    }

    /** @return array<string, array{string, bool}> */
    public static function ips(): array
    {
        return [
            'OVH SG v6' => ['2402:1f00:8000:800::40db', true],
            'White Label v6' => ['2602:fa5d::30', true],
            'ColoCrossing' => ['198.46.154.7', true],
            'ColoCrossing single' => ['107.173.160.145', true],
            'neighbour /24' => ['198.46.155.7', false],
            'home v4' => ['83.45.10.20', false],
            'home v6' => ['2a0c:5a80::1', false],
            'garbage' => ['not-an-ip', false],
        ];
    }

    #[DataProvider('ips')]
    public function testSeenHosting(string $ip, bool $expected): void
    {
        self::assertSame($expected, NetList::contains(NetList::SEEN_HOSTING, $ip));
    }

    public function testOddPrefixLengths(): void
    {
        self::assertTrue(NetList::inNet('10.0.0.0/12', '10.15.255.1'));
        self::assertFalse(NetList::inNet('10.0.0.0/12', '10.16.0.1'));
        self::assertTrue(NetList::inNet('1.2.3.4', '1.2.3.4'));
        self::assertFalse(NetList::inNet('1.2.3.0/40', '1.2.3.4'));
    }

    public function testParse(): void
    {
        self::assertSame(['1.2.3.0/24', '2001:db8::/32'], NetList::parse("1.2.3.0/24 # vps\n\nnonsense\n2001:db8::/32\n1.2.3.0/24"));
    }

    public function testStamp(): void
    {
        $now = 1_800_000_000;
        $stamp = FormStamp::make('k', $now - 30);
        self::assertSame(['state' => 'ok', 'elapsed' => 30], FormStamp::check('k', $stamp, $now));
        self::assertSame('invalid', FormStamp::check('other-key', $stamp, $now)['state']);
        self::assertSame('invalid', FormStamp::check('k', ($now - 30) . '.0000000000aaaaaaaaaa', $now)['state']);
        self::assertSame('invalid', FormStamp::check('k', 'hello', $now)['state']);
        self::assertSame('missing', FormStamp::check('k', '', $now)['state']);
        self::assertSame('invalid', FormStamp::check('k', FormStamp::make('k', $now + 3600), $now)['state']);
    }
}
