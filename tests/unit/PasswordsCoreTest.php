<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\Passwords;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/MemoryHost.php';

final class PasswordsCoreTest extends TestCase
{
    private function host(array $settings, ?string $range = null): MemoryHost
    {
        $h = new MemoryHost();
        $h->settings = $settings;
        $h->filters['pwd_range'] = static fn ($value, $prefix) => $range;

        return $h;
    }

    public function test_off_by_default(): void
    {
        $h = $this->host([], 'should-not-be-asked');
        $this->assertFalse(Passwords::enabled($h));
        $this->assertSame('', Passwords::problem($h, 'a'));
    }

    public function test_minimum_length_counts_characters_not_bytes(): void
    {
        $h = $this->host(['pwd_min' => '10']);
        $this->assertSame('pwd_short:10', Passwords::problem($h, 'corto'));
        $this->assertSame('', Passwords::problem($h, 'ñandúñandú'));
        $this->assertSame('', Passwords::problem($h, ''), 'an empty field means "no change", never refused');
    }

    public function test_minimum_outside_8_to_64_is_ignored(): void
    {
        $this->assertSame(0, Passwords::minLength($this->host(['pwd_min' => '4'])));
        $this->assertSame(0, Passwords::minLength($this->host(['pwd_min' => '99'])));
        $this->assertSame(12, Passwords::minLength($this->host(['pwd_min' => '12'])));
    }

    public function test_breached_password_is_refused_and_only_the_prefix_is_asked(): void
    {
        $hash = strtoupper(sha1('password'));
        $asked = [];
        $h = $this->host(['pwd_breached' => '1']);
        $h->filters['pwd_range'] = static function ($value, $prefix) use (&$asked, $hash) {
            $asked[] = $prefix;

            return "0000000000000000000000000000000000A:0\r\n" . substr($hash, 5) . ":9545824\r\n";
        };
        $this->assertSame('pwd_breached:0', Passwords::problem($h, 'password'));
        $this->assertSame([substr($hash, 0, 5)], $asked);
        $this->assertSame('', Passwords::problem($h, 'correct horse battery staple 2026'));
    }

    public function test_padding_lines_and_no_answer_accept_the_password(): void
    {
        $suffix = substr(strtoupper(sha1('secret')), 5);
        $this->assertSame(0, Passwords::countIn($suffix, $suffix . ':0'));
        $this->assertSame(3, Passwords::countIn(strtolower($suffix), $suffix . ":3\n"));
        $this->assertSame(0, Passwords::countIn($suffix, ''));
    }
}
