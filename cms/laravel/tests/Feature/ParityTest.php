<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Tests\Feature;

use DracoInsomnis\Laravel\Store;
use DracoInsomnis\Laravel\Tests\TestCase;

final class ParityTest extends TestCase
{
    public function test_the_translations_load_and_translate(): void
    {
        $base = dirname(__DIR__, 2) . '/lang';
        $english = require $base . '/en/messages.php';
        $dirs = glob($base . '/*', GLOB_ONLYDIR) ?: [];
        $this->assertGreaterThan(5, count($dirs));
        foreach ($dirs as $dir) {
            $messages = require $dir . '/messages.php';
            $this->assertSame([], array_diff(array_keys($messages), array_keys($english)), basename($dir) . ' has unknown keys');
        }
        app()->setLocale('de');
        $this->assertNotSame($english['blocked_title'], __('draco::messages.blocked_title'));
        $this->assertStringContainsString('12', __('draco::messages.pwd_short', ['min' => 12]));
        app()->setLocale('en');
    }

    public function test_password_rules_validate_only_when_switched_on(): void
    {
        $rule = ['p' => ['required', new \DracoInsomnis\Laravel\Rules\DracoPassword()]];
        $this->assertTrue(validator(['p' => 'abc'], $rule)->passes());
        config(['draco.pwd_min' => 12]);
        $v = validator(['p' => 'abc'], $rule);
        $this->assertTrue($v->fails());
        $this->assertStringContainsString('12', $v->errors()->first('p'));
        $this->assertTrue(validator(['p' => 'a long enough one'], $rule)->passes());
        $this->assertTrue(validator(['p' => 'abc'], ['p' => 'draco_password'])->fails());

        config(['draco.pwd_min' => 0, 'draco.pwd_breached' => true]);
        $hash = strtoupper(sha1('password'));
        \Illuminate\Support\Facades\Event::listen(\DracoInsomnis\Laravel\DracoFilter::class, static function ($e) use ($hash): void {
            if ($e->name === 'pwd_range') {
                $e->value = substr($hash, 5) . ':9545824';
            }
        });
        $this->assertTrue(validator(['p' => 'password'], $rule)->fails());
        $this->assertTrue(validator(['p' => 'not in the fake list'], $rule)->passes());
    }

    public function test_security_headers_only_when_switched_on(): void
    {
        $this->get('/')->assertOk()->assertHeaderMissing('X-Content-Type-Options');
        config(['draco.headers' => true]);
        $this->get('/')->assertHeader('X-Content-Type-Options', 'nosniff')->assertHeader('X-Frame-Options', 'SAMEORIGIN')->assertHeaderMissing('Strict-Transport-Security');
    }

    public function test_a_range_blocked_forever_can_read_but_not_post(): void
    {
        config(['draco.waf_mode' => 'block']);
        $net = implode('.', array_slice(explode('.', self::VISITOR), 0, 3)) . '.0/24';
        $this->assertTrue((new Store())->block('ip', $net, 0, 'range', true));
        $this->assertSame('net', $this->blocks()[0]->kind);
        $this->assertSame('9999-12-31 23:59:59', $this->blocks()[0]->until_at);
        $this->get('/')->assertOk();
        $this->post('/')->assertForbidden();
        $this->assertFalse((new Store())->block('ip', '10.0.0.0/8', 30, 'too wide', true));
    }

    public function test_the_country_filter_uses_a_local_list(): void
    {
        $file = sys_get_temp_dir() . '/draco-geo-' . getmypid() . '.bin';
        $rows = [['0.0.0.0', '--'], [self::VISITOR, 'CN'], [long2ip(ip2long(self::VISITOR) + 1), '--']];
        $bin = 'DRGEO1' . gmdate('Ymd') . pack('NN', count($rows), 0);
        foreach ($rows as [$ip, $cc]) {
            $bin .= inet_pton($ip) . $cc;
        }
        file_put_contents($file, $bin);
        config(['draco.waf_mode' => 'log', 'draco.geo_file' => $file, 'draco.geo_mode' => 'block', 'draco.geo_countries' => 'CN', 'draco.geo_action' => 'block']);
        $this->get('/')->assertOk();
        $this->post('/')->assertForbidden();
        $this->assertSame('waf:geo', $this->events()[0]->endpoint);
        $this->assertSame([], $this->blocks());
        config(['draco.geo_mode' => 'allow']);
        $this->post('/')->assertOk()->assertSee('posted');
        config(['draco.geo_mode' => 'block']);
        $this->get('/login')->assertForbidden();
        @unlink($file);
    }

    private static function field(string $html, string $name): string
    {
        return preg_match('/name="' . $name . '" value="([^"]*)"/', $html, $m) ? html_entity_decode($m[1]) : '';
    }

    public function test_a_blocked_visitor_can_ask_for_a_review_and_be_let_through(): void
    {
        config(['draco.waf_mode' => 'block']);
        $page = $this->get('/?q=1%27%20union%20select%20password%20from%20users--%20')->assertForbidden()->getContent();
        $this->assertStringContainsString('name="draco_review"', $page);
        $post = ['draco_review' => '1', 'draco_rule' => self::field($page, 'draco_rule'), 'draco_ts' => self::field($page, 'draco_ts'),
            'draco_sig' => self::field($page, 'draco_sig'), 'draco_email' => 'ana@example.org', 'draco_message' => 'I was <b>searching</b>'];
        $this->post('/', $post)->assertOk();
        $this->post('/', ['draco_sig' => 'forged'] + $post)->assertOk();
        $reviews = Store::reviews();
        $this->assertCount(1, $reviews);
        $this->assertSame('pending', $reviews[0]->verdict);
        $this->assertStringContainsString('I was searching', (string) $reviews[0]->fields);

        $this->artisan('draco:reviews')->assertSuccessful();
        $this->artisan('draco:reviews', ['id' => $reviews[0]->id, '--approve' => '1'])->assertSuccessful();
        $this->assertSame('approved', Store::review((int) $reviews[0]->id)->verdict);
        $this->get('/?q=1%27%20union%20select%20password%20from%20users--%20')->assertOk();
    }

    public function test_the_signed_test_request_is_answered_and_never_logged(): void
    {
        config(['draco.waf_mode' => 'block']);
        $host = new \DracoInsomnis\Laravel\LaravelHost();
        $this->get('/', ['X-Draco-Test' => \DracoInsomnis\Core\TestProbe::token($host, time())])->assertHeader('X-Draco-Test-Result', 'sqli|block');
        $this->get('/', ['X-Draco-Test' => '1.forged'])->assertOk()->assertHeaderMissing('X-Draco-Test-Result');
        $this->assertSame([], $this->events());
        $this->get('/?q=1%27%20union%20select%20password%20from%20users--%20')->assertForbidden();
        $this->assertSame(1, \DracoInsomnis\Core\Summary::waf(Store::wafRows(86400))['total']);
    }
}
