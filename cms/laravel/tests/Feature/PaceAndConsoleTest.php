<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Tests\Feature;

use DracoInsomnis\Laravel\DracoFilter;
use DracoInsomnis\Laravel\Tests\TestCase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;

final class PaceAndConsoleTest extends TestCase
{
    public function test_past_the_limit_pages_get_429_and_one_evidence_line(): void
    {
        config(['draco.pace_mode' => 'block', 'draco.anticopy_rate_ip' => 10]);
        $codes = [];
        for ($i = 0; $i < 12; $i++) {
            $codes[] = $this->get('/', ['Accept' => 'text/html'])->getStatusCode();
        }
        $this->assertSame([200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 429, 429], $codes);
        $this->assertCount(1, $this->events());
        $this->assertSame('anticopy:rate_ip', $this->events()[0]->endpoint);
    }

    public function test_json_api_clients_are_not_counted(): void
    {
        config(['draco.pace_mode' => 'block', 'draco.anticopy_rate_ip' => 10]);
        for ($i = 0; $i < 15; $i++) {
            $this->getJson('/api/items')->assertOk();
        }
        $this->assertSame([], $this->events());
    }

    public function test_logged_in_users_are_never_limited(): void
    {
        config(['draco.pace_mode' => 'block', 'draco.anticopy_rate_ip' => 10]);
        for ($i = 0; $i < 15; $i++) {
            $this->withSessionCookie()->actingAs($this->user(false))->get('/', ['Accept' => 'text/html'])->assertOk();
        }
    }

    public function test_a_crawler_name_is_not_trusted_but_the_app_can_vouch_for_it(): void
    {
        config(['draco.pace_mode' => 'block', 'draco.anticopy_rate_ip' => 10]);
        $google = ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'Accept' => 'text/html'];
        for ($i = 0; $i < 10; $i++) {
            $this->get('/', $google);
        }
        $this->get('/', $google)->assertStatus(429);

        Event::listen(DracoFilter::class, function (DracoFilter $f): void {
            if ($f->name === 'crawler_verified') {
                $f->value = true;
            }
        });
        $this->get('/', $google)->assertOk();
    }

    public function test_status_evidence_block_and_cleanup_commands(): void
    {
        config(['draco.waf_mode' => 'log']);
        $this->get(self::ATTACK);
        $this->artisan('draco:status')->expectsOutputToContain('Firewall')->assertSuccessful();
        $this->artisan('draco:evidence', ['ip' => self::VISITOR])->expectsOutputToContain('waf:sqli')->assertSuccessful();
        $this->artisan('draco:evidence', ['ip' => 'nope'])->assertFailed();

        $this->artisan('draco:block', ['value' => '198.51.100.9', '--days' => 7])->assertSuccessful();
        $this->artisan('draco:block', ['value' => '198.51.100.9', '--days' => 3])->assertFailed();
        $id = DB::table('draco_blocks')->value('id');
        $this->artisan('draco:block', ['--unblock' => $id])->assertSuccessful();
        $this->assertSame([], $this->blocks());

        DB::table('draco_events')->update(['created_at' => gmdate('Y-m-d H:i:s', time() - 91 * 86400)]);
        $this->artisan('draco:cleanup')->expectsOutputToContain('1 rows removed')->assertSuccessful();
    }
}
