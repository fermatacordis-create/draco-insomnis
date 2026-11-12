<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Tests\Feature;

use DracoInsomnis\Laravel\Tests\TestCase;

final class FirewallTest extends TestCase
{
    public function test_off_by_default_the_app_works_as_before(): void
    {
        $this->get(self::ATTACK)->assertOk()->assertSee('home');
        $this->assertSame([], $this->events());
    }

    public function test_log_only_records_and_lets_it_through(): void
    {
        config(['draco.waf_mode' => 'log']);
        $this->get(self::ATTACK)->assertOk();
        $events = $this->events();
        $this->assertCount(1, $events);
        $this->assertSame('waf:sqli', $events[0]->endpoint);
        $this->assertSame('doubtful', $events[0]->verdict);
        $this->assertSame(self::VISITOR, $events[0]->ip);
    }

    public function test_ordinary_words_pass_and_leave_no_trace(): void
    {
        config(['draco.waf_mode' => 'block']);
        $this->get('/?q=European+Union+select+committee')->assertOk();
        $this->assertSame([], $this->events());
    }

    public function test_block_answers_403_without_details(): void
    {
        config(['draco.waf_mode' => 'block']);
        $this->get(self::ATTACK)->assertForbidden()->assertSee('Ref.')->assertDontSee('sqli');
        $this->withHeader('User-Agent', 'sqlmap/1.8')->get('/')->assertForbidden();
    }

    public function test_unknown_paths_are_inspected_too(): void
    {
        config(['draco.waf_mode' => 'block']);
        $this->get('/.env')->assertForbidden();
        $this->assertSame('waf:probe', $this->events()[0]->endpoint);
    }

    public function test_five_attacks_block_the_address_which_can_still_read_but_not_post(): void
    {
        config(['draco.waf_mode' => 'block']);
        for ($i = 0; $i < 5; $i++) {
            $this->get(self::ATTACK);
        }
        $blocks = $this->blocks();
        $this->assertCount(1, $blocks);
        $this->assertSame(self::VISITOR, $blocks[0]->value);
        $this->assertSame('Firewall: 5 attacks in 10 minutes', $blocks[0]->reason);
        $this->get('/')->assertOk();
        $this->post('/')->assertForbidden();
        $this->get('/login')->assertForbidden();
    }

    public function test_an_address_listed_in_the_settings_is_never_blocked(): void
    {
        config(['draco.waf_mode' => 'block', 'draco.admin_ips' => [self::VISITOR]]);
        $this->get(self::ATTACK)->assertOk();
    }

    public function test_excepted_paths_are_left_alone(): void
    {
        config(['draco.waf_mode' => 'block', 'draco.except' => ['webhooks']]);
        $this->get('/webhooks/x?q=1%27%20union%20select%20password%20from%20users--%20')->assertNotFound();
        $this->assertSame([], $this->events());
    }

    public function test_users_with_the_bypass_ability_are_not_inspected_and_their_address_is_remembered(): void
    {
        config(['draco.waf_mode' => 'block']);
        $this->withSessionCookie()->actingAs($this->user(true))->get(self::ATTACK)->assertOk();
        $this->assertContains(self::VISITOR, \DracoInsomnis\Laravel\Guard::host()->adminIps());
    }

    public function test_other_logged_in_users_are_inspected(): void
    {
        config(['draco.waf_mode' => 'block']);
        $this->withSessionCookie()->actingAs($this->user(false))->get(self::ATTACK)->assertForbidden();
    }

    public function test_a_session_cookie_that_logs_nobody_in_does_not_dodge_the_firewall(): void
    {
        config(['draco.waf_mode' => 'block']);
        $this->withSessionCookie()->get(self::ATTACK)->assertForbidden();
    }

    public function test_emergency_exit(): void
    {
        config(['draco.waf_mode' => 'block', 'draco.waf_off' => true]);
        $this->get(self::ATTACK)->assertOk();
    }
}
