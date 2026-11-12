<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Tests\Feature;

use DracoInsomnis\Laravel\Tests\TestCase;

final class ShieldTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['draco.shield' => true]);
    }

    public function test_the_form_gets_the_stamp_and_the_trap(): void
    {
        $html = $this->get('/register')->assertOk()->getContent();
        $this->assertStringContainsString('name="' . $this->shield()->stampField() . '"', $html);
        $this->assertStringContainsString('name="' . $this->shield()->trapField() . '"', $html);
    }

    public function test_nothing_is_added_when_the_shield_is_off(): void
    {
        config(['draco.shield' => false]);
        $this->assertStringNotContainsString('dr_', $this->get('/register')->getContent());
    }

    public function test_a_bot_gets_no_account_and_leaves_evidence(): void
    {
        $this->post('/register', [
            'name' => 'usru88w16kx',
            'email' => 'bot@spam.example',
            'password' => 'never-stored',
            $this->shield()->trapField() => 'http://spam.example',
        ])->assertSessionHasErrors(['email' => 'The registration could not be completed.'])->assertDontSee('account created');
        $events = $this->events();
        $this->assertCount(1, $events);
        $this->assertSame('laravel_register', $events[0]->endpoint);
        $this->assertSame('bot', $events[0]->verdict);
        $this->assertStringContainsString('honeypot', $events[0]->reasons);
        $this->assertStringContainsString('bot@spam.example', $events[0]->fields);
        $this->assertStringNotContainsString('never-stored', serialize($events), 'passwords are never kept');
    }

    public function test_a_json_client_gets_a_422(): void
    {
        $this->postJson('/register', ['name' => 'usru88w16kx', 'email' => 'bot@spam.example', $this->shield()->trapField() => 'x'])
            ->assertStatus(422)->assertJsonValidationErrors(['email']);
    }

    public function test_a_script_posting_straight_to_the_route_gets_no_account(): void
    {
        $this->withHeader('User-Agent', 'python-requests/2.32')
            ->post('/register', ['name' => 'verifrw8mfsrh', 'email' => 'script@spam.example'])
            ->assertSessionHasErrors('email');
    }

    public function test_a_person_signs_up_and_leaves_no_trace(): void
    {
        $this->post('/register', [
            'name' => 'Maria Garcia',
            'email' => 'maria@example.org',
            $this->shield()->stampField() => $this->personStamp(),
        ])->assertOk()->assertSee('account created');
        $this->assertSame([], $this->events());
    }

    public function test_three_bot_attempts_block_the_address(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $this->post('/register', ['name' => "bot$i", 'email' => "bot$i@spam.example", $this->shield()->trapField() => 'x']);
        }
        $this->assertSame('Automatic: 3 bot attempts in 24 h', $this->blocks()[0]->reason);
    }

    public function test_spanish_message(): void
    {
        app()->setLocale('es');
        $this->post('/register', ['name' => 'x', 'email' => 'bot@spam.example', $this->shield()->trapField() => 'x'])
            ->assertSessionHasErrors(['email' => 'No se ha podido completar el registro.']);
    }
}
