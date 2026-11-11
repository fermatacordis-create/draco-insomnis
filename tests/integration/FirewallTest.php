<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Firewall\Waf;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Store;

/**
 * The firewall in "log only" mode. Blocking answers with a 403 page and ends the request, so that
 * part is tested over HTTP in bin/ci-http-smoke.sh.
 */
final class FirewallTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        update_option(Waf::OPTION_ENABLED, 'yes');
        update_option(Waf::OPTION_MODE, 'log');
    }

    private function request(string $query): void
    {
        $_SERVER['REQUEST_URI'] = '/?' . http_build_query(['q' => $query]);
        $_GET = ['q' => $query];
    }

    public function test_an_attack_is_recorded_in_log_mode_and_the_request_goes_on(): void
    {
        $this->request("1' UNION SELECT user_pass FROM wp_users-- ");
        Waf::inspect();
        $rows = Store::recentWhere('waf:');
        $this->assertCount(1, $rows);
        $this->assertSame('doubtful', $rows[0]['verdict']);
        $this->assertFalse(Store::isBlocked('', self::VISITOR_IP), 'log mode never blocks');
    }

    public function test_ordinary_text_is_not_an_attack(): void
    {
        $this->request('european union select committee');
        Waf::inspect();
        $this->request('O\'Brien & sons <3');
        Waf::inspect();
        $this->assertSame([], Store::recentWhere('waf:'));
    }

    public function test_editors_and_administrator_addresses_are_not_inspected(): void
    {
        $this->request('<script>alert(1)</script>');
        wp_set_current_user($this->user('editor')->ID);
        Waf::inspect();
        wp_set_current_user(0);
        update_option(Plugin::OPTION_ADMIN_IPS, [self::VISITOR_IP]);
        Waf::inspect();
        $this->assertSame([], Store::recentWhere('waf:'));
    }

    public function test_it_only_runs_when_switched_on(): void
    {
        $this->assertTrue(Waf::active());
        update_option(Waf::OPTION_ENABLED, 'no');
        $this->assertFalse(Waf::active());
    }

    public function test_pingbacks_are_removed_from_xml_rpc(): void
    {
        $methods = Waf::xmlrpcMethods(['pingback.ping' => 'x', 'pingback.extensions.getPingbacks' => 'x', 'wp.getPosts' => 'x']);
        $this->assertSame(['wp.getPosts'], array_keys($methods));
    }

    public function test_the_user_list_is_hidden_from_visitors_only(): void
    {
        $endpoints = ['/wp/v2/users' => 1, '/wp/v2/users/(?P<id>[\d]+)' => 1, '/wp/v2/posts' => 1];
        $this->assertSame(['/wp/v2/posts'], array_keys(Waf::hideUserEndpoints($endpoints)));
        wp_set_current_user($this->user('administrator')->ID);
        $this->assertCount(3, Waf::hideUserEndpoints($endpoints));
    }

    public function test_ten_failed_logins_lock_the_address_for_a_while(): void
    {
        for ($i = 0; $i < 9; $i++) {
            Waf::loginFailed();
        }
        $this->assertNull(Waf::refuseLockedLogin(null));
        Waf::loginFailed();
        $result = Waf::refuseLockedLogin(null);
        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('draco_login_locked', $result->get_error_code());
        $_SERVER['REMOTE_ADDR'] = '203.0.113.77';
        $this->assertNull(Waf::refuseLockedLogin(null));
    }
}
