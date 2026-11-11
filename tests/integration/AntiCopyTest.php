<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\AntiCopy\Guard;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Store;

/** The "block" answer of the pace limit ends the request, so it is tested over HTTP in bin/ci-http-smoke.sh. */
final class AntiCopyTest extends TestCase
{
    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    private function read(string $route, string $method = 'GET')
    {
        return Guard::rest(null, null, new \WP_REST_Request($method, $route));
    }

    public function test_it_is_off_unless_switched_on(): void
    {
        $this->assertSame('off', Guard::mode(Guard::OPTION_REST));
        $this->assertSame('off', Guard::mode(Guard::OPTION_RATE));
        update_option(Guard::OPTION_REST, 'nonsense');
        $this->assertSame('off', Guard::mode(Guard::OPTION_REST));
    }

    public function test_log_mode_lets_the_read_through_and_writes_it_down(): void
    {
        update_option(Guard::OPTION_REST, 'log');
        $this->assertNull($this->read('/wp/v2/posts'));
        $rows = Store::recentWhere('anticopy:');
        $this->assertCount(1, $rows);
        $this->assertSame('anticopy_rest_log', $rows[0]['reasons']);
        $this->assertSame('/wp/v2/posts', json_decode($rows[0]['fields'], true)['referer']);
        $this->assertSame('doubtful', $rows[0]['verdict'], 'never counts as a bot attempt for the shield');
    }

    public function test_block_mode_closes_content_reads_to_anonymous_visitors(): void
    {
        update_option(Guard::OPTION_REST, 'block');
        $result = $this->read('/wp/v2/posts');
        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame(401, $result->get_error_data()['status']);
        $this->assertInstanceOf(\WP_Error::class, $this->read('/wp/v2/media/12'));
    }

    public function test_what_stays_open(): void
    {
        update_option(Guard::OPTION_REST, 'block');
        update_option(Guard::OPTION_REST_ALLOW, "/wp/v2/posts\n  /wp/v2/categories/ \nnot-a-route");
        $this->assertNull($this->read('/wp/v2/posts'), 'allow list');
        $this->assertNull($this->read('/wp/v2/posts/7'), 'allow list covers what is under it');
        $this->assertNull($this->read('/wp/v2/categories'), 'trailing slash and spaces are tidied');
        $this->assertInstanceOf(\WP_Error::class, $this->read('/wp/v2/postsx'), 'a prefix is a whole segment');
        $this->assertNull($this->read('/contact-form-7/v1/contact-forms/5/feedback'), 'other APIs are untouched');
        $this->assertNull($this->read('/wc/store/v1/cart'));
        $this->assertNull($this->read('/wp/v2/comments', 'POST'), 'only reads are closed');
        add_filter('draco_insomnis_rest_allow', static fn (array $list) => array_merge($list, ['/wp/v2/pages']));
        $this->assertNull($this->read('/wp/v2/pages/2'));
    }

    public function test_people_logged_in_and_administrator_addresses_pass(): void
    {
        update_option(Guard::OPTION_REST, 'block');
        wp_set_current_user($this->user('subscriber')->ID);
        $this->assertNull($this->read('/wp/v2/posts'));
        wp_set_current_user(0);
        update_option(Plugin::OPTION_ADMIN_IPS, [self::VISITOR_IP]);
        $this->assertNull($this->read('/wp/v2/posts'));
    }

    public function test_a_verified_search_engine_passes_and_an_impostor_does_not(): void
    {
        update_option(Guard::OPTION_REST, 'block');
        $_SERVER['HTTP_USER_AGENT'] = self::GOOGLEBOT;
        add_filter('draco_insomnis_crawler_verified', '__return_true');
        $this->assertNull($this->read('/wp/v2/posts'));
        remove_filter('draco_insomnis_crawler_verified', '__return_true');
        add_filter('draco_insomnis_crawler_verified', '__return_false');
        $this->assertInstanceOf(\WP_Error::class, $this->read('/wp/v2/posts'));
    }

    public function test_the_dns_check_is_real_and_kept_for_a_day(): void
    {
        // 127.0.0.1 reverse-resolves to localhost, never to googlebot.com.
        $this->assertFalse(Guard::verifiedCrawler('127.0.0.1', self::GOOGLEBOT));
        $this->assertSame('n', get_transient('draco_crawler_' . md5('127.0.0.1|googlebot')));
        $this->assertFalse(Guard::verifiedCrawler('127.0.0.1', 'Mozilla/5.0 Chrome/131.0'), 'no claim, no lookup');
        $this->assertFalse(Guard::verifiedCrawler('not-an-ip', self::GOOGLEBOT));
    }

    public function test_pace_log_mode_writes_down_each_address_once_per_minute(): void
    {
        update_option(Guard::OPTION_RATE, 'log');
        update_option(Guard::OPTION_RATE_IP, 10);
        for ($i = 0; $i < 15; $i++) {
            Guard::pace();
        }
        $rows = Store::recentWhere('anticopy:');
        $this->assertCount(1, $rows);
        $this->assertSame('anticopy_rate_ip_log', $rows[0]['reasons']);
    }

    public function test_pace_counts_a_whole_network(): void
    {
        update_option(Guard::OPTION_RATE, 'log');
        update_option(Guard::OPTION_RATE_IP, 100);
        update_option(Guard::OPTION_RATE_NET, 10);
        for ($i = 1; $i <= 12; $i++) {
            $_SERVER['REMOTE_ADDR'] = '198.51.100.' . $i;
            Guard::pace();
        }
        $rows = Store::recentWhere('anticopy:');
        $this->assertCount(1, $rows);
        $this->assertSame('anticopy_rate_net_log', $rows[0]['reasons']);
        $this->assertSame('198.51.100.11', $rows[0]['ip']);
    }

    public function test_pace_never_touches_people_logged_in_administrators_or_search_engines(): void
    {
        update_option(Guard::OPTION_RATE, 'log');
        update_option(Guard::OPTION_RATE_IP, 10);
        update_option(Plugin::OPTION_ADMIN_IPS, ['203.0.113.200']);
        $_SERVER['REMOTE_ADDR'] = '203.0.113.200';
        for ($i = 0; $i < 15; $i++) {
            Guard::pace();
        }
        $_SERVER['REMOTE_ADDR'] = '192.0.2.10';
        $_SERVER['HTTP_USER_AGENT'] = self::GOOGLEBOT;
        add_filter('draco_insomnis_crawler_verified', '__return_true');
        for ($i = 0; $i < 15; $i++) {
            Guard::pace();
        }
        $_SERVER['REMOTE_ADDR'] = '192.0.2.99';
        wp_set_current_user($this->user('subscriber')->ID);
        for ($i = 0; $i < 15; $i++) {
            Guard::pace();
        }
        $this->assertSame([], Store::recentWhere('anticopy:'));
    }

    public function test_limits_below_ten_fall_back_to_the_defaults(): void
    {
        update_option(Guard::OPTION_RATE, 'log');
        update_option(Guard::OPTION_RATE_IP, 1);
        for ($i = 0; $i < 15; $i++) {
            Guard::pace();
        }
        $this->assertSame([], Store::recentWhere('anticopy:'), 'a typo of 1 must not lock the site');
    }
}
