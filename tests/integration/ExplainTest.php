<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Firewall\Explain;
use DracoInsomnis\Shield\Store;

/** Addresses taken from a real firewall log (notoriusvision.com, November 2026). */
final class ExplainTest extends TestCase
{
    /** @return array<string, array{string, string, string}> */
    public static function probes(): array
    {
        return [
            'backup' => ['/backup.sql', 'backup', ''],
            'compressed dump' => ['/dump.sql.gz', 'backup', ''],
            'config copy' => ['/wp-config.php.bak', 'secrets', ''],
            'log' => ['/wp-content/debug.log', 'log', ''],
            'server status' => ['/server-status', 'info', ''],
            'phpinfo' => ['/phpinfo.php', 'info', ''],
            'adminer' => ['/adminer.php', 'admin_tool', ''],
            'phpunit' => ['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', 'exploit', 'PHPUnit CVE-2017-9841'],
            'phpunit in a framework folder' => ['/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', 'exploit', 'PHPUnit CVE-2017-9841'],
            'php-cgi' => ['/cgi-bin/php-cgi?-d allow_url_include=on -d auto_prepend_file=php://input', 'exploit', 'PHP-CGI CVE-2012-1823 / CVE-2024-4577'],
            'back door' => ['/alfa.php', 'shell', 'Alfa shell'],
            'env file' => ['/.env', 'secrets', ''],
            'installer' => ['/wp-admin/install.php', 'installer', ''],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('probes')]
    public function test_what_a_probe_was_after(string $requested, string $kind, string $signature): void
    {
        $this->assertSame($kind, Explain::kind('waf_probe', $requested));
        $this->assertSame($signature, Explain::signature($requested));
    }

    public function test_other_rules_keep_their_kind_and_known_attacks_are_named(): void
    {
        $spip = '/?page=recherche&recherche=<?php header("X-Spip-Filtre: html_entity_decode"); ?><?php @file_put_contents(_DIR_RACINE."img_cache.php",base64_decode("PD9w"));';
        $this->assertSame('waf_code', Explain::kind('waf_code', $spip));
        $this->assertSame('SPIP', Explain::signature($spip));
        $this->assertSame('/proc/self/environ', Explain::signature('/proc/self/environ?.js'));
        $this->assertSame('PHP-CGI CVE-2012-1823 / CVE-2024-4577', Explain::signature('/index.php?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input'));
        $this->assertSame('', Explain::signature('/wp-login.php'), 'never a guess');
        $this->assertSame('', Explain::signature('/shop/?s=select+from'), 'never a guess');
        $this->assertSame('probe', Explain::kind('waf_probe', '/.ds_store'));
    }

    public function test_the_answer_is_only_said_when_known(): void
    {
        $this->assertSame('403', Explain::answer('bot'));
        $this->assertSame('', Explain::answer('doubtful'), 'log only: WordPress answered and it was not written down');
    }

    public function test_the_summary_leaves_administrators_out_and_groups_by_kind(): void
    {
        $log = static function (string $ip, string $rule, string $path): void {
            Store::log($ip, $ip, 'waf:test', ['score' => 100, 'verdict' => 'bot', 'reasons' => [$rule]], 'curl/8', ['username' => '', 'email' => '', 'role' => '', 'referer' => $path]);
        };
        $log('198.51.100.7', 'waf_probe', '/backup.sql');
        $log('198.51.100.7', 'waf_probe', '/phpinfo.php');
        $log('198.51.100.8', 'waf_code', '/');
        $log('192.0.2.50', 'waf_probe', '/backup.sql');
        $log('192.0.2.50', 'waf_probe', '/debug.log');

        $all = Store::wafSummary(7);
        $this->assertSame(5, $all['total']);
        $this->assertSame(4, $all['rules']['waf_probe']);

        $mine = Store::wafSummary(7, ['192.0.2.50'], [Explain::class, 'kind']);
        $this->assertSame(3, $mine['total'], 'an administrator\'s own tests do not count');
        $got = array_intersect_key($mine['rules'], ['backup' => 0, 'info' => 0, 'waf_code' => 0]);
        ksort($got);
        $this->assertSame(['backup' => 1, 'info' => 1, 'waf_code' => 1], $got);
        $this->assertArrayNotHasKey('log', $mine['rules']);
        $this->assertArrayNotHasKey('192.0.2.50', $mine['ips']);
        $this->assertSame(2, $mine['ips']['198.51.100.7']);
    }
}
