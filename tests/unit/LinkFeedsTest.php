<?php
declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;

/** Which link list may run where (docs/adr/0001): checked on the source, as the plugin is built. */
final class LinkFeedsTest extends TestCase
{
    private function source(): string
    {
        return (string) file_get_contents(dirname(__DIR__, 2) . '/src/Gate/LinkCheck.php');
    }

    public function test_urlhaus_stays_out_of_bundled_copies(): void
    {
        $src = $this->source();
        $this->assertMatchesRegularExpression('/function available\(\): bool\s*\{\s*return !Plugin::bundled\(\);/', $src);
        $this->assertMatchesRegularExpression('/function active\(\): bool\s*\{\s*return self::available\(\)/', $src, 'URLhaus is only active where it is available');
    }

    public function test_phishtank_does_not_depend_on_being_standalone(): void
    {
        $this->assertMatchesRegularExpression('/function phishtankActive\(\): bool\s*\{\s*return get_option\(self::PT_OPTION_ENABLED, \'no\'\) === \'yes\';/', $this->source());
    }

    public function test_threatfox_and_the_stale_phishing_database_are_not_used(): void
    {
        $src = strtolower($this->source());
        $this->assertStringNotContainsString('threatfox', $src);
        $this->assertStringNotContainsString('phishing.database', $src);
        $this->assertStringNotContainsString('phishing-database', $src);
    }
}
