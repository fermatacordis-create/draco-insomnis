<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Guardia\CoreFiles;
use DracoInsomnis\Guardia\Diff;
use PHPUnit\Framework\TestCase;

/** Guardia: what is not part of WordPress but cannot do anything is a note, not an alarm. */
final class GuardiaHarmlessTest extends TestCase
{
    public function test_stubs_html_and_wordfence_are_harmless(): void
    {
        $this->assertTrue(CoreFiles::harmless('opnv-i18n-oneshot.php', "<?php // neutralized\n"));
        $this->assertTrue(CoreFiles::harmless('opnv-edge-diag.php', "<?php http_response_code(404); exit; // neutralized probe\n"));
        $this->assertTrue(CoreFiles::harmless('opnv-purge.php', "<?php /* neutralized */ exit;\n"));
        $this->assertTrue(CoreFiles::harmless('audit.php', "<?php\n"));
        $this->assertTrue(CoreFiles::harmless('default.php', "<!DOCTYPE html>\n<html><body>Hosting default page</body></html>"));
        $wf = "<?php\n// Before removing this file, please verify the PHP ini setting `auto_prepend_file` does not point to this.\n"
            . "if (file_exists(__DIR__.'/wp-content/plugins/wordfence/waf/bootstrap.php')) {\n\tdefine(\"WFWAF_LOG_PATH\", __DIR__.'/wp-content/wflogs/');\n\tinclude_once __DIR__.'/wp-content/plugins/wordfence/waf/bootstrap.php';\n}\n";
        $this->assertTrue(CoreFiles::harmless('wordfence-waf.php', $wf));
    }

    public function test_real_code_stays_high(): void
    {
        $this->assertFalse(CoreFiles::harmless('opnv-extract.php', "<?php\n\$zip = new ZipArchive();\n\$zip->open('x.zip');\n"));
        $this->assertFalse(CoreFiles::harmless('x.php', "<?php eval(\$_POST['a']);"));
        $this->assertFalse(CoreFiles::harmless('wordfence-waf.php', "<?php // wp-content/plugins/wordfence/waf/bootstrap.php\neval(base64_decode(\$_GET['x']));"), 'a lookalike with code');
        $this->assertFalse(CoreFiles::harmless('x.php', null), 'unreadable counts as code');
        $this->assertFalse(CoreFiles::harmless('x.php', "<?php exit; ?>\n<?php system(\$_GET['c']);"), 'code after an early exit');
    }

    public function test_severity_in_baseline_and_after(): void
    {
        $items = CoreFiles::deviations([], [], ['opnv-stub.php', 'opnv-tool.php'], ['opnv-stub.php' => "<?php exit;", 'opnv-tool.php' => "<?php require 'wp-load.php'; update_option('x', 1);"]);
        $base = array_column(Diff::compare([], $items, true), 'severity', 'id');
        $this->assertSame([Diff::INFO, Diff::HIGH], [$base['core|opnv-stub.php'], $base['core|opnv-tool.php']]);
        $new = array_column(Diff::compare(['core|x.php' => ['state' => Diff::PRESENT, 'fp' => 'extra', 'back' => 0]], $items, false), 'severity', 'id');
        $this->assertSame([Diff::INFO, Diff::HIGH], [$new['core|opnv-stub.php'], $new['core|opnv-tool.php']]);
        $cron = Diff::compare(['admin|a' => ['state' => Diff::PRESENT, 'fp' => 'x', 'back' => 0]], ['admin|a' => ['fp' => 'x'], 'cron|rank_math/redirection/clean_trashed' => ['fp' => '']], false);
        $this->assertSame(Diff::INFO, $cron[0]['severity'], 'a hook no code handles cannot run anything');
    }
}
