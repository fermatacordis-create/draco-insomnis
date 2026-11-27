<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Firewall\Versions;

final class HideVersionsTest extends TestCase
{
    private function page(): string
    {
        add_action('wp_head', static function (): void {
            echo '<meta name="generator" content="Divi v.5.19.1" />' . "\n";
            echo "<meta content='Powered by Slider Revolution 7.2.7' name='generator'/>\n";
            echo '<meta name="description" content="kept">' . "\n";
        });
        ob_start();
        do_action('wp_head');
        $head = (string) ob_get_clean();
        // The addresses WordPress prints for styles and scripts go through these filters.
        $assets = [
            apply_filters('style_loader_src', includes_url('css/dashicons.min.css') . '?ver=' . get_bloginfo('version'), 'core'),
            apply_filters('style_loader_src', plugins_url('x/a.css') . '?ver=7.2.7', 'plugin'),
            apply_filters('script_loader_src', plugins_url('x/b.js') . '?ver=1795754314', 'stamp'),
        ];

        return $head . "\n" . implode("\n", $assets);
    }

    public function test_off_by_default_and_nothing_changes(): void
    {
        $this->assertFalse(Versions::active());
        Versions::boot();
        $html = $this->page();
        $this->assertStringContainsString('content="WordPress ' . get_bloginfo('version') . '"', $html);
        $this->assertStringContainsString('Divi v.5.19.1', $html);
        $this->assertStringContainsString('ver=7.2.7', $html);
    }

    public function test_on_takes_versions_out_of_the_head_and_the_feed(): void
    {
        update_option(Versions::OPTION, 'yes');
        Versions::boot();
        $html = $this->page();
        $wp = get_bloginfo('version');

        $this->assertStringNotContainsString('name="generator"', $html);
        $this->assertStringNotContainsString("name='generator'", $html);
        $this->assertStringNotContainsString('ver=' . $wp, $html);
        $this->assertStringNotContainsString('ver=7.2.7', $html);
        $this->assertStringContainsString('name="description" content="kept"', $html, 'other tags stay');
        $this->assertStringContainsString('ver=1795754314', $html, 'a timestamp is not a version');
        $this->assertSame('', apply_filters('the_generator', get_the_generator('rss2'), 'rss2'), 'feeds too');
    }

    public function test_the_code_changes_with_the_version_and_is_the_same_for_the_same_one(): void
    {
        $a = Versions::rewrite('https://example.com/wp-content/plugins/x/a.css?ver=7.2.7');
        $this->assertMatchesRegularExpression('/\?ver=[0-9a-f]{10}$/', $a);
        $this->assertSame($a, Versions::rewrite('https://example.com/wp-content/plugins/x/a.css?ver=7.2.7'));
        $this->assertNotSame($a, Versions::rewrite('https://example.com/wp-content/plugins/x/a.css?ver=7.2.8'));
        $this->assertStringEndsWith('&lang=es', Versions::rewrite('https://example.com/a.js?ver=abc-1.0.364&lang=es'));
        $this->assertStringNotContainsString('1.0.364', Versions::rewrite('https://example.com/a.js?ver=abc-1.0.364&lang=es'));
    }

    public function test_an_unbalanced_buffer_of_another_plugin_is_left_alone(): void
    {
        $level = ob_get_level();
        Versions::headStart();
        ob_start(); // another plugin's, never closed
        echo '<meta name="generator" content="X 1.0">';
        Versions::headEnd();
        $this->assertSame($level + 2, ob_get_level(), 'Draco did not close buffers that are not its own');
        $out = ob_get_clean() . ob_get_clean();
        $this->assertStringContainsString('X 1.0', $out);
    }
}
