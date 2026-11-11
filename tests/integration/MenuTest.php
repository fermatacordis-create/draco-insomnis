<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Admin\Brand;

/** The standalone plugin keeps its own menu, whatever another plugin asks for. */
final class MenuTest extends TestCase
{
    public function test_the_standalone_plugin_ignores_the_menu_parent_filter(): void
    {
        $this->assertFalse(\DracoInsomnis\Plugin::bundled(), 'the test site runs the standalone plugin');
        add_filter('draco_insomnis_menu_parent', static fn () => 'some-other-plugin');
        $this->assertSame('', Brand::nestedParent());
        $_GET['page'] = 'draco-insomnis-firewall';
        $this->assertSame('tools.php', Brand::highlightParent('tools.php'), 'menu highlighting is left alone');
    }

    public function test_the_own_menu_lists_every_screen(): void
    {
        global $menu, $submenu, $_wp_submenu_nopriv, $_registered_pages;
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        wp_set_current_user($this->user('administrator')->ID);
        $menu = $submenu = $_wp_submenu_nopriv = [];
        do_action('admin_menu');
        $this->assertArrayHasKey(Brand::PARENT, $submenu);
        $slugs = array_column($submenu[Brand::PARENT], 2);
        foreach (['draco-insomnis', 'draco-insomnis-shield', 'draco-insomnis-forms', 'draco-insomnis-login', 'draco-insomnis-firewall', 'draco-insomnis-anticopy', 'draco-insomnis-mail'] as $slug) {
            $this->assertContains($slug, $slugs);
        }
    }
}
