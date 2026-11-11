<?php
/**
 * Loads a real, throwaway WordPress with Draco Insomnis active (see bin/ci-wp-setup.sh).
 * The tests write to its database: never point WP_DIR at a site you care about.
 */
declare(strict_types=1);

$wpDir = rtrim((string) (getenv('WP_DIR') ?: '/tmp/wordpress'), '/');
if (!is_file($wpDir . '/wp-load.php')) {
    fwrite(STDERR, "No WordPress at $wpDir. Run bin/ci-wp-setup.sh first, or set WP_DIR.\n");
    exit(1);
}
if (!is_file($wpDir . '/.draco-ci')) {
    fwrite(STDERR, "$wpDir was not created by bin/ci-wp-setup.sh. The tests only run on a throwaway site.\n");
    exit(1);
}

$_SERVER['HTTP_HOST'] = $_SERVER['HTTP_HOST'] ?? 'localhost';
$_SERVER['SERVER_NAME'] = $_SERVER['SERVER_NAME'] ?? 'localhost';
$_SERVER['SERVER_PORT'] = $_SERVER['SERVER_PORT'] ?? '80';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['REMOTE_ADDR'] = '203.0.113.10';

// PHPUnit includes this file inside a method: WordPress's file-level variables must be global.
// phpcs:ignore
global $wpdb, $wp, $wp_query, $wp_the_query, $wp_rewrite, $wp_roles, $wp_version, $wp_db_version, $table_prefix,
    $shortcode_tags, $wp_filter, $wp_actions, $wp_current_filter, $wp_locale, $wp_embed, $wp_widget_factory,
    $phpmailer, $current_user, $current_site, $current_blog, $pagenow, $blog_id, $wp_plugin_paths,
    $wp_theme_directories, $allowedposttags, $allowedtags, $wp_object_cache, $wp_post_types, $wp_taxonomies;

define('WP_USE_THEMES', false);
require $wpDir . '/wp-load.php';

if (!defined('DRACO_INSOMNIS_VERSION')) {
    fwrite(STDERR, "Draco Insomnis is not active in $wpDir.\n");
    exit(1);
}

require_once ABSPATH . WPINC . '/PHPMailer/PHPMailer.php';
require_once ABSPATH . WPINC . '/PHPMailer/Exception.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
require __DIR__ . '/TestCase.php';
