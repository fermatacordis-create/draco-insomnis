<?php
/**
 * Plugin Name:       Draco Insomnis
 * Plugin URI:        https://github.com/fermatacordis-create/draco-insomnis
 * Description:       Ab insomni custodita dracone. Open-source security by Notorius Vision (OPNV Systems · OPNV SOLΞ): anti-bot shield without captchas, e-mail confirmation of forms and sign-ups, two-step login, firewall, anti-copy and site mail (SMTP).
 * Version:           0.1.16
 * Requires at least: 6.5
 * Requires PHP:      8.0
 * Author:            Notorius Vision · OPNV Systems
 * Author URI:        https://notoriusvision.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       draco-insomnis
 * Domain Path:       /languages
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

// Another copy is already running (the standalone plugin, or the one bundled in OPNV-WP): leave it in charge.
if (defined('DRACO_INSOMNIS_VERSION')) {
    return;
}

define('DRACO_INSOMNIS_VERSION', '0.1.16');
define('DRACO_INSOMNIS_FILE', __FILE__);
define('DRACO_INSOMNIS_DIR', __DIR__ . '/');

spl_autoload_register(static function (string $class): void {
    $prefix = 'DracoInsomnis\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = DRACO_INSOMNIS_DIR . 'src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

register_activation_hook(__FILE__, [\DracoInsomnis\Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [\DracoInsomnis\Plugin::class, 'deactivate']);
add_action('plugins_loaded', static function (): void {
    // The plugin ships its own translations; WordPress.org language packs, when they exist, take precedence.
    load_plugin_textdomain('draco-insomnis', false, dirname(plugin_basename(DRACO_INSOMNIS_FILE)) . '/languages'); // phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound
}, 0);
add_action('plugins_loaded', [\DracoInsomnis\Firewall\Waf::class, 'boot'], 1);
add_action('plugins_loaded', [\DracoInsomnis\AntiCopy\Guard::class, 'boot'], 2);
add_action('plugins_loaded', [\DracoInsomnis\Plugin::class, 'boot']);
