<?php
/**
 * Plugin Name:       Draco Insomnis
 * Plugin URI:        https://github.com/fermatacordis-create/draco-insomnis
 * Description:       Ab insomni custodita dracone. Open-source security by Notorius Vision (OPNV Systems · OPNV SOLΞ): anti-bot shield without captchas, e-mail confirmation of forms and sign-ups, two-step login, firewall, anti-copy and site mail (SMTP).
 * Version:           0.1.35
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

define('DRACO_INSOMNIS_VERSION', '0.1.35');
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

// Declared inside if (): an unconditional top-level function is defined when the file is compiled,
// before the early return above, and a second copy of Draco (standalone + bundled) would be fatal.
if (!function_exists('draco_insomnis_form_fields')) {
    /** For a form Draco does not build: the hidden stamp and trap to print inside it ('' while the shield is off). */
    function draco_insomnis_form_fields(): string
    {
        return \DracoInsomnis\Shield\Guard::formFields();
    }
}

if (!function_exists('draco_insomnis_form_check')) {
    /**
     * For the same form, when it is sent: false when the shield judges it a bot. $email is the sender's
     * address, $form a short name of the form (it shows in the shield's log).
     */
    function draco_insomnis_form_check(string $email = '', string $form = 'form'): bool
    {
        return \DracoInsomnis\Shield\Guard::formCheck($email, $form);
    }
}

register_activation_hook(__FILE__, [\DracoInsomnis\Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [\DracoInsomnis\Plugin::class, 'deactivate']);
add_action('plugins_loaded', static function (): void {
    // The plugin ships its own translations; WordPress.org language packs, when they exist, take precedence.
    load_plugin_textdomain('draco-insomnis', false, dirname(plugin_basename(DRACO_INSOMNIS_FILE)) . '/languages'); // phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound
}, 0);
add_action('plugins_loaded', [\DracoInsomnis\Firewall\Waf::class, 'boot'], 1);
add_action('plugins_loaded', [\DracoInsomnis\AntiCopy\Guard::class, 'boot'], 2);
add_action('plugins_loaded', [\DracoInsomnis\Plugin::class, 'boot']);
