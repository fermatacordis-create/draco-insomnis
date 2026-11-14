<?php
/**
 * Draco Insomnis for Magento 2 and Mage-OS. Ab insomni custodita dracone.
 *
 * The deciding code is the same as in every other Draco package (core/, src/Core of the
 * repository); this module only connects it to the shop.
 *
 * @author  Notorius Vision
 * @license GPL-2.0-or-later
 */

declare(strict_types=1);

use Magento\Framework\Component\ComponentRegistrar;

ComponentRegistrar::register(ComponentRegistrar::MODULE, 'DracoInsomnis_Magento', __DIR__);

// Installed by hand in app/code, Composer does not know about the shared engines: load them from here.
spl_autoload_register(static function (string $class): void {
    $prefix = 'DracoInsomnis\\Core\\';
    if (strncmp($class, $prefix, strlen($prefix)) === 0) {
        $file = __DIR__ . '/core/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});
