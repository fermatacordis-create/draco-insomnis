<?php

/**
 * Autoloader for the shared engines (DracoInsomnis\Core), copied into lib/Core by the build.
 *
 * @copyright   (C) 2026 Notorius Vision
 * @license     GNU General Public License version 2 or later
 */

\defined('_JEXEC') or die;

spl_autoload_register(static function (string $class): void {
    $prefix = 'DracoInsomnis\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
