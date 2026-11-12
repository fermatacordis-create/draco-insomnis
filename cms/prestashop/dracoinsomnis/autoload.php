<?php
/**
 * @author    Notorius Vision
 * @license   GPL-2.0-or-later
 */

declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'DracoInsomnis\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
