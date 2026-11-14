<?php

declare(strict_types=1);

// Draco Insomnis Server: the shared engines (core/) and the server adapter (src/).
spl_autoload_register(static function (string $class): void {
    foreach (['DracoInsomnis\\Core\\' => __DIR__ . '/core/', 'DracoInsomnis\\Server\\' => __DIR__ . '/src/'] as $prefix => $dir) {
        if (strncmp($class, $prefix, strlen($prefix)) === 0) {
            $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (is_file($file)) {
                require_once $file;
            }

            return;
        }
    }
});
