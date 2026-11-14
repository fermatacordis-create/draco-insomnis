<?php
/**
 * Draco Insomnis Server — loaded before every PHP script through auto_prepend_file.
 * Ab insomni custodita dracone.
 *
 * Does nothing on the command line, nor twice. Any error of Draco itself is written to the PHP log
 * and the request goes on: a broken guard must never take a site down.
 */

declare(strict_types=1);

if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' || defined('DRACO_SERVER_GUARD')) {
    return;
}
define('DRACO_SERVER_GUARD', '0.1.25');

(static function (): void {
    try {
        require_once __DIR__ . '/autoload.php';
        \DracoInsomnis\Server\Guard::run();
    } catch (\Throwable $e) {
        error_log('Draco Insomnis Server: ' . get_class($e) . ': ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    }
})();
