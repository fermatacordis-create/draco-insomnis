<?php
/**
 * @author    Notorius Vision
 * @license   GPL-2.0-or-later
 */

declare(strict_types=1);

namespace DracoInsomnis\Presta;

use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\Host;
use DracoInsomnis\Core\Request;
use DracoInsomnis\Core\WafRules;

if (!defined('_PS_VERSION_')) {
    exit;
}

/** The engines in src/Core, running in PrestaShop. */
final class PsHost implements Host
{
    private static ?self $instance = null;

    public static function get(): self
    {
        return self::$instance ??= new self();
    }

    /** The current request, read fresh every time. */
    public static function request(): Request
    {
        $server = static fn (string $key): string => isset($_SERVER[$key]) && is_string($_SERVER[$key]) ? $_SERVER[$key] : '';
        $method = strtoupper(self::clean($server('REQUEST_METHOD')));
        $method = $method !== '' ? $method : 'GET';
        $uri = $server('REQUEST_URI');
        $post = [];
        foreach ($_POST as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $post[$name] = self::clean($value);
            }
        }

        return new Request(
            $method,
            rawurldecode((string) parse_url($uri, PHP_URL_PATH)),
            urldecode((string) parse_url($uri, PHP_URL_QUERY)),
            WafRules::flatten(array_merge($_GET, $method === 'POST' ? $_POST : [])),
            $post,
            self::clean($server('HTTP_USER_AGENT')),
            $server('HTTP_USER_AGENT'),
            self::clean($server('REMOTE_ADDR')),
            self::clean($server('HTTP_CF_CONNECTING_IP')),
            self::clean($server('HTTP_X_FORWARDED_FOR')),
            self::clean((string) filter_var($server('HTTP_REFERER'), FILTER_SANITIZE_URL)),
        );
    }

    /** One line of plain text: no tags, no control characters. */
    public static function clean(string $value): string
    {
        return trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', strip_tags($value)));
    }

    public function secret(): string
    {
        return Settings::secret();
    }

    public function setting(string $name): string
    {
        return Settings::get('DRACO_' . strtoupper($name));
    }

    public function adminIps(): array
    {
        return Settings::adminIps();
    }

    public function bump(string $key, int $ttl): int
    {
        return Store::bump($key, $ttl);
    }

    public function recall(string $key): ?string
    {
        return Store::recall($key);
    }

    public function remember(string $key, string $value, int $ttl): void
    {
        Store::remember($key, $value, $ttl);
    }

    /**
     * Site code can change a value through the actionDracoInsomnisFilter hook, which receives the
     * name, the value by reference and the arguments.
     */
    public function filter(string $name, $value, ...$args)
    {
        \Hook::exec('actionDracoInsomnisFilter', ['name' => $name, 'value' => &$value, 'args' => $args]);

        return $value;
    }

    public function text(string $id, int $number): string
    {
        $translator = \Context::getContext()->getTranslator();
        if ($id === 'waf_block') {
            return sprintf($translator->trans('Firewall: %d attacks in 10 minutes', [], 'Modules.Dracoinsomnis.Admin'), $number);
        }

        return sprintf($translator->trans('Automatic: %d bot attempts in 24 h', [], 'Modules.Dracoinsomnis.Admin'), $number);
    }

    public function events(): EventStore
    {
        return new Store();
    }
}
