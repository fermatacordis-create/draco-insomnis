<?php

/**
 * @package     Draco Insomnis for Joomla
 * @copyright   (C) 2026 Notorius Vision
 * @license     GNU General Public License version 2 or later
 */

namespace Notorius\Plugin\System\DracoInsomnis;

use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\Host;
use DracoInsomnis\Core\Request;
use DracoInsomnis\Core\WafRules;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\Registry\Registry;

\defined('_JEXEC') or die;

/** The engines in lib/Core, running in Joomla. Settings are the plugin's parameters. */
final class JoomlaHost implements Host
{
    public const MODES = ['off', 'log', 'block'];

    public function __construct(private Registry $params)
    {
    }

    public function mode(string $name): string
    {
        $mode = (string) $this->params->get($name, 'off');

        return \in_array($mode, self::MODES, true) ? $mode : 'off';
    }

    public function shieldOn(): bool
    {
        return (int) $this->params->get('shield', 0) === 1;
    }

    /** One visitor request as plain values. */
    public static function request(): Request
    {
        $server = static fn (string $key): string => isset($_SERVER[$key]) && \is_string($_SERVER[$key]) ? $_SERVER[$key] : '';
        $method = strtoupper(self::clean($server('REQUEST_METHOD')));
        $method = $method !== '' ? $method : 'GET';
        $uri = $server('REQUEST_URI');
        $post = [];
        foreach ($_POST as $name => $value) {
            if (\is_string($name) && \is_string($value)) {
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

    public static function clean(string $value): string
    {
        return trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', strip_tags($value)));
    }

    /** Derived from the site's own secret in configuration.php: nothing extra to store. */
    public function secret(): string
    {
        return hash('sha256', 'draco-insomnis|' . (string) Factory::getApplication()->get('secret'));
    }

    public function setting(string $name): string
    {
        $value = $this->params->get($name, '');

        return \is_scalar($value) ? (string) $value : '';
    }

    public function adminIps(): array
    {
        $list = json_decode((string) Store::recall('draco_admin_ips'), true);

        return \is_array($list) ? array_values(array_filter($list, 'is_string')) : [];
    }

    /** The last ten addresses administrators worked from: never blocked, never limited. */
    public function rememberAdminIp(string $ip): void
    {
        $list = $this->adminIps();
        if (($list[0] ?? null) === $ip) {
            return;
        }
        $list = \array_slice(array_values(array_unique(array_merge([$ip], $list))), 0, 10);
        Store::remember('draco_admin_ips', (string) json_encode($list), 10 * 365 * 86400);
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

    /** Other plugins change values through the onDracoInsomnisFilter event (argument "value"). */
    public function filter(string $name, $value, ...$args)
    {
        $event = new \Joomla\Event\Event('onDracoInsomnisFilter', ['name' => $name, 'value' => $value, 'args' => $args]);
        Factory::getApplication()->getDispatcher()->dispatch('onDracoInsomnisFilter', $event);

        return $event->getArgument('value', $value);
    }

    public function text(string $id, int $number): string
    {
        return Text::sprintf($id === 'waf_block' ? 'PLG_SYSTEM_DRACOINSOMNIS_WAF_BLOCK' : 'PLG_SYSTEM_DRACOINSOMNIS_AUTO_BLOCK', $number);
    }

    public function events(): EventStore
    {
        return new Store();
    }
}
