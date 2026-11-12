<?php
/**
 * @author    Notorius Vision
 * @license   GPL-2.0-or-later
 */

declare(strict_types=1);

namespace DracoInsomnis\Presta;

if (!defined('_PS_VERSION_')) {
    exit;
}

/** The module's settings, kept in PrestaShop's Configuration as DRACO_<NAME>. */
final class Settings
{
    public const SECRET = 'DRACO_SECRET';
    public const SHIELD = 'DRACO_SHIELD';
    public const WAF_MODE = 'DRACO_WAF_MODE';
    public const PACE_MODE = 'DRACO_PACE_MODE';
    public const RATE_IP = 'DRACO_ANTICOPY_RATE_IP';
    public const RATE_NET = 'DRACO_ANTICOPY_RATE_NET';
    public const PROXY = 'DRACO_PROXY_HEADER';
    public const NETS = 'DRACO_HOSTING_NETS';
    public const TRUSTED = 'DRACO_TRUSTED_PROXIES';
    public const ADMIN_IPS = 'DRACO_ADMIN_IPS';
    public const MODES = ['off', 'log', 'block'];
    public const PROXIES = ['', 'cf', 'xff'];

    private const ALL = [self::SECRET, self::SHIELD, self::WAF_MODE, self::PACE_MODE, self::RATE_IP, self::RATE_NET, self::PROXY, self::TRUSTED, self::NETS, self::ADMIN_IPS];

    public static function install(): bool
    {
        self::secret();

        // Everything starts off: the owner switches each part on, the firewall first in "log only".
        return \Configuration::updateGlobalValue(self::SHIELD, '0')
            && \Configuration::updateGlobalValue(self::WAF_MODE, 'off')
            && \Configuration::updateGlobalValue(self::PACE_MODE, 'off');
    }

    public static function uninstall(): void
    {
        foreach (self::ALL as $name) {
            \Configuration::deleteByName($name);
        }
    }

    public static function get(string $name): string
    {
        $value = \Configuration::getGlobalValue($name);

        return is_scalar($value) ? (string) $value : '';
    }

    public static function set(string $name, string $value): void
    {
        \Configuration::updateGlobalValue($name, $value);
    }

    public static function mode(string $name): string
    {
        $mode = self::get($name);

        return in_array($mode, self::MODES, true) ? $mode : 'off';
    }

    /**
     * Per-shop secret. It signs the page stamp and picks this shop's field names, so knowing the
     * module's source code does not tell a bot what to send.
     */
    public static function secret(): string
    {
        $secret = self::get(self::SECRET);
        if (strlen($secret) !== 64) {
            $secret = bin2hex(random_bytes(32));
            self::set(self::SECRET, $secret);
        }

        return $secret;
    }

    /** @return list<string> */
    public static function adminIps(): array
    {
        $list = json_decode(self::get(self::ADMIN_IPS), true);

        return is_array($list) ? array_values(array_filter($list, 'is_string')) : [];
    }

    /** The last ten addresses employees worked from. */
    public static function rememberAdminIp(\Context $context): void
    {
        if (!isset($context->employee) || !\Validate::isLoadedObject($context->employee)) {
            return;
        }
        $ip = PsHost::request()->via(PsHost::get());
        $list = self::adminIps();
        if (($list[0] ?? null) === $ip) {
            return;
        }
        self::set(self::ADMIN_IPS, (string) json_encode(array_slice(array_values(array_unique(array_merge([$ip], $list))), 0, 10)));
    }
}
