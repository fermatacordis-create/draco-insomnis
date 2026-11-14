<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\Filesystem\DirectoryList;

/** The module's settings: Stores > Configuration > Advanced > Draco Insomnis, and two lines in env.php. */
class Settings
{
    public const PATH = 'draco_insomnis/';
    public const MODES = ['off', 'log', 'block'];

    /** The engines' short names and where Magento keeps them. */
    private const MAP = [
        'proxy_header' => 'network/proxy_header',
        'trusted_proxies' => 'network/trusted_proxies',
        'hosting_nets' => 'network/hosting_nets',
        'anticopy_rate_ip' => 'anticopy/rate_ip',
        'anticopy_rate_net' => 'anticopy/rate_net',
        'geo_mode' => 'country/mode',
        'geo_countries' => 'country/countries',
        'geo_scope' => 'country/scope',
        'geo_action' => 'country/action',
        'headers' => 'headers/enabled',
        'hsts' => 'headers/hsts',
        'pwd_min' => 'passwords/min_length',
        'pwd_breached' => 'passwords/breached',
    ];

    public function __construct(
        private ScopeConfigInterface $config,
        private DeploymentConfig $deployment,
        private DirectoryList $dirs
    ) {
    }

    public function value(string $path): string
    {
        $value = $this->config->getValue(self::PATH . $path);

        return is_scalar($value) ? trim((string) $value) : '';
    }

    /** A setting by the engines' name, or '' when unset. */
    public function setting(string $name): string
    {
        if ($name === 'geo_file') {
            // Public data, refreshed monthly; in var/ so module updates keep it.
            return $this->dirs->getPath(DirectoryList::VAR_DIR) . '/draco/draco-geo.bin';
        }

        return isset(self::MAP[$name]) ? $this->value(self::MAP[$name]) : '';
    }

    /** off | log | block. The firewall also turns off with 'draco_waf_off' => true in env.php. */
    public function mode(string $part): string
    {
        if ($part === 'firewall' && $this->deployment->get('draco_waf_off')) {
            return 'off';
        }
        $mode = $this->value($part . '/mode');

        return in_array($mode, self::MODES, true) ? $mode : 'off';
    }

    public function shield(): bool
    {
        return $this->value('shield/enabled') === '1';
    }

    /** Derived from the shop's encryption key: nothing extra to store, and different in every shop. */
    public function secret(): string
    {
        return hash('sha256', 'draco-insomnis|' . (string) $this->deployment->get('crypt/key'));
    }

    /** Start of paths never inspected (webhooks, health checks). @return list<string> */
    public function except(): array
    {
        $lines = preg_split('/[\r\n,]+/', $this->value('network/except')) ?: [];

        return array_values(array_filter(array_map(static fn (string $p): string => trim($p, " \t/"), $lines), static fn (string $p): bool => $p !== ''));
    }

    public function notifyEmail(): string
    {
        $to = $this->value('notify/email');
        if ($to === '') {
            $to = (string) $this->config->getValue('trans_email/ident_general/email');
        }

        return filter_var($to, FILTER_VALIDATE_EMAIL) !== false ? $to : '';
    }

    public function shopName(): string
    {
        $name = (string) $this->config->getValue('general/store_information/name');

        return $name !== '' ? $name : (string) $this->config->getValue('web/unsecure/base_url');
    }

    public function baseUrl(): string
    {
        return (string) $this->config->getValue('web/secure/base_url') ?: (string) $this->config->getValue('web/unsecure/base_url');
    }
}
