<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * One visitor request, as the CMS adapter read it. Plain values only, so the engines can be tested
 * without a CMS.
 */
final class Request
{
    /**
     * @param string $path URL path, decoded.
     * @param string $query Query string, decoded.
     * @param list<string> $params Decoded GET and POST values (and keys), for the firewall only.
     * @param array<string, string> $post Sanitised POST text fields, by name.
     * @param string $userAgent Sanitised, for scoring and logs.
     * @param string $rawUserAgent As sent, for the firewall only.
     */
    public function __construct(
        public string $method = 'GET',
        public string $path = '/',
        public string $query = '',
        public array $params = [],
        public array $post = [],
        public string $userAgent = '',
        public string $rawUserAgent = '',
        public string $remoteAddr = '0.0.0.0',
        public string $cfConnectingIp = '',
        public string $forwardedFor = '',
        public string $referer = '',
    ) {
    }

    public function field(string $name): string
    {
        return $this->post[$name] ?? '';
    }

    /**
     * Cloudflare's published ranges (https://www.cloudflare.com/ips/). A CF-Connecting-IP header is only
     * believed when the connection comes from one of them, or from a proxy the administrator listed.
     */
    public const CLOUDFLARE = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
        '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
        '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
        '2a06:98c0::/29', '2c0f:f248::/32',
    ];

    /**
     * The proxies trusted when the administrator listed none: the machine itself and networks that
     * cannot be reached from the internet (private, carrier-grade NAT and link-local), where a
     * hosting's own front servers live.
     */
    public const LOCAL_PROXIES = [
        '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16',
        '::1/128', 'fc00::/7', 'fe80::/10',
    ];

    /** The visitor's address with the site's settings ("proxy_header", "trusted_proxies"). */
    public function via(Host $host): string
    {
        return $this->ip($host->setting('proxy_header'), $host->setting('trusted_proxies'));
    }

    /**
     * The visitor's address: the connection's own, unless the administrator chose a proxy header
     * ('cf' = Cloudflare, 'xff' = X-Forwarded-For) AND the connection comes from a trusted proxy.
     * Anyone can send these headers, so a header that does not come through a trusted proxy is ignored.
     * X-Forwarded-For is read from the right: each proxy adds the address it saw at the end, so the
     * first address that is not a trusted proxy is the visitor; whatever is on its left was written
     * by the visitor.
     *
     * @param string $trustedProxies One CIDR or address per line; empty = LOCAL_PROXIES.
     */
    public function ip(string $proxyMode, string $trustedProxies = ''): string
    {
        $remote = $this->remote();
        if (!$this->fromTrustedProxy($proxyMode, $trustedProxies)) {
            return $remote;
        }
        if ($proxyMode === 'cf') {
            $ip = filter_var(trim($this->cfConnectingIp), FILTER_VALIDATE_IP);

            return is_string($ip) ? $ip : $remote;
        }
        $proxies = self::proxies($trustedProxies);
        $hops = array_reverse(array_map('trim', explode(',', $this->forwardedFor)));
        foreach ($hops as $hop) {
            $ip = filter_var($hop, FILTER_VALIDATE_IP);
            if (!is_string($ip)) {
                return $remote;
            }
            if (!NetList::contains($proxies, $ip)) {
                return $ip;
            }
            $remote = $ip;
        }

        return $remote;
    }

    /** Whether the chosen proxy header may be read at all: the connection comes from a trusted proxy. */
    public function fromTrustedProxy(string $proxyMode, string $trustedProxies = ''): bool
    {
        $remote = $this->remote();
        if ($proxyMode === 'cf') {
            return $this->cfConnectingIp !== '' && (NetList::contains(self::CLOUDFLARE, $remote) || NetList::contains(NetList::parse($trustedProxies), $remote));
        }
        if ($proxyMode === 'xff') {
            return trim($this->forwardedFor) !== '' && NetList::contains(self::proxies($trustedProxies), $remote);
        }

        return false;
    }

    /**
     * True when a proxy header is chosen and this request carries it, but the connection does not come
     * from a trusted proxy: the header was ignored. The settings screens show it as a warning.
     */
    public function proxyHeaderIgnored(string $proxyMode, string $trustedProxies = ''): bool
    {
        $sent = ($proxyMode === 'cf' && $this->cfConnectingIp !== '') || ($proxyMode === 'xff' && trim($this->forwardedFor) !== '');

        return $sent && !$this->fromTrustedProxy($proxyMode, $trustedProxies);
    }

    /** @return list<string> */
    private static function proxies(string $trustedProxies): array
    {
        $listed = NetList::parse($trustedProxies);

        return $listed !== [] ? $listed : self::LOCAL_PROXIES;
    }

    public function remote(): string
    {
        $remote = filter_var($this->remoteAddr, FILTER_VALIDATE_IP);

        return is_string($remote) ? $remote : '0.0.0.0';
    }
}
