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
     * The visitor's address: the connection's own, unless the administrator chose to trust a proxy
     * header ('cf' = Cloudflare, 'xff' = first X-Forwarded-For entry). A forged header is ignored.
     */
    public function ip(string $proxyMode): string
    {
        $candidate = '';
        if ($proxyMode === 'cf') {
            $candidate = $this->cfConnectingIp;
        } elseif ($proxyMode === 'xff') {
            $candidate = explode(',', $this->forwardedFor)[0];
        }
        $ip = filter_var(trim($candidate), FILTER_VALIDATE_IP);
        if (is_string($ip)) {
            return $ip;
        }
        $remote = filter_var($this->remoteAddr, FILTER_VALIDATE_IP);

        return is_string($remote) ? $remote : '0.0.0.0';
    }

    public function remote(): string
    {
        $remote = filter_var($this->remoteAddr, FILTER_VALIDATE_IP);

        return is_string($remote) ? $remote : '0.0.0.0';
    }
}
