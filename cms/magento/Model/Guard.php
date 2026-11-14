<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Gatekeeper;
use DracoInsomnis\Core\Review;
use DracoInsomnis\Core\TestProbe;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\Controller\Result\Raw;
use Magento\Framework\Controller\Result\RawFactory;

/** Firewall, country filter and pace limit for one request: the answer that stops it, or null. */
class Guard
{
    /**
     * POST is always sensitive; these are the login, sign-up and password paths, in the storefront,
     * the REST API and GraphQL (store codes in the address do not matter: they are path endings).
     */
    public const SENSITIVE = [
        '/customer/account/login', '/customer/account/loginPost', '/customer/account/loginpost',
        '/customer/account/create', '/customer/account/createpost', '/customer/account/createPost',
        '/customer/account/forgotpassword', '/customer/account/forgotpasswordpost', '/customer/account/forgotPasswordPost',
        '/V1/customers', '/V1/integration/customer/token', '/V1/customers/password', '/graphql',
    ];

    /** The endings with and without the trailing slash Magento adds to its addresses. @return list<string> */
    public static function sensitive(): array
    {
        return array_merge(self::SENSITIVE, array_map(static fn (string $e): string => $e . '/', self::SENSITIVE));
    }

    public function __construct(
        private MagentoHost $host,
        private Settings $settings,
        private RawFactory $results
    ) {
    }

    /** @param bool $pagesCount The request is a page a person reads, from someone not logged in. */
    public function check(HttpRequest $http, bool $pagesCount): ?Raw
    {
        if ($this->excepted($http)) {
            return null;
        }
        $waf = $this->settings->mode('firewall');
        $request = MagentoHost::request($http);
        $probe = TestProbe::answer($this->host, (string) $http->getHeader(TestProbe::HEADER), $waf, time());
        if ($probe !== null) {
            return $this->response($probe['status'], '', [TestProbe::RESULT => $probe['result'], 'Cache-Control' => 'no-store']);
        }
        $post = (array) $http->getPost()->toArray();
        if (Review::isRequest($request, $post)) {
            (new Review($this->host))->accept($request, $post, time());
            $this->host->translate();

            return $this->page((string) __('Request sent'), (string) __('Thank you. The owner of the shop will look at it and, if it was a mistake, let you through.'), 'review', '', 200);
        }
        $answer = (new Gatekeeper($this->host))->decide($request, $waf, $this->settings->mode('anticopy'), self::sensitive(), $pagesCount);
        if ($answer === null) {
            return null;
        }
        if ($answer['status'] === 429) {
            return $this->response(429, 'Too many requests. Please wait a minute.', [
                'Retry-After' => (string) max(1, $answer['retry']),
                'Content-Type' => 'text/plain; charset=UTF-8',
                'Cache-Control' => 'no-store',
                'X-Robots-Tag' => 'noindex',
            ]);
        }
        // No details for the attacker: what matched stays in the log.
        $this->host->translate();
        $form = (new Review($this->host))->form($request, $answer['why'], time(), [
            'email' => (string) __('Your e-mail'),
            'message' => (string) __('What were you doing?'),
            'button' => (string) __('Ask for a review'),
        ]);

        return $this->page(
            (string) __('Request blocked'),
            (string) __('This request was stopped for security reasons. If you think this is a mistake, tell the owner of the shop what you were doing:'),
            $answer['why'],
            $form,
            403
        );
    }

    private function excepted(HttpRequest $http): bool
    {
        $path = trim((string) parse_url((string) $http->getRequestUri(), PHP_URL_PATH), '/');
        foreach ($this->settings->except() as $prefix) {
            if ($path === $prefix || str_starts_with($path, $prefix . '/')) {
                return true;
            }
        }

        return false;
    }

    private function page(string $title, string $text, string $why, string $form, int $status): Raw
    {
        return $this->response($status, Firewall::page($title, $text, $why, $form), [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }

    /**
     * A controller result, so Magento renders it into its own response object (storefront, REST and
     * GraphQL alike) and keeps the status code.
     *
     * @param array<string, string> $headers
     */
    private function response(int $status, string $body, array $headers): Raw
    {
        $result = $this->results->create();
        $result->setHttpResponseCode($status);
        foreach ($headers as $name => $value) {
            $result->setHeader($name, $value, true);
        }
        $result->setContents($body);

        return $result;
    }
}
