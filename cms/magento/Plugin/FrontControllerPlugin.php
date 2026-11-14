<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Plugin;

use DracoInsomnis\Magento\Model\Guard;
use Magento\Customer\Model\Session as CustomerSession;
use Magento\Framework\App\Area;
use Magento\Framework\App\FrontControllerInterface;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\App\State;
use Psr\Log\LoggerInterface;

/**
 * The first point of every storefront, REST and GraphQL request, before the full page cache (this
 * plugin is the outermost one). The admin panel is never inspected.
 */
class FrontControllerPlugin
{
    public function __construct(
        private Guard $guard,
        private State $state,
        private CustomerSession $customers,
        private LoggerInterface $logger
    ) {
    }

    /** @return mixed */
    public function aroundDispatch(FrontControllerInterface $subject, callable $proceed, RequestInterface $request)
    {
        if (!$request instanceof HttpRequest) {
            return $proceed($request);
        }
        try {
            $area = $this->state->getAreaCode();
            if ($area === Area::AREA_ADMINHTML) {
                return $proceed($request);
            }
            $answer = $this->guard->check($request, $this->isPage($request, $area) && !$this->customers->isLoggedIn());
        } catch (\Throwable $e) {
            // If Draco itself fails, the shop keeps working.
            $this->logger->warning('Draco Insomnis: ' . $e->getMessage());
            $answer = null;
        }

        return $answer ?? $proceed($request);
    }

    /** Only pages a person reads count for the pace limit: API calls and AJAX are not scraped pages. */
    private function isPage(HttpRequest $request, string $area): bool
    {
        if ($area !== Area::AREA_FRONTEND || !in_array($request->getMethod(), ['GET', 'HEAD'], true) || $request->isAjax()) {
            return false;
        }
        $accept = strtolower((string) $request->getHeader('Accept'));

        return $accept === '' || str_contains($accept, 'text/html');
    }
}
