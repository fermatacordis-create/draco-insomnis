<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Observer;

use DracoInsomnis\Magento\Model\MagentoHost;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\App\Response\Http as HttpResponse;
use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;

/** Security headers on the answer, when switched on; never one the shop already sends. */
class SecurityHeaders implements ObserverInterface
{
    public function __construct(private MagentoHost $host)
    {
    }

    public function execute(Observer $observer): void
    {
        $request = $observer->getEvent()->getData('request');
        $response = $observer->getEvent()->getData('response');
        if (!$response instanceof HttpResponse) {
            return;
        }
        try {
            $https = $request instanceof HttpRequest && $request->isSecure();
            foreach (\DracoInsomnis\Core\SecurityHeaders::wanted($this->host, $https) as $name => $value) {
                if (!$response->getHeader($name)) {
                    $response->setHeader($name, $value);
                }
            }
        } catch (\Throwable $e) {
            // Headers are a bonus: never break the answer for them.
        }
    }
}
