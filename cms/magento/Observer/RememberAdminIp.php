<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Observer;

use DracoInsomnis\Magento\Model\MagentoHost;
use DracoInsomnis\Magento\Model\Store;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;

/** The address an administrator logs in from is never blocked or limited (the last ten are kept). */
class RememberAdminIp implements ObserverInterface
{
    public function __construct(private HttpRequest $request, private MagentoHost $host, private Store $store)
    {
    }

    public function execute(Observer $observer): void
    {
        try {
            $this->store->rememberAdminIp(MagentoHost::request($this->request)->via($this->host));
        } catch (\Throwable $e) {
            // Logging in always works.
        }
    }
}
