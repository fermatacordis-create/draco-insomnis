<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Block;

use DracoInsomnis\Core\Shield;
use DracoInsomnis\Magento\Model\MagentoHost;
use DracoInsomnis\Magento\Model\Settings;
use Magento\Framework\View\Element\AbstractBlock;
use Magento\Framework\View\Element\Context;

/**
 * The page stamp and the trap field inside the sign-up form. The block is not cacheable: a stamp
 * from the full page cache would be old for everyone.
 */
class ShieldFields extends AbstractBlock
{
    public function __construct(Context $context, private MagentoHost $host, private Settings $settings, array $data = [])
    {
        parent::__construct($context, $data);
    }

    protected function _toHtml(): string
    {
        return $this->settings->shield() ? (new Shield($this->host))->fieldsHtml(time()) : '';
    }
}
