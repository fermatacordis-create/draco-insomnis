<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;

final class ProxyHeader implements OptionSourceInterface
{
    public function toOptionArray(): array
    {
        return [
            ['value' => '', 'label' => __('The connection address (recommended)')],
            ['value' => 'cf', 'label' => __('Cloudflare (CF-Connecting-IP)')],
            ['value' => 'xff', 'label' => __('Another proxy (X-Forwarded-For)')],
        ];
    }
}
