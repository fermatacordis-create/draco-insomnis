<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;

final class GeoAction implements OptionSourceInterface
{
    public function toOptionArray(): array
    {
        return [
            ['value' => 'log', 'label' => __('Log only (stop nothing)')],
            ['value' => 'block', 'label' => __('Block')],
        ];
    }
}
