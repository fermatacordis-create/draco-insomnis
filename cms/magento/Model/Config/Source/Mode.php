<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;

final class Mode implements OptionSourceInterface
{
    public function toOptionArray(): array
    {
        return [
            ['value' => 'off', 'label' => __('Off')],
            ['value' => 'log', 'label' => __('Log only (stop nothing)')],
            ['value' => 'block', 'label' => __('Block')],
        ];
    }
}
