<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;

final class GeoMode implements OptionSourceInterface
{
    public function toOptionArray(): array
    {
        return [
            ['value' => 'off', 'label' => __('Off')],
            ['value' => 'block', 'label' => __('Refuse the countries listed')],
            ['value' => 'allow', 'label' => __('Only allow the countries listed')],
        ];
    }
}
