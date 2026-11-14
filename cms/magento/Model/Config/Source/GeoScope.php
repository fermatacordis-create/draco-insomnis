<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;

final class GeoScope implements OptionSourceInterface
{
    public function toOptionArray(): array
    {
        return [
            ['value' => 'sensitive', 'label' => __('Login, sign-up and anything posted')],
            ['value' => 'site', 'label' => __('The whole shop')],
        ];
    }
}
