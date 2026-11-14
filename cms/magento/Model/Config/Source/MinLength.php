<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;

final class MinLength implements OptionSourceInterface
{
    public function toOptionArray(): array
    {
        $options = [['value' => '0', 'label' => __('No minimum (Magento rules only)')]];
        foreach ([8, 10, 12, 14, 16] as $n) {
            $options[] = ['value' => (string) $n, 'label' => $n === 12 ? __('%1 characters · recommended', $n) : __('%1 characters', $n)];
        }

        return $options;
    }
}
