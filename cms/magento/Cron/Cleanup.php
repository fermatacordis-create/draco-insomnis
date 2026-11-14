<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Cron;

use DracoInsomnis\Core\GeoUpdate;
use DracoInsomnis\Magento\Model\Settings;
use DracoInsomnis\Magento\Model\Store;

/** Daily: evidence older than 90 days and finished blocks go; the country list is refreshed monthly. */
class Cleanup
{
    public function __construct(private Store $store, private Settings $settings)
    {
    }

    /** @return array{removed: int, geo: string} geo: '' (nothing to do), 'updated' or the error. */
    public function execute(): array
    {
        $removed = $this->store->cleanup();
        $geo = '';
        $file = $this->settings->setting('geo_file');
        if (in_array($this->settings->setting('geo_mode'), ['block', 'allow'], true) && GeoUpdate::stale($file, time())) {
            if (!is_dir(dirname($file))) {
                @mkdir(dirname($file), 0775, true);
            }
            $error = GeoUpdate::update($file);
            $geo = $error === '' ? 'updated' : $error;
        }

        return ['removed' => $removed, 'geo' => $geo];
    }
}
