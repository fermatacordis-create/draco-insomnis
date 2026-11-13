<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Console;

use DracoInsomnis\Laravel\Store;
use Illuminate\Console\Command;

/** Daily: removes evidence older than 90 days and finished blocks. Scheduled by the package. */
final class CleanupCommand extends Command
{
    protected $signature = 'draco:cleanup';

    protected $description = 'Draco Insomnis: remove old evidence and finished blocks';

    public function handle(): int
    {
        $this->info(Store::cleanup() . ' rows removed.');
        $host = new \DracoInsomnis\Laravel\LaravelHost();
        if (in_array($host->setting('geo_mode'), ['block', 'allow'], true) && \DracoInsomnis\Core\GeoUpdate::stale($host->setting('geo_file'), time())) {
            $error = \DracoInsomnis\Core\GeoUpdate::update($host->setting('geo_file'));
            $error === '' ? $this->info('Country list updated.') : $this->warn('Country list not updated: ' . $error);
        }

        return self::SUCCESS;
    }
}
