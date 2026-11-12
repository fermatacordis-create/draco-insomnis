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

        return self::SUCCESS;
    }
}
