<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Console;

use DracoInsomnis\Laravel\Store;
use Illuminate\Console\Command;

/** Blocks an address or e-mail by hand, or lifts a block. */
final class BlockCommand extends Command
{
    protected $signature = 'draco:block {value? : IP address or e-mail to block}
        {--days=7 : 7, 15, 30 or 90}
        {--reason= : Why}
        {--unblock= : ID of a block to lift (see draco:status)}';

    protected $description = 'Draco Insomnis: block an address or e-mail, or lift a block';

    public function handle(): int
    {
        $unblock = $this->option('unblock');
        if ($unblock !== null) {
            if (!Store::unblock((int) $unblock)) {
                $this->error('No block with that ID.');

                return self::FAILURE;
            }
            $this->info('Block lifted.');

            return self::SUCCESS;
        }
        $value = (string) $this->argument('value');
        $kind = filter_var($value, FILTER_VALIDATE_IP) !== false ? 'ip' : 'email';
        $reason = (string) ($this->option('reason') ?: 'Manual');
        if (!(new Store())->block($kind, $value, (int) $this->option('days'), $reason)) {
            $this->error('Not blocked: invalid value or days, or it belongs to someone who is never blocked.');

            return self::FAILURE;
        }
        $this->info("Blocked $value for " . (int) $this->option('days') . ' days.');

        return self::SUCCESS;
    }
}
