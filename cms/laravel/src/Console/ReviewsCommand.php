<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Console;

use DracoInsomnis\Laravel\Store;
use Illuminate\Console\Command;

/** The review requests sent from the block page, and the decision on one of them. */
final class ReviewsCommand extends Command
{
    protected $signature = 'draco:reviews
        {id? : ID of the request to decide}
        {--approve= : Let the address through for 1, 7, 30 or 0 (forever) days}
        {--deny : Leave it as it is}
        {--attacker : Block the address for 90 days}';

    protected $description = 'Draco Insomnis: requests to review a firewall block, and the decision on one';

    public function handle(): int
    {
        $id = $this->argument('id');
        if ($id === null) {
            $rows = Store::reviews(50);
            $this->line('<info>Review requests</info> (Draco never writes to them: answer from your own mail if you want)');
            if ($rows === []) {
                $this->line('No requests.');

                return self::SUCCESS;
            }
            $this->table(['ID', 'Date (UTC)', 'Address', 'E-mail', 'Message', 'State'], array_map(static function ($r): array {
                $f = json_decode((string) $r->fields, true);
                $f = is_array($f) ? $f : [];

                return [$r->id, $r->created_at, $r->ip, (string) ($f['email'] ?? ''), mb_strimwidth((string) ($f['referer'] ?? ''), 0, 60, '…'), $r->verdict];
            }, $rows));
            $this->line('Decide: draco:reviews <id> --approve=1|7|30|0, --deny or --attacker');

            return self::SUCCESS;
        }
        $row = Store::review((int) $id);
        if ($row === null) {
            $this->error('No review request with that ID.');

            return self::FAILURE;
        }
        $f = json_decode((string) $row->fields, true);
        $reason = 'Review: ' . (is_array($f) ? (string) ($f['email'] ?? '') : '');
        if ($this->option('approve') !== null) {
            $done = Store::allow((string) $row->ip, (int) $this->option('approve'), $reason);
            $verdict = 'approved';
        } elseif ($this->option('attacker')) {
            $done = (new Store())->block('ip', (string) $row->ip, 90, $reason, true);
            $verdict = 'attacker';
        } elseif ($this->option('deny')) {
            $done = true;
            $verdict = 'denied';
        } else {
            $this->error('Say what to do: --approve=1|7|30|0, --deny or --attacker.');

            return self::FAILURE;
        }
        if (!$done) {
            $this->error('It could not be done for that address.');

            return self::FAILURE;
        }
        Store::setVerdict((int) $row->id, $verdict);
        $this->info('Done.');

        return self::SUCCESS;
    }
}
