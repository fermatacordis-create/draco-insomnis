<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Console;

use DracoInsomnis\Laravel\Store;
use Illuminate\Console\Command;

/** Everything one address did, as CSV, ready to attach to an abuse report to its network provider. */
final class EvidenceCommand extends Command
{
    protected $signature = 'draco:evidence {ip : The address} {--output= : Write to this file instead of the screen}';

    protected $description = 'Draco Insomnis: the evidence of one address as CSV, for an abuse report';

    public function handle(): int
    {
        $ip = (string) $this->argument('ip');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $this->error('Not an IP address.');

            return self::FAILURE;
        }
        $out = fopen('php://temp', 'w+');
        fputcsv($out, ['created_at_utc', 'ip', 'remote_addr', 'endpoint', 'verdict', 'score', 'reasons', 'user_agent', 'fields'], ',', '"', '\\');
        $rows = Store::byIp($ip);
        foreach ($rows as $row) {
            fputcsv($out, [$row->created_at, $row->ip, $row->remote_addr, $row->endpoint, $row->verdict, $row->score, $row->reasons, $row->user_agent, $row->fields], ',', '"', '\\');
        }
        rewind($out);
        $csv = (string) stream_get_contents($out);
        fclose($out);
        $path = $this->option('output');
        if (is_string($path) && $path !== '') {
            file_put_contents($path, $csv);
            $this->info(count($rows) . ' rows written to ' . $path);
        } else {
            $this->output->write($csv);
        }

        return self::SUCCESS;
    }
}
