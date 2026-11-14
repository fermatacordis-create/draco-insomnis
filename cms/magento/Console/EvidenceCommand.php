<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Console;

use DracoInsomnis\Magento\Model\Store;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/** Everything one address did, as CSV, ready to attach to an abuse report to its network provider. */
class EvidenceCommand extends Command
{
    private const COLUMNS = ['created_at', 'ip', 'remote_addr', 'endpoint', 'verdict', 'score', 'reasons', 'user_agent', 'fields'];

    public function __construct(private Store $store)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('draco:evidence')
            ->setDescription('Draco Insomnis: the evidence of one address as CSV, for an abuse report')
            ->addArgument('ip', InputArgument::REQUIRED, 'The address')
            ->addOption('output', null, InputOption::VALUE_REQUIRED, 'Write to this file instead of the screen');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $ip = (string) $input->getArgument('ip');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $output->writeln('<error>Not an IP address.</error>');

            return Command::FAILURE;
        }
        $out = fopen('php://temp', 'w+');
        $header = self::COLUMNS;
        $header[0] = 'created_at_utc';
        fputcsv($out, $header, ',', '"', '\\');
        $rows = $this->store->byIp($ip);
        foreach ($rows as $row) {
            fputcsv($out, array_map(static fn (string $c): string => (string) ($row[$c] ?? ''), self::COLUMNS), ',', '"', '\\');
        }
        rewind($out);
        $csv = (string) stream_get_contents($out);
        fclose($out);
        $path = (string) $input->getOption('output');
        if ($path !== '') {
            file_put_contents($path, $csv);
            $output->writeln(count($rows) . ' rows written to ' . $path);
        } else {
            $output->write($csv, false, OutputInterface::OUTPUT_RAW);
        }

        return Command::SUCCESS;
    }
}
