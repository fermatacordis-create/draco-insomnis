<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Console;

use DracoInsomnis\Magento\Model\Store;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/** The review requests sent from the block page, and the decision on one of them. */
class ReviewsCommand extends Command
{
    public function __construct(private Store $store)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('draco:reviews')
            ->setDescription('Draco Insomnis: requests to review a firewall block, and the decision on one')
            ->addArgument('id', InputArgument::OPTIONAL, 'ID of the request to decide')
            ->addOption('approve', null, InputOption::VALUE_REQUIRED, 'Let the address through for 1, 7, 30 or 0 (forever) days')
            ->addOption('deny', null, InputOption::VALUE_NONE, 'Leave it as it is')
            ->addOption('attacker', null, InputOption::VALUE_NONE, 'Block the address for 90 days');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $id = $input->getArgument('id');
        if ($id === null) {
            $rows = $this->store->reviews(50);
            $output->writeln('<info>Review requests</info> (Draco never writes to them: answer from your own mail if you want)');
            if ($rows === []) {
                $output->writeln('No requests.');

                return Command::SUCCESS;
            }
            (new Table($output))->setHeaders(['ID', 'Date (UTC)', 'Address', 'E-mail', 'Message', 'State'])->setRows(array_map(static function (array $r): array {
                $f = json_decode((string) $r['fields'], true);
                $f = is_array($f) ? $f : [];

                return [$r['id'], $r['created_at'], $r['ip'], (string) ($f['email'] ?? ''), mb_strimwidth((string) ($f['referer'] ?? ''), 0, 60, '…'), $r['verdict']];
            }, $rows))->render();
            $output->writeln('Decide: draco:reviews <id> --approve=1|7|30|0, --deny or --attacker');

            return Command::SUCCESS;
        }
        $row = $this->store->review((int) $id);
        if ($row === null) {
            $output->writeln('<error>No review request with that ID.</error>');

            return Command::FAILURE;
        }
        $f = json_decode((string) $row['fields'], true);
        $reason = 'Review: ' . (is_array($f) ? (string) ($f['email'] ?? '') : '');
        if ($input->getOption('approve') !== null) {
            $done = $this->store->allow((string) $row['ip'], (int) $input->getOption('approve'), $reason);
            $verdict = 'approved';
        } elseif ($input->getOption('attacker')) {
            $done = $this->store->block('ip', (string) $row['ip'], 90, $reason, true);
            $verdict = 'attacker';
        } elseif ($input->getOption('deny')) {
            $done = true;
            $verdict = 'denied';
        } else {
            $output->writeln('<error>Say what to do: --approve=1|7|30|0, --deny or --attacker.</error>');

            return Command::FAILURE;
        }
        if (!$done) {
            $output->writeln('<error>It could not be done for that address.</error>');

            return Command::FAILURE;
        }
        $this->store->setVerdict((int) $row['id'], $verdict);
        $output->writeln('Done.');

        return Command::SUCCESS;
    }
}
