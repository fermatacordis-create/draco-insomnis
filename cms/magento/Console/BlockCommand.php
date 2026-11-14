<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Console;

use DracoInsomnis\Magento\Model\Store;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/** Blocks an address, a network or an e-mail by hand, or lifts a block. */
class BlockCommand extends Command
{
    public function __construct(private Store $store)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('draco:block')
            ->setDescription('Draco Insomnis: block an address, network or e-mail, or lift a block')
            ->addArgument('value', InputArgument::OPTIONAL, 'IP address, CIDR network or e-mail to block')
            ->addOption('days', null, InputOption::VALUE_REQUIRED, '7, 15, 30, 90 or 0 (forever)', '7')
            ->addOption('reason', null, InputOption::VALUE_REQUIRED, 'Why', 'Manual')
            ->addOption('unblock', null, InputOption::VALUE_REQUIRED, 'ID of a block to lift (see draco:status)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $unblock = $input->getOption('unblock');
        if ($unblock !== null) {
            if (!$this->store->unblock((int) $unblock)) {
                $output->writeln('<error>No block with that ID.</error>');

                return Command::FAILURE;
            }
            $output->writeln('Block lifted.');

            return Command::SUCCESS;
        }
        $value = trim((string) $input->getArgument('value'));
        $kind = filter_var($value, FILTER_VALIDATE_IP) !== false || str_contains($value, '/') ? 'ip' : 'email';
        $days = (int) $input->getOption('days');
        if (!$this->store->block($kind, $value, $days, (string) $input->getOption('reason'))) {
            $output->writeln('<error>Not blocked: invalid value or days, or it belongs to someone who is never blocked.</error>');

            return Command::FAILURE;
        }
        $output->writeln("Blocked $value " . ($days === 0 ? 'forever.' : "for $days days."));

        return Command::SUCCESS;
    }
}
