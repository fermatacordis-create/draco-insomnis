<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Console;

use DracoInsomnis\Magento\Cron\Cleanup;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** What the daily cron job does, now. */
class CleanupCommand extends Command
{
    public function __construct(private Cleanup $cleanup)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('draco:cleanup')->setDescription('Draco Insomnis: remove old evidence and finished blocks (cron does it daily)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $done = $this->cleanup->execute();
        $output->writeln($done['removed'] . ' rows removed.');
        if ($done['geo'] === 'updated') {
            $output->writeln('Country list updated.');
        } elseif ($done['geo'] !== '') {
            $output->writeln('<comment>Country list not updated: ' . $done['geo'] . '</comment>');
        }

        return Command::SUCCESS;
    }
}
