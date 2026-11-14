<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Console;

use DracoInsomnis\Core\TestProbe;
use DracoInsomnis\Magento\Model\MagentoHost;
use DracoInsomnis\Magento\Model\Settings;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** Sends a harmless attack-shaped request to the shop and says what the firewall did. It is not logged. */
class TestCommand extends Command
{
    public function __construct(private MagentoHost $host, private Settings $settings)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('draco:test')
            ->setDescription('Draco Insomnis: test the firewall with a harmless attack-shaped request')
            ->addArgument('url', InputArgument::OPTIONAL, 'Address of the shop (default: its base URL)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $url = (string) ($input->getArgument('url') ?: $this->settings->baseUrl());
        [$rule, $mode] = array_pad(explode('|', TestProbe::run($this->host, $url, time()), 2), 2, '');
        switch (true) {
            case $rule === 'off':
                $output->writeln('<comment>The firewall is off: set it to "Log only" or "Block", then test again.</comment>');

                return Command::FAILURE;
            case $rule === 'error' || $rule === 'unseen':
                $output->writeln("<comment>The test could not reach $url from here. Check the base URL, or pass the address.</comment>");

                return Command::FAILURE;
            case $rule === 'upstream':
                $output->writeln('The test was stopped before it reached the shop, by a firewall in front. Good: two layers.');

                return Command::SUCCESS;
            case $rule === 'none':
                $output->writeln('<error>The test attack was not recognised. Please report it to Draco Insomnis.</error>');

                return Command::FAILURE;
            default:
                $output->writeln($mode === 'block'
                    ? 'Works: a database injection was recognised and blocked (403).'
                    : 'Works: a database injection was recognised. In "Log only" it is written down but not stopped; set "Block" when you are ready.');

                return Command::SUCCESS;
        }
    }
}
