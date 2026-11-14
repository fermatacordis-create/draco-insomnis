<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Console;

use DracoInsomnis\Core\Summary;
use DracoInsomnis\Magento\Model\Settings;
use DracoInsomnis\Magento\Model\Store;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/** Settings, blocked addresses and the last suspicious attempts. */
class StatusCommand extends Command
{
    public function __construct(private Store $store, private Settings $settings)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('draco:status')
            ->setDescription('Draco Insomnis: settings, blocked addresses and the last suspicious attempts')
            ->addOption('limit', null, InputOption::VALUE_REQUIRED, 'How many attempts to show', '20');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('<info>Draco Insomnis</info> — ab insomni custodita dracone');
        $proxy = $this->settings->setting('proxy_header');
        (new Table($output))->setHeaders(['Part', 'Mode'])->setRows([
            ['Sign-up shield', $this->settings->shield() ? 'on' : 'off'],
            ['Firewall', $this->settings->mode('firewall')],
            ['Anti-copy pace limit', $this->settings->mode('anticopy') . ' (' . ((int) $this->settings->setting('anticopy_rate_ip') ?: 120) . '/min per address)'],
            ['Countries', $this->settings->setting('geo_mode') ?: 'off'],
            ['Visitor address', $proxy !== '' ? $proxy : 'connection address'],
        ])->render();

        $sum = Summary::waf($this->store->wafRows(7 * 86400));
        $output->writeln('<info>Firewall: last 7 days</info> — ' . $sum['total'] . ' attacks seen, ' . $sum['blocked'] . ' blocked');
        foreach (['What' => $sum['rules'], 'Busiest addresses' => $sum['ips']] as $title => $counts) {
            if ($counts !== []) {
                $output->writeln('  ' . $title . ': ' . implode(' · ', array_map(static fn ($k, $n): string => str_replace('waf_', '', (string) $k) . ': ' . $n, array_keys($counts), $counts)));
            }
        }
        $pending = count(array_filter($this->store->reviews(50), static fn (array $r): bool => $r['verdict'] === 'pending'));
        if ($pending > 0) {
            $output->writeln("<comment>$pending review request(s) waiting: bin/magento draco:reviews</comment>");
        }

        $blocks = $this->store->activeBlocks();
        $output->writeln('<info>Blocked addresses</info> (' . count($blocks) . ')');
        if ($blocks !== []) {
            (new Table($output))->setHeaders(['ID', 'Address or e-mail', 'Kind', 'Reason', 'Until (UTC)'])
                ->setRows(array_map(static fn (array $b): array => [$b['id'], $b['value'], $b['kind'], $b['reason'], $b['until_at']], $blocks))->render();
        }

        $events = $this->store->recent(max(1, (int) $input->getOption('limit')));
        $output->writeln('<info>Last suspicious attempts</info> (kept 90 days; draco:evidence <ip> for the CSV)');
        if ($events !== []) {
            (new Table($output))->setHeaders(['Date (UTC)', 'Address', 'Where', 'Verdict', 'Signs'])
                ->setRows(array_map(static fn (array $e): array => [$e['created_at'], $e['ip'], $e['endpoint'], $e['verdict'], $e['reasons']], $events))->render();
        }

        return Command::SUCCESS;
    }
}
