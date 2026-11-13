<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Console;

use DracoInsomnis\Core\TestProbe;
use DracoInsomnis\Laravel\LaravelHost;
use Illuminate\Console\Command;

/** Sends a harmless attack-shaped request to the app and says what the firewall did. It is not logged. */
final class TestCommand extends Command
{
    protected $signature = 'draco:test {url? : Address of the app (default: APP_URL)}';

    protected $description = 'Draco Insomnis: test the firewall with a harmless attack-shaped request';

    public function handle(): int
    {
        $url = (string) ($this->argument('url') ?: config('app.url'));
        [$rule, $mode] = array_pad(explode('|', TestProbe::run(new LaravelHost(), $url, time()), 2), 2, '');
        switch (true) {
            case $rule === 'off':
                $this->warn('The firewall is off: set DRACO_WAF_MODE=log or block, then test again.');

                return self::FAILURE;
            case $rule === 'error' || $rule === 'unseen':
                $this->warn("The test could not reach $url from here. Check APP_URL, or pass the address.");

                return self::FAILURE;
            case $rule === 'upstream':
                $this->info('The test was stopped before it reached the app, by a firewall in front. Good: two layers.');

                return self::SUCCESS;
            case $rule === 'none':
                $this->error('The test attack was not recognised. Please report it to Draco Insomnis.');

                return self::FAILURE;
            default:
                $this->info($mode === 'block'
                    ? 'Works: a database injection was recognised and blocked (403).'
                    : 'Works: a database injection was recognised. In "log" it is written down but not stopped; set DRACO_WAF_MODE=block when you are ready.');

                return self::SUCCESS;
        }
    }
}
