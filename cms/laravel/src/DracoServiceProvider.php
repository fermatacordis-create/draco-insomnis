<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel;

use DracoInsomnis\Laravel\Console\BlockCommand;
use DracoInsomnis\Laravel\Console\CleanupCommand;
use DracoInsomnis\Laravel\Console\EvidenceCommand;
use DracoInsomnis\Laravel\Console\ReviewsCommand;
use DracoInsomnis\Laravel\Console\StatusCommand;
use DracoInsomnis\Laravel\Console\TestCommand;
use DracoInsomnis\Laravel\Http\Middleware\Firewall;
use DracoInsomnis\Laravel\Http\Middleware\SignupShield;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

/**
 * Draco Insomnis for Laravel. Ab insomni custodita dracone.
 *
 * - Firewall and pace limit: a global middleware for requests without a session, and the same
 *   middleware at the end of the configured groups for requests with one.
 * - Sign-up shield: the 'draco.signup' middleware on the registration route and @dracoFields in
 *   its form.
 * - Artisan: draco:status, draco:evidence, draco:block, draco:reviews, draco:test, draco:cleanup (scheduled daily).
 */
final class DracoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/draco.php', 'draco');
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->loadTranslationsFrom(__DIR__ . '/../lang', 'draco');
        $this->publishes([__DIR__ . '/../config/draco.php' => config_path('draco.php')], 'draco-config');

        // Through the HTTP kernel: it owns the middleware groups and copies them to the router, so
        // anything pushed to the router alone would be overwritten when the kernel syncs.
        $kernel = $this->app->make(Kernel::class);
        $kernel->prependMiddleware(Firewall::class);
        foreach ((array) config('draco.groups', []) as $group) {
            $kernel->appendMiddlewareToGroup((string) $group, Firewall::class . ':group');
        }
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('draco', Firewall::class);
        $router->aliasMiddleware('draco.signup', SignupShield::class);

        $this->callAfterResolving('blade.compiler', static function ($blade): void {
            $blade->directive('dracoFields', static fn (): string => '<?php echo \\DracoInsomnis\\Laravel\\Guard::fields(); ?>');
        });

        if ($this->app->runningInConsole()) {
            $this->commands([StatusCommand::class, EvidenceCommand::class, BlockCommand::class, CleanupCommand::class, ReviewsCommand::class, TestCommand::class]);
            $this->callAfterResolving(Schedule::class, static function (Schedule $schedule): void {
                $schedule->command('draco:cleanup')->daily();
            });
        }
    }
}
