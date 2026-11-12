<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Tests;

use DracoInsomnis\Core\FormStamp;
use DracoInsomnis\Core\Shield;
use DracoInsomnis\Laravel\DracoServiceProvider;
use DracoInsomnis\Laravel\Guard;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase as Base;

abstract class TestCase extends Base
{
    protected const VISITOR = '203.0.113.7';
    protected const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36';
    protected const ATTACK = '/?q=1%27%20union%20select%20password%20from%20users--%20';

    protected function getPackageProviders($app): array
    {
        return [DracoServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));
        $app['config']->set('database.default', 'testing');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('draco.bypass_ability', 'bypassDraco');
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }

    protected function defineRoutes($router): void
    {
        Route::middleware('web')->group(function () {
            Route::get('/', fn () => 'home');
            Route::post('/', fn () => 'posted');
            Route::get('/login', fn () => 'login page');
            Route::get('/register', fn () => Blade::render('<form method="post">@dracoFields</form>'));
            Route::post('/register', fn () => 'account created')->middleware('draco.signup');
        });
        Route::middleware('api')->prefix('api')->group(function () {
            Route::get('/items', fn () => ['items' => []]);
        });
    }

    protected function setUp(): void
    {
        parent::setUp();
        Gate::define('bypassDraco', fn ($user) => (bool) ($user->is_admin ?? false));
        Cache::flush();
        $this->withServerVariables(['REMOTE_ADDR' => self::VISITOR])->withHeader('User-Agent', self::BROWSER);
    }

    protected function events(): array
    {
        return DB::table('draco_events')->orderBy('id')->get()->all();
    }

    protected function blocks(): array
    {
        return DB::table('draco_blocks')->get()->all();
    }

    protected function shield(): Shield
    {
        return new Shield(Guard::host());
    }

    protected function personStamp(): string
    {
        return FormStamp::make(Guard::host()->secret(), time() - 40);
    }

    protected function user(bool $admin): User
    {
        $user = new User();
        $user->forceFill(['id' => $admin ? 1 : 2, 'email' => $admin ? 'admin@example.org' : 'editor@example.org']);
        $user->is_admin = $admin;

        return $user;
    }

    protected function withSessionCookie(): static
    {
        return $this->withUnencryptedCookie((string) config('session.cookie'), 'session-id');
    }
}
