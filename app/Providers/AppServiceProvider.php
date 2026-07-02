<?php

declare(strict_types=1);

namespace App\Providers;

use App\Services\AuthTokenIssuer;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\ServiceProvider;

final class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(AuthTokenIssuer::class, fn (): AuthTokenIssuer => new AuthTokenIssuer(
            secret: (string) config('auth_token.secret'),
            ttlSeconds: (int) config('auth_token.ttl_seconds'),
            issuer: (string) config('auth_token.issuer'),
        ));
    }

    public function boot(): void
    {
        Model::shouldBeStrict(! $this->app->isProduction());
    }
}
