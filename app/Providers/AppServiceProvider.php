<?php

declare(strict_types=1);

namespace App\Providers;

use App\Services\AuthTokenIssuer;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\ServiceProvider;
use RuntimeException;

final class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(AuthTokenIssuer::class, function (): AuthTokenIssuer {
            [$privateKeyPem, $publicKeyPems, $kid] = $this->loadSigningKeys();

            return new AuthTokenIssuer(
                privateKeyPem: $privateKeyPem,
                kid: $kid,
                publicKeyPems: $publicKeyPems,
                ttlSeconds: (int) config('auth_token.ttl_seconds'),
                issuer: (string) config('auth_token.issuer'),
                legacySecret: (string) config('auth_token.secret'),
                acceptHs256: (bool) config('auth_token.accept_hs256'),
            );
        });
    }

    public function boot(): void
    {
        Model::shouldBeStrict(! $this->app->isProduction());
    }

    /**
     * Fail fast: a missing, unreadable, or non-RSA signing key must abort the
     * first token operation loudly instead of producing broken tokens.
     *
     * @return array{0: string, 1: array<string, string>, 2: string}
     */
    private function loadSigningKeys(): array
    {
        $path = (string) config('auth_token.private_key_path');
        $privateKeyPem = $path === '' ? false : @file_get_contents($path);

        if ($privateKeyPem === false) {
            throw new RuntimeException('AUTH_JWT_PRIVATE_KEY_PATH does not point to a readable PEM file.');
        }

        $key = openssl_pkey_get_private($privateKeyPem);
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new RuntimeException('The auth signing key must be a valid RSA private key.');
        }

        $kid = (string) config('auth_token.active_kid');

        if ($kid === '') {
            throw new RuntimeException('AUTH_JWT_ACTIVE_KID must be set.');
        }

        $publicKeyPems = [$kid => (string) $details['key']];

        $previousPath = (string) config('auth_token.previous_public_key_path');
        $previousKid = (string) config('auth_token.previous_kid');

        if ($previousPath !== '' && $previousKid !== '') {
            $previousPem = @file_get_contents($previousPath);

            if ($previousPem === false || openssl_pkey_get_public($previousPem) === false) {
                throw new RuntimeException('AUTH_JWT_PREVIOUS_PUBLIC_KEY_PATH does not point to a readable public key.');
            }

            $publicKeyPems[$previousKid] = $previousPem;
        }

        return [$privateKeyPem, $publicKeyPems, $kid];
    }
}
