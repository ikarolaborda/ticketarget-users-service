<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Services\AuthTokenIssuer;
use RuntimeException;
use Tests\Support\UsesRs256SigningKey;
use Tests\TestCase;

/**
 * The issuer must refuse to boot on a broken signing-key configuration rather
 * than mint unverifiable or unsigned tokens.
 */
final class SigningKeyBootTest extends TestCase
{
    use UsesRs256SigningKey;

    public function test_it_aborts_when_the_private_key_path_is_unreadable(): void
    {
        config(['auth_token.private_key_path' => '/does/not/exist.pem', 'auth_token.active_kid' => 'k1']);

        $this->expectException(RuntimeException::class);
        $this->resolveIssuer();
    }

    public function test_it_aborts_when_the_key_is_not_rsa(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'not-rsa-');
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $pem = '';
        openssl_pkey_export($key, $pem);
        file_put_contents($path, $pem);

        config(['auth_token.private_key_path' => $path, 'auth_token.active_kid' => 'k1']);

        $this->expectException(RuntimeException::class);
        $this->resolveIssuer();
    }

    public function test_it_aborts_when_the_active_kid_is_empty(): void
    {
        config(['auth_token.private_key_path' => self::rs256PrivateKeyPath(), 'auth_token.active_kid' => '']);

        $this->expectException(RuntimeException::class);
        $this->resolveIssuer();
    }

    public function test_it_aborts_when_the_previous_public_key_is_unreadable(): void
    {
        config([
            'auth_token.private_key_path' => self::rs256PrivateKeyPath(),
            'auth_token.active_kid' => 'k1',
            'auth_token.previous_public_key_path' => '/does/not/exist.pem',
            'auth_token.previous_kid' => 'k0',
        ]);

        $this->expectException(RuntimeException::class);
        $this->resolveIssuer();
    }

    public function test_it_boots_with_a_valid_key(): void
    {
        $this->configureRs256SigningKey();

        $this->assertInstanceOf(AuthTokenIssuer::class, $this->resolveIssuer());
    }

    private function resolveIssuer(): AuthTokenIssuer
    {
        $this->app->forgetInstance(AuthTokenIssuer::class);

        return $this->app->make(AuthTokenIssuer::class);
    }
}
