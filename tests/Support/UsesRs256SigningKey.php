<?php

declare(strict_types=1);

namespace Tests\Support;

/**
 * Generates one ephemeral RSA keypair per test process and points the issuer
 * config at it. A committed PEM fixture would trip secret scanners; a fresh
 * key costs ~100ms once per run.
 */
trait UsesRs256SigningKey
{
    private static ?string $rsaPrivateKeyPath = null;

    private static ?string $rsaPrivateKeyPem = null;

    protected function configureRs256SigningKey(): void
    {
        config([
            'auth_token.private_key_path' => self::rs256PrivateKeyPath(),
            'auth_token.active_kid' => 'test-kid',
        ]);
    }

    protected static function rs256PrivateKeyPath(): string
    {
        if (self::$rsaPrivateKeyPath === null) {
            $path = tempnam(sys_get_temp_dir(), 'jwt-test-key-');

            if ($path === false || file_put_contents($path, self::rs256PrivateKeyPem()) === false) {
                throw new \RuntimeException('Failed to persist the test RSA keypair.');
            }

            self::$rsaPrivateKeyPath = $path;
        }

        return self::$rsaPrivateKeyPath;
    }

    protected static function rs256PrivateKeyPem(): string
    {
        if (self::$rsaPrivateKeyPem === null) {
            self::$rsaPrivateKeyPem = self::generateRsaPrivateKeyPem();
        }

        return self::$rsaPrivateKeyPem;
    }

    protected static function rs256PublicKeyPem(): string
    {
        $key = openssl_pkey_get_private(self::rs256PrivateKeyPem());
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if ($details === false) {
            throw new \RuntimeException('Failed to derive the test public key.');
        }

        return (string) $details['key'];
    }

    protected static function generateRsaPrivateKeyPem(): string
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $pem = '';

        if ($key === false || openssl_pkey_export($key, $pem) !== true) {
            throw new \RuntimeException('Failed to generate a test RSA keypair.');
        }

        return $pem;
    }
}
