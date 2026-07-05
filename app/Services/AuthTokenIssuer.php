<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\User;

/**
 * Issues and verifies the platform's stateless JWTs (RFC 7519 compact form).
 * Issuance is RS256 only — this service holds the sole private key, so no
 * other service can mint tokens. Verification accepts RS256 against the
 * published key ring (active kid plus an optional rotation-overlap key) and,
 * while the accept_hs256 migration flag stays on, legacy HS256 tokens signed
 * with the old shared secret. The algorithm is taken from a strictly parsed
 * header but only ever selects between these two server-configured paths —
 * "none" or any other downgrade is impossible.
 */
final readonly class AuthTokenIssuer
{
    /**
     * @param  array<string, string>  $publicKeyPems  kid => PEM accepted on verify (active + rotation overlap)
     */
    public function __construct(
        private string $privateKeyPem,
        private string $kid,
        private array $publicKeyPems,
        private int $ttlSeconds,
        private string $issuer,
        private string $legacySecret,
        private bool $acceptHs256,
    ) {}

    public function issue(User $user): string
    {
        $now = time();

        $header = $this->base64UrlEncode(json_encode(
            ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $this->kid],
            JSON_THROW_ON_ERROR,
        ));

        $payload = $this->base64UrlEncode(json_encode([
            'iss' => $this->issuer,
            'sub' => $user->id,
            'email' => $user->email,
            'name' => $user->name,
            'is_admin' => $user->is_admin === true,
            'iat' => $now,
            'exp' => $now + $this->ttlSeconds,
        ], JSON_THROW_ON_ERROR));

        $signature = '';
        if (openssl_sign($header.'.'.$payload, $signature, $this->privateKeyPem, OPENSSL_ALGO_SHA256) !== true) {
            throw new \RuntimeException('Failed to sign the auth token with the RS256 private key.');
        }

        return $header.'.'.$payload.'.'.$this->base64UrlEncode($signature);
    }

    /**
     * @return array{sub: string, email: string, name: string, is_admin: bool}|null claims, or null when invalid
     */
    public function verify(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        [$header, $payload, $signature] = $parts;

        $decodedHeader = json_decode($this->base64UrlDecode($header), true);
        if (! is_array($decodedHeader)) {
            return null;
        }

        if (! $this->signatureValid($decodedHeader, $header.'.'.$payload, $signature)) {
            return null;
        }

        $claims = json_decode($this->base64UrlDecode($payload), true);

        if (! is_array($claims)
            || ($claims['iss'] ?? null) !== $this->issuer
            || ! is_string($claims['sub'] ?? null)
            || preg_match('/^[0-9a-f-]{36}$/i', $claims['sub']) !== 1
            || ! is_string($claims['email'] ?? null)
            || ! is_string($claims['name'] ?? null)
            || ! is_int($claims['exp'] ?? null)
            || $claims['exp'] < time()
        ) {
            return null;
        }

        // Tokens minted before the admin rollout carry no is_admin claim;
        // they are plain customers, never admins.
        return [
            'sub' => $claims['sub'],
            'email' => $claims['email'],
            'name' => $claims['name'],
            'is_admin' => ($claims['is_admin'] ?? null) === true,
        ];
    }

    /**
     * The RFC 7517 key set for every public key verifiers may accept.
     *
     * @return list<array{kty: string, use: string, alg: string, kid: string, n: string, e: string}>
     */
    public function jwks(): array
    {
        $keys = [];

        foreach ($this->publicKeyPems as $kid => $pem) {
            $key = openssl_pkey_get_public($pem);
            $details = $key === false ? false : openssl_pkey_get_details($key);

            if ($details === false || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
                throw new \RuntimeException(sprintf('Public key "%s" is not a readable RSA key.', $kid));
            }

            $keys[] = [
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => 'RS256',
                'kid' => (string) $kid,
                'n' => $this->base64UrlEncode(ltrim($details['rsa']['n'], "\x00")),
                'e' => $this->base64UrlEncode(ltrim($details['rsa']['e'], "\x00")),
            ];
        }

        return $keys;
    }

    /** @param array<mixed> $decodedHeader */
    private function signatureValid(array $decodedHeader, string $signingInput, string $signature): bool
    {
        $algorithm = $decodedHeader['alg'] ?? null;

        if ($algorithm === 'RS256') {
            $kid = $decodedHeader['kid'] ?? null;
            if (! is_string($kid) || ! isset($this->publicKeyPems[$kid])) {
                return false;
            }

            $raw = $this->base64UrlDecode($signature);

            return $raw !== ''
                && openssl_verify($signingInput, $raw, $this->publicKeyPems[$kid], OPENSSL_ALGO_SHA256) === 1;
        }

        if ($algorithm === 'HS256' && $this->acceptHs256 && $this->legacySecret !== '') {
            $expected = $this->base64UrlEncode(hash_hmac('sha256', $signingInput, $this->legacySecret, true));

            return hash_equals($expected, $signature);
        }

        return false;
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string
    {
        return base64_decode(strtr($value, '-_', '+/'), true) ?: '';
    }
}
