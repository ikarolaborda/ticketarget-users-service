<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\User;

/**
 * Issues and verifies stateless HS256 JWTs (RFC 7519 compact form). The
 * implementation is intentionally minimal and strict: the algorithm is FIXED
 * to HS256 (no negotiation, "none" is impossible), every claim is required,
 * and signatures are compared in constant time. Any service holding the
 * shared secret can verify tokens without a round trip.
 */
final readonly class AuthTokenIssuer
{
    public function __construct(
        private string $secret,
        private int $ttlSeconds,
        private string $issuer,
    ) {
    }

    public function issue(User $user): string
    {
        $now = time();

        $header = $this->base64UrlEncode(json_encode(
            ['alg' => 'HS256', 'typ' => 'JWT'],
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

        return $header.'.'.$payload.'.'.$this->sign($header.'.'.$payload);
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

        if (! hash_equals($this->sign($header.'.'.$payload), $signature)) {
            return null;
        }

        $decodedHeader = json_decode($this->base64UrlDecode($header), true);
        if (! is_array($decodedHeader) || ($decodedHeader['alg'] ?? null) !== 'HS256') {
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

    private function sign(string $signingInput): string
    {
        return $this->base64UrlEncode(hash_hmac('sha256', $signingInput, $this->secret, true));
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
