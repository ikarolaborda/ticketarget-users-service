<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Tests\Support\UsesRs256SigningKey;
use Tests\TestCase;

final class Rs256IssuanceTest extends TestCase
{
    use RefreshDatabase;
    use UsesRs256SigningKey;

    protected function beforeRefreshingDatabase(): void
    {
        if (config('database.default') !== 'sqlite') {
            throw new \RuntimeException('Refusing to refresh a non-sqlite database.');
        }
    }

    protected function setUp(): void
    {
        parent::setUp();

        config(['auth_token.secret' => 'test-auth-secret', 'auth_token.ttl_seconds' => 3600]);
        $this->configureRs256SigningKey();

        if (! Schema::hasTable('users')) {
            Schema::create('users', function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('name');
                $table->string('email')->unique();
                $table->string('password');
                $table->boolean('is_admin')->default(false);
                $table->rememberToken();
                $table->timestamps();
            });
        }
    }

    public function test_issued_tokens_carry_an_rs256_header_with_the_active_kid(): void
    {
        $token = $this->registerUser('rs@example.com');

        $header = json_decode($this->base64UrlDecode(explode('.', $token)[0]), true);

        $this->assertSame('RS256', $header['alg']);
        $this->assertSame('JWT', $header['typ']);
        $this->assertSame('test-kid', $header['kid']);
    }

    public function test_the_jwks_endpoint_publishes_the_active_rsa_key(): void
    {
        $response = $this->getJson('/auth/.well-known/jwks.json')->assertOk();

        $key = $response->json('keys.0');

        $this->assertSame('RSA', $key['kty']);
        $this->assertSame('sig', $key['use']);
        $this->assertSame('RS256', $key['alg']);
        $this->assertSame('test-kid', $key['kid']);
        $this->assertNotSame('', (string) $key['n']);
        $this->assertSame('AQAB', $key['e']);
    }

    public function test_a_legacy_hs256_token_is_accepted_only_while_the_flag_is_on(): void
    {
        config(['auth_token.accept_hs256' => true]);
        $this->registerUser('legacy@example.com');

        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$this->legacyHs256Token()])
            ->assertOk()
            ->assertJsonPath('user.email', 'legacy@example.com');
    }

    public function test_a_legacy_hs256_token_is_rejected_once_the_flag_is_off(): void
    {
        config(['auth_token.accept_hs256' => false]);

        $this->registerUser('cutoff@example.com');

        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$this->legacyHs256Token()])
            ->assertStatus(401);
    }

    public function test_an_rs256_token_with_an_unknown_kid_is_rejected(): void
    {
        $token = $this->registerUser('kid@example.com');

        [$header, $payload, $signature] = explode('.', $token);
        $forgedHeader = $this->base64UrlEncode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'unknown-kid']));

        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$forgedHeader.'.'.$payload.'.'.$signature])
            ->assertStatus(401);
    }

    private function registerUser(string $email): string
    {
        $response = $this->postJson('/auth/register', [
            'name' => 'Rs Tester',
            'email' => $email,
            'password' => 'super-secret-1',
        ])->assertCreated();

        return (string) $response->json('token');
    }

    private function legacyHs256Token(): string
    {
        $user = User::query()->firstOrFail();

        $header = $this->base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = $this->base64UrlEncode(json_encode([
            'iss' => config('auth_token.issuer'),
            'sub' => $user->id,
            'email' => $user->email,
            'name' => $user->name,
            'is_admin' => false,
            'iat' => time(),
            'exp' => time() + 3600,
        ]));
        $signature = $this->base64UrlEncode(hash_hmac('sha256', $header.'.'.$payload, 'test-auth-secret', true));

        return $header.'.'.$payload.'.'.$signature;
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
