<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\User;
use App\Services\AuthTokenIssuer;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

final class AuthTest extends TestCase
{
    use RefreshDatabase;

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

        // The users table is owned by the Event service's migrations (shared
        // data plane), so these tests create the minimal schema themselves.
        if (! Schema::hasTable('users')) {
            Schema::create('users', function (Blueprint $table): void {
                $table->uuid('id')->primary();
                $table->string('name');
                $table->string('email')->unique();
                $table->string('password');
                $table->rememberToken();
                $table->timestamps();
            });
        }
    }

    public function test_it_registers_a_user_and_returns_a_token(): void
    {
        $response = $this->postJson('/auth/register', [
            'name' => 'Ana Souza',
            'email' => '  ANA@Example.com ',
            'password' => 'super-secret-1',
        ]);

        $response->assertCreated()
            ->assertJsonStructure(['token', 'user' => ['id', 'name', 'email']])
            ->assertJsonPath('user.email', 'ana@example.com');

        $this->assertDatabaseHas('users', ['email' => 'ana@example.com']);
        $this->assertNotSame('super-secret-1', User::query()->first()->password);
    }

    public function test_it_rejects_a_duplicate_email_deterministically(): void
    {
        $payload = ['name' => 'Ana', 'email' => 'dup@example.com', 'password' => 'super-secret-1'];

        $this->postJson('/auth/register', $payload)->assertCreated();
        $this->postJson('/auth/register', $payload)->assertStatus(422);

        $this->assertDatabaseCount('users', 1);
    }

    public function test_it_rejects_weak_or_missing_input(): void
    {
        $this->postJson('/auth/register', [
            'name' => 'Ana',
            'email' => 'not-an-email',
            'password' => 'short',
        ])->assertStatus(422)->assertJsonValidationErrors(['email', 'password']);
    }

    public function test_it_logs_in_with_normalized_email_and_correct_password(): void
    {
        $this->registerUser('login@example.com', 'super-secret-1');

        $response = $this->postJson('/auth/login', [
            'email' => 'LOGIN@example.com',
            'password' => 'super-secret-1',
        ]);

        $response->assertOk()->assertJsonPath('user.email', 'login@example.com');
    }

    public function test_it_rejects_a_wrong_password_and_an_unknown_user(): void
    {
        $this->registerUser('who@example.com', 'super-secret-1');

        $this->postJson('/auth/login', ['email' => 'who@example.com', 'password' => 'wrong-password'])
            ->assertStatus(401);
        $this->postJson('/auth/login', ['email' => 'ghost@example.com', 'password' => 'whatever-123'])
            ->assertStatus(401);
    }

    public function test_me_returns_the_token_identity(): void
    {
        $token = $this->registerUser('me@example.com', 'super-secret-1');

        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$token])
            ->assertOk()
            ->assertJsonPath('user.email', 'me@example.com');
    }

    public function test_me_rejects_missing_malformed_tampered_and_expired_tokens(): void
    {
        $token = $this->registerUser('sec@example.com', 'super-secret-1');

        $this->getJson('/auth/me')->assertStatus(401);
        $this->getJson('/auth/me', ['Authorization' => 'Bearer not.a.jwt'])->assertStatus(401);
        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$token.'x'])->assertStatus(401);

        // Token signed with a different secret must be rejected.
        $foreign = (new AuthTokenIssuer('other-secret', 3600, (string) config('auth_token.issuer')))
            ->issue(User::query()->firstOrFail());
        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$foreign])->assertStatus(401);

        // Expired token must be rejected.
        $expired = (new AuthTokenIssuer('test-auth-secret', -10, (string) config('auth_token.issuer')))
            ->issue(User::query()->firstOrFail());
        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$expired])->assertStatus(401);
    }

    public function test_it_rejects_a_token_with_a_forged_none_algorithm(): void
    {
        $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
        $header = $b64(json_encode(['alg' => 'none', 'typ' => 'JWT']));
        $payload = $b64(json_encode([
            'iss' => config('auth_token.issuer'),
            'sub' => '019f0000-0000-7000-8000-000000000001',
            'email' => 'x@example.com',
            'name' => 'X',
            'iat' => time(),
            'exp' => time() + 3600,
        ]));

        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$header.'.'.$payload.'.'])
            ->assertStatus(401);
    }

    private function registerUser(string $email, string $password): string
    {
        $response = $this->postJson('/auth/register', [
            'name' => 'Test User',
            'email' => $email,
            'password' => $password,
        ]);

        return $response->json('token');
    }
}
