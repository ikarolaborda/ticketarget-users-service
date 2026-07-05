<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Tests\Support\UsesRs256SigningKey;
use Tests\TestCase;

final class AdminClaimTest extends TestCase
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

    public function test_a_fresh_registration_is_not_an_admin(): void
    {
        $response = $this->postJson('/auth/register', [
            'name' => 'Regular Rita',
            'email' => 'rita@example.com',
            'password' => 'secret-password-1',
        ]);

        $response->assertStatus(201)->assertJsonPath('user.is_admin', false);

        $this->assertFalse($this->claims($response->json('token'))['is_admin']);
    }

    public function test_a_promoted_user_logs_in_with_the_admin_claim(): void
    {
        $this->register('boss@example.com');
        $this->artisan('admin:promote', ['email' => 'boss@example.com'])->assertSuccessful();

        $response = $this->postJson('/auth/login', [
            'email' => 'boss@example.com',
            'password' => 'secret-password-1',
        ]);

        $response->assertOk()->assertJsonPath('user.is_admin', true);

        $token = $response->json('token');
        $this->assertTrue($this->claims($token)['is_admin']);

        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$token])
            ->assertOk()
            ->assertJsonPath('user.is_admin', true);
    }

    public function test_a_token_minted_before_the_admin_rollout_is_treated_as_non_admin(): void
    {
        $this->register('legacy@example.com');

        $user = User::query()->where('email', 'legacy@example.com')->firstOrFail();
        $legacy = $this->legacyToken($user);

        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$legacy])
            ->assertOk()
            ->assertJsonPath('user.is_admin', false);
    }

    public function test_promote_is_idempotent_and_demote_reverts(): void
    {
        $this->register('flip@example.com');

        $this->artisan('admin:promote', ['email' => 'flip@example.com'])->assertSuccessful();
        $this->artisan('admin:promote', ['email' => 'flip@example.com'])->assertSuccessful();
        $this->assertTrue(User::query()->where('email', 'flip@example.com')->firstOrFail()->is_admin);

        $this->artisan('admin:promote', ['email' => 'flip@example.com', '--demote' => true])->assertSuccessful();
        $this->assertFalse(User::query()->where('email', 'flip@example.com')->firstOrFail()->is_admin);
    }

    public function test_promoting_an_unknown_email_fails(): void
    {
        $this->artisan('admin:promote', ['email' => 'ghost@example.com'])->assertFailed();
    }

    private function register(string $email): void
    {
        $this->postJson('/auth/register', [
            'name' => 'Someone',
            'email' => $email,
            'password' => 'secret-password-1',
        ])->assertStatus(201);
    }

    private function claims(string $token): array
    {
        [, $payload] = explode('.', $token);

        return json_decode(base64_decode(strtr($payload, '-_', '+/')), true);
    }

    /** A pre-rollout token: same contract, no is_admin claim. */
    private function legacyToken(User $user): string
    {
        $encode = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');

        $header = $encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = $encode(json_encode([
            'iss' => 'ticketarget-users',
            'sub' => $user->id,
            'email' => $user->email,
            'name' => $user->name,
            'iat' => time(),
            'exp' => time() + 3600,
        ]));

        return $header.'.'.$payload.'.'.$encode(hash_hmac('sha256', $header.'.'.$payload, 'test-auth-secret', true));
    }
}
