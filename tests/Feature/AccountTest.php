<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

final class AccountTest extends TestCase
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

    public function test_profile_update_changes_claims_and_returns_a_fresh_working_token(): void
    {
        $token = $this->register('old@example.com');

        $response = $this->putJson('/auth/profile', [
            'name' => 'New Name',
            'email' => 'NEW@example.com',
        ], ['Authorization' => 'Bearer '.$token]);

        $response->assertOk()
            ->assertJsonPath('user.name', 'New Name')
            ->assertJsonPath('user.email', 'new@example.com')
            ->assertJsonStructure(['token']);

        $this->getJson('/auth/me', ['Authorization' => 'Bearer '.$response->json('token')])
            ->assertOk()
            ->assertJsonPath('user.email', 'new@example.com');
    }

    public function test_a_no_op_update_returns_no_new_token(): void
    {
        $token = $this->register('same@example.com', 'Same Name');

        $this->putJson('/auth/profile', [
            'name' => 'Same Name',
            'email' => 'same@example.com',
        ], ['Authorization' => 'Bearer '.$token])
            ->assertOk()
            ->assertJsonMissingPath('token');
    }

    public function test_profile_update_rejects_a_taken_email_and_anonymous_calls(): void
    {
        $this->register('taken@example.com');
        $token = $this->register('mine@example.com');

        $this->putJson('/auth/profile', ['email' => 'taken@example.com'], [
            'Authorization' => 'Bearer '.$token,
        ])->assertStatus(422);

        $this->putJson('/auth/profile', ['name' => 'X'])->assertStatus(401);
    }

    public function test_password_change_requires_the_current_password_and_takes_effect(): void
    {
        $token = $this->register('pw@example.com');

        $this->putJson('/auth/password', [
            'current_password' => 'wrong-password',
            'password' => 'brand-new-secret',
        ], ['Authorization' => 'Bearer '.$token])->assertStatus(422);

        $this->putJson('/auth/password', [
            'current_password' => 'super-secret-1',
            'password' => 'brand-new-secret',
        ], ['Authorization' => 'Bearer '.$token])->assertOk();

        $this->postJson('/auth/login', ['email' => 'pw@example.com', 'password' => 'super-secret-1'])
            ->assertStatus(401);
        $this->postJson('/auth/login', ['email' => 'pw@example.com', 'password' => 'brand-new-secret'])
            ->assertOk();
    }

    private function register(string $email, string $name = 'Test User'): string
    {
        return $this->postJson('/auth/register', [
            'name' => $name,
            'email' => $email,
            'password' => 'super-secret-1',
        ])->json('token');
    }
}
