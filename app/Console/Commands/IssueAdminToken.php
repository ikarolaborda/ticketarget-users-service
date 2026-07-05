<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\User;
use App\Services\AuthTokenIssuer;
use Illuminate\Console\Command;

/**
 * Mints a platform JWT for CLI and service callers. Deliberately admin-only:
 * regular users authenticate through /auth/login, and refusing non-admin
 * issuance keeps this command from becoming a login bypass.
 */
final class IssueAdminToken extends Command
{
    protected $signature = 'auth:issue-token {email}';

    protected $description = 'Issue a platform JWT for an existing admin user (replaces the old Sanctum admin:token)';

    public function handle(AuthTokenIssuer $tokens): int
    {
        $email = mb_strtolower(trim((string) $this->argument('email')));

        $user = User::query()->where('email', $email)->first();

        if ($user === null) {
            $this->error('No user with that email. Register one first, then promote it with admin:promote.');

            return self::FAILURE;
        }

        if ($user->is_admin !== true) {
            $this->error('User is not an admin. Promote it with admin:promote before issuing a token.');

            return self::FAILURE;
        }

        $this->info(sprintf('Admin token (expires in %d seconds):', (int) config('auth_token.ttl_seconds')));
        $this->line($tokens->issue($user));

        return self::SUCCESS;
    }
}
