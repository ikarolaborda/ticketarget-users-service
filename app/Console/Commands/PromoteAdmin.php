<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;

/**
 * Grants the admin flag to an existing account. The flag lands in freshly
 * issued JWTs (is_admin claim); the user must log in again to pick it up.
 */
final class PromoteAdmin extends Command
{
    protected $signature = 'admin:promote {email} {--demote : Revoke the admin flag instead}';
    protected $description = 'Grant (or revoke, with --demote) the admin flag on an account';

    public function handle(): int
    {
        $email = mb_strtolower(trim((string) $this->argument('email')));
        $target = ! $this->option('demote');

        $user = User::query()->where('email', $email)->first();

        if ($user === null) {
            $this->error("No account found for {$email}.");

            return self::FAILURE;
        }

        if ($user->is_admin === $target) {
            $this->info("{$email} is already ".($target ? 'an admin' : 'a regular user').'.');

            return self::SUCCESS;
        }

        $user->is_admin = $target;
        $user->save();

        $this->info("{$email} ".($target ? 'promoted to admin' : 'demoted to regular user').'. A fresh login is required for the new token claim.');

        return self::SUCCESS;
    }
}
