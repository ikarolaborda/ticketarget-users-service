<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;

/**
 * Seeds (or promotes) an admin account. Idempotent so a bootstrap can run it
 * repeatedly: an existing account is promoted, a missing one is created. The
 * password is only applied when the account is created — it never silently
 * resets a real user's password on re-run.
 */
final class CreateAdmin extends Command
{
    protected $signature = 'admin:create {email} {--password=admin-password} {--name=Admin}';

    protected $description = 'Create an admin account (or promote an existing one) for first-run bootstrapping';

    public function handle(): int
    {
        $email = mb_strtolower(trim((string) $this->argument('email')));

        $user = User::query()->where('email', $email)->first();

        if ($user !== null) {
            if ($user->is_admin !== true) {
                $user->is_admin = true;
                $user->save();
                $this->info($email.' already existed; promoted to admin.');

                return self::SUCCESS;
            }

            $this->info($email.' is already an admin.');

            return self::SUCCESS;
        }

        $user = new User;
        $user->name = trim((string) $this->option('name'));
        $user->email = $email;
        $user->password = Hash::make((string) $this->option('password'));
        $user->is_admin = true;
        $user->save();

        $this->info('Created admin '.$email.'.');

        return self::SUCCESS;
    }
}
