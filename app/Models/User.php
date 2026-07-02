<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * Account row in the shared users table (created by the Event service's
 * migrations — shared data plane, same pattern as tickets for Booking).
 */
final class User extends Model
{
    use HasUuids;

    protected $hidden = ['password', 'remember_token'];

    protected function casts(): array
    {
        return ['is_admin' => 'boolean'];
    }
}
