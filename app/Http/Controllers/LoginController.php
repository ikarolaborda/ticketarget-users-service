<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Models\User;
use App\Services\AuthTokenIssuer;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Hash;

final readonly class LoginController
{
    public function __construct(private AuthTokenIssuer $tokens)
    {
    }

    public function __invoke(LoginRequest $request): JsonResponse
    {
        $user = User::query()->where('email', $request->normalizedEmail())->first();

        if ($user === null || ! Hash::check($request->validated('password'), $user->password)) {
            return response()->json(['message' => 'Invalid email or password.'], 401);
        }

        return response()->json([
            'token' => $this->tokens->issue($user),
            'user' => ['id' => $user->id, 'name' => $user->name, 'email' => $user->email],
        ]);
    }
}
