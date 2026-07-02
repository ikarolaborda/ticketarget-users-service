<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\UpdatePasswordRequest;
use App\Models\User;
use App\Services\AuthTokenIssuer;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Hash;

final readonly class UpdatePasswordController
{
    public function __construct(private AuthTokenIssuer $tokens)
    {
    }

    public function __invoke(UpdatePasswordRequest $request): JsonResponse
    {
        $claims = $this->tokens->verify((string) $request->bearerToken());

        if ($claims === null) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        $user = User::query()->find($claims['sub']);

        if ($user === null || ! Hash::check($request->validated('current_password'), $user->password)) {
            return response()->json(['message' => 'Current password is incorrect.'], 422);
        }

        $user->password = Hash::make($request->validated('password'));
        $user->save();

        // Existing tokens stay valid until expiry (no revocation registry yet);
        // documented tradeoff, acceptable for stateless 24h tokens.
        return response()->json(['message' => 'Password updated.']);
    }
}
