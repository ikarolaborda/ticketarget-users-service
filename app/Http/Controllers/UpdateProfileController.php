<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\UpdateProfileRequest;
use App\Models\User;
use App\Services\AuthTokenIssuer;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

final readonly class UpdateProfileController
{
    public function __construct(private AuthTokenIssuer $tokens) {}

    public function __invoke(UpdateProfileRequest $request): JsonResponse
    {
        $claims = $this->tokens->verify((string) $request->bearerToken());

        if ($claims === null) {
            return response()->json(['message' => 'Unauthenticated.'], Response::HTTP_UNAUTHORIZED);
        }

        $user = User::query()->find($claims['sub']);

        if ($user === null) {
            return response()->json(['message' => 'Unauthenticated.'], Response::HTTP_UNAUTHORIZED);
        }

        $name = $request->validated('name');
        $email = $request->normalizedEmail();
        $changed = false;

        if ($name !== null && trim($name) !== $user->name) {
            $user->name = trim($name);
            $changed = true;
        }

        if ($email !== null && $email !== $user->email) {
            $user->email = $email;
            $changed = true;
        }

        if (! $changed) {
            return response()->json([
                'user' => ['id' => $user->id, 'name' => $user->name, 'email' => $user->email, 'is_admin' => $user->is_admin === true],
            ]);
        }

        try {
            $user->save();
        } catch (UniqueConstraintViolationException) {
            return response()->json(['message' => 'An account with this email already exists.'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Name/email live inside the token claims, so a claim change must come
        // with a fresh token or every client keeps presenting stale identity.
        return response()->json([
            'token' => $this->tokens->issue($user),
            'user' => ['id' => $user->id, 'name' => $user->name, 'email' => $user->email, 'is_admin' => $user->is_admin === true],
        ]);
    }
}
