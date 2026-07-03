<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Models\User;
use App\Services\AuthTokenIssuer;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

final readonly class RegisterController
{
    public function __construct(private AuthTokenIssuer $tokens) {}

    public function __invoke(RegisterRequest $request): JsonResponse
    {
        $user = new User;
        $user->name = trim($request->validated('name'));
        $user->email = $request->normalizedEmail();
        $user->password = Hash::make($request->validated('password'));
        // Set explicitly: strict models forbid reading a column the INSERT
        // never touched, and the issuer reads it for the is_admin claim.
        $user->is_admin = false;

        try {
            $user->save();
        } catch (UniqueConstraintViolationException) {
            // The unique index is the source of truth for duplicates, so a
            // concurrent double-submit degrades to the same deterministic 422.
            return response()->json(['message' => 'An account with this email already exists.'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        return response()->json([
            'token' => $this->tokens->issue($user),
            'user' => ['id' => $user->id, 'name' => $user->name, 'email' => $user->email, 'is_admin' => $user->is_admin === true],
        ], Response::HTTP_CREATED);
    }
}
