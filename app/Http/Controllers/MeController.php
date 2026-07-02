<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\AuthTokenIssuer;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final readonly class MeController
{
    public function __construct(private AuthTokenIssuer $tokens)
    {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $claims = $this->tokens->verify((string) $request->bearerToken());

        if ($claims === null) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        return response()->json([
            'user' => ['id' => $claims['sub'], 'name' => $claims['name'], 'email' => $claims['email'], 'is_admin' => $claims['is_admin']],
        ]);
    }
}
