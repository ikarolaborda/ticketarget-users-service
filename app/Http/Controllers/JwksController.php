<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\AuthTokenIssuer;
use Illuminate\Http\JsonResponse;

/**
 * Publishes the RFC 7517 key set verifier services use to check RS256
 * signatures. Public keys only — safe to expose through the gateway.
 */
final readonly class JwksController
{
    public function __construct(private AuthTokenIssuer $tokens) {}

    public function __invoke(): JsonResponse
    {
        return response()->json(['keys' => $this->tokens->jwks()]);
    }
}
