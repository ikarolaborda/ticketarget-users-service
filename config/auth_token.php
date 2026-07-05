<?php

declare(strict_types=1);

return [
    // Legacy symmetric secret. Only consulted while accept_hs256 stays on;
    // remove the env once the migration overlap window has passed.
    'secret' => env('AUTH_JWT_SECRET', ''),

    'ttl_seconds' => (int) env('AUTH_JWT_TTL', 86400),

    'issuer' => env('AUTH_JWT_ISSUER', 'ticketarget-users'),

    // RS256 signing key — this service is the platform's sole token issuer.
    // Boot fails fast when the key is missing or not RSA.
    'private_key_path' => env('AUTH_JWT_PRIVATE_KEY_PATH', ''),

    'active_kid' => env('AUTH_JWT_ACTIVE_KID', ''),

    // Rotation overlap: the previous public key stays published (and
    // accepted) for at least token TTL + verifier cache TTL after a rotation.
    'previous_public_key_path' => env('AUTH_JWT_PREVIOUS_PUBLIC_KEY_PATH', ''),

    'previous_kid' => env('AUTH_JWT_PREVIOUS_KID', ''),

    // Accept legacy HS256 bearers during the RS256 migration window.
    'accept_hs256' => (bool) env('AUTH_JWT_ACCEPT_HS256', true),
];
