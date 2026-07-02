<?php

declare(strict_types=1);

return [
    'default' => env('DB_CONNECTION', 'pgsql'),

    'connections' => [
        'pgsql' => [
            'driver' => 'pgsql',
            'read' => ['host' => [env('DB_READ_HOST', env('DB_HOST', 'postgres-replica'))]],
            // Credential checks and writes must see the freshest rows.
            'write' => ['host' => [env('DB_HOST', 'postgres-primary')]],
            'sticky' => true,
            'port' => env('DB_PORT', '5432'),
            'database' => env('DB_DATABASE', 'ticketarget'),
            'username' => env('DB_USERNAME', 'ticketarget'),
            'password' => env('DB_PASSWORD', ''),
            'charset' => 'utf8',
            'prefix' => '',
            'search_path' => 'public',
            'sslmode' => 'prefer',
        ],

        // In-memory database used exclusively by the test suite (phpunit.xml
        // forces DB_CONNECTION=sqlite so tests can never touch the live pgsql).
        'sqlite' => [
            'driver' => 'sqlite',
            'database' => env('DB_DATABASE', ':memory:'),
            'prefix' => '',
            'foreign_key_constraints' => true,
        ],
    ],

    'migrations' => ['table' => 'migrations'],
];
