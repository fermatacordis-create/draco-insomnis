<?php

/*
 * Draco Insomnis for Laravel. Ab insomni custodita dracone.
 * Every part starts off: switch them on here or in .env.
 */

return [

    // The sign-up shield. Put the 'draco.signup' middleware on your registration route and
    // @dracoFields inside its form.
    'shield' => (bool) env('DRACO_SHIELD', false),

    // Firewall: 'off', 'log' (record what it would stop) or 'block'. Start with 'log'.
    // Emergency exit: DRACO_WAF_OFF=true in .env.
    'waf_mode' => env('DRACO_WAF_MODE', 'off'),
    'waf_off' => (bool) env('DRACO_WAF_OFF', false),

    // Anti-copy pace limit: 'off', 'log' or 'block'. Logged-in users are never limited.
    'pace_mode' => env('DRACO_PACE_MODE', 'off'),
    'anticopy_rate_ip' => (int) env('DRACO_RATE_IP', 120),
    'anticopy_rate_net' => (int) env('DRACO_RATE_NET', 600),

    // Where the visitor address comes from: '' (the connection, recommended), 'cf' (Cloudflare) or
    // 'xff' (first X-Forwarded-For). Only change it when the app is behind that proxy.
    'proxy_header' => env('DRACO_PROXY_HEADER', ''),

    // Extra rented-server networks (CIDR, one per line), added to the ones Draco knows.
    'hosting_nets' => env('DRACO_HOSTING_NETS', ''),

    // A Gate ability: users who pass it are never inspected by the firewall, and the addresses they
    // work from are never blocked or limited. null = nobody is exempt by role.
    'bypass_ability' => env('DRACO_BYPASS_ABILITY'),

    // Addresses that are never blocked or limited (comma-separated), on top of the remembered ones.
    'admin_ips' => array_filter(array_map('trim', explode(',', (string) env('DRACO_ADMIN_IPS', '')))),

    // Paths that are never inspected or limited (start of the path), such as health checks or webhooks
    // that receive signed payloads.
    'except' => ['up'],

    // Middleware groups that get the check for requests with a session (the global middleware
    // already checks the ones without).
    'groups' => ['web', 'api'],

    // Form fields read by 'draco.signup'.
    'signup_fields' => [
        'username' => 'name',
        'email' => 'email',
    ],

    // Cache store for counters (null = the default store). Redis or database are best with several
    // servers.
    'cache_store' => env('DRACO_CACHE_STORE'),

    // Database connection for the evidence and the block list (null = the default connection).
    'connection' => env('DRACO_DB_CONNECTION'),
];
