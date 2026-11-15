<?php
/**
 * The release's SBOM (CycloneDX 1.6, JSON), written from what is really in the release folder.
 *
 *   php bin/build-sbom.php <release-dir> [output-file]
 *
 * Draco ships no third-party code, so a scanner finds almost nothing to list. This says what a buyer
 * or an auditor asks instead: every package of the release with its SHA-256 and SHA-512, its package
 * URL and what it runs on; the shared engines (src/Core) file by file, and which packages carry them;
 * the Docker image by digest and its base image; the country data; and every outside service Draco
 * can talk to, when, and what it sends.
 *
 * Environment: GITHUB_SHA (else git), GITHUB_REPOSITORY (else fermatacordis-create/draco-insomnis),
 * DRACO_DOCKER_DIGEST (else <release-dir>/docker-digest.txt, else no image).
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$dir = rtrim($argv[1] ?? '', '/');
if ($dir === '' || !is_dir($dir)) {
    fwrite(STDERR, "usage: php bin/build-sbom.php <release-dir> [output-file]\n");
    exit(1);
}
$version = trim((string) shell_exec('sed -n "s/^ \* Version: *//p" ' . escapeshellarg("$root/draco-insomnis.php")));
$repo = getenv('GITHUB_REPOSITORY') ?: 'fermatacordis-create/draco-insomnis';
$commit = getenv('GITHUB_SHA') ?: trim((string) shell_exec('git -C ' . escapeshellarg($root) . ' rev-parse HEAD 2>/dev/null'));
// The commit's own time, so the same commit always gives the same SBOM.
$time = trim((string) shell_exec('git -C ' . escapeshellarg($root) . ' log -1 --format=%cI ' . escapeshellarg($commit) . ' 2>/dev/null')) ?: gmdate('c');
$out = $argv[2] ?? "$dir/draco-insomnis-v$version.cdx.json";
$gh = "https://github.com/$repo";
$download = "$gh/releases/download/v$version/";
$license = [['license' => ['id' => 'GPL-2.0-or-later']]];
$supplier = ['name' => 'Notorius Vision', 'url' => ['https://notoriusvision.com']];

/** A version 5 UUID: the same commit and version always get the same serial number. */
function uuid5(string $name): string
{
    $h = sha1(hex2bin('6ba7b8119dad11d180b400c04fd430c8') . $name);

    return sprintf('%s-%s-5%s-%x%s-%s', substr($h, 0, 8), substr($h, 8, 4), substr($h, 13, 3), (hexdec($h[16]) & 0x3) | 0x8, substr($h, 17, 3), substr($h, 20, 12));
}

function hashes(string $file): array
{
    return [['alg' => 'SHA-256', 'content' => hash_file('sha256', $file)], ['alg' => 'SHA-512', 'content' => hash_file('sha512', $file)]];
}

function props(array $kv): array
{
    $out = [];
    foreach ($kv as $k => $v) {
        $out[] = ['name' => $k, 'value' => $v];
    }

    return $out;
}

// What each file of the release is. The pattern is matched against the file name.
$kinds = [
    ['/^draco-insomnis-wordpress-.*\.zip$/', 'draco-insomnis-wordpress', 'WordPress plugin', 'WordPress 6.5 or newer, PHP 8.0 or newer', null, true],
    ['/^dracoinsomnis-prestashop-.*\.zip$/', 'dracoinsomnis-prestashop', 'PrestaShop module', 'PrestaShop 8 or 9', null, true],
    ['/^draco_insomnis-drupal-.*\.zip$/', 'draco_insomnis-drupal', 'Drupal module', 'Drupal 10.3 or 11', null, true],
    ['/^plg_system_dracoinsomnis-joomla-.*\.zip$/', 'plg_system_dracoinsomnis-joomla', 'Joomla system plugin', 'Joomla 5 or 6', null, true],
    ['/^local_dracoinsomnis-moodle-.*\.zip$/', 'local_dracoinsomnis-moodle', 'Moodle local plugin', 'Moodle 4.5 to 5.x', null, true],
    ['/^draco-insomnis-laravel-.*\.zip$/', 'draco-insomnis-laravel', 'Laravel package (Composer)', 'Laravel 11 to 13, PHP 8.2 or newer', 'pkg:composer/notoriusvision/draco-insomnis-laravel@%s', true],
    ['/^draco-insomnis-magento-.*\.zip$/', 'draco-insomnis-magento', 'Magento 2 / Mage-OS module (Composer)', 'Magento Open Source or Adobe Commerce 2.4, Mage-OS; PHP 8.2 to 8.4', 'pkg:composer/notoriusvision/draco-insomnis-magento@%s', true],
    ['/^draco-insomnis-server_.*_all\.deb$/', 'draco-insomnis-server', 'Server edition for any PHP site (Debian, Ubuntu)', 'PHP 8.0 or newer with PDO SQLite', 'pkg:deb/draco-insomnis-server@%s?arch=all', true],
    ['/^draco-insomnis-server-.*\.noarch\.rpm$/', 'draco-insomnis-server', 'Server edition for any PHP site (RHEL, AlmaLinux, Rocky, Fedora)', 'PHP 8.0 or newer with PDO SQLite', 'pkg:rpm/draco-insomnis-server@%s-1?arch=noarch', true],
    ['/^draco-insomnis-server-.*\.tar\.gz$/', 'draco-insomnis-server-tarball', 'Server edition for any PHP site (install.sh)', 'PHP 8.0 or newer with PDO SQLite', null, true],
    ['/^draco-insomnis-js-.*\.tgz$/', 'draco-insomnis', 'JavaScript package: Node.js (Express, Koa, Strapi, Directus) and Cloudflare Workers', 'Node.js 20 or newer, or Cloudflare Workers', 'pkg:npm/draco-insomnis@%s', false],
];

$components = [];
$dependencies = [];
$shipped = [];

// The shared engines, file by file: every PHP package carries this same code.
$coreFiles = glob("$root/src/Core/*.php") ?: [];
sort($coreFiles);
$coreRef = "draco-insomnis-core@$version";
$coreParts = [];
foreach ($coreFiles as $f) {
    $coreParts[] = [
        'type' => 'file',
        'bom-ref' => 'core-file:' . basename($f),
        'name' => 'src/Core/' . basename($f),
        'hashes' => [['alg' => 'SHA-256', 'content' => hash_file('sha256', $f)]],
    ];
}
$components[] = [
    'type' => 'library',
    'bom-ref' => $coreRef,
    'supplier' => $supplier,
    'name' => 'draco-insomnis-core',
    'version' => $version,
    'description' => 'The shared engines (sign-up shield, firewall signatures, block list, country filter, anti-copy pace limit, password rules, security headers). Plain PHP, no third-party code. Copied into every PHP package.',
    'licenses' => $license,
    'purl' => "pkg:github/$repo@v$version#src/Core",
    'components' => $coreParts,
    'externalReferences' => [['type' => 'vcs', 'url' => "$gh/tree/v$version/src/Core"]],
];

foreach (scandir($dir) ?: [] as $file) {
    foreach ($kinds as [$pattern, $name, $what, $requires, $purl, $hasCore]) {
        if (!preg_match($pattern, $file)) {
            continue;
        }
        $ref = "$file";
        $c = [
            'type' => 'application',
            'bom-ref' => $ref,
            'supplier' => $supplier,
            'name' => $name,
            'version' => $version,
            'description' => $what,
            'hashes' => hashes("$dir/$file"),
            'licenses' => $license,
            'purl' => $purl !== null ? sprintf($purl, $version) : "pkg:generic/$name@$version?download_url=" . rawurlencode($download . $file),
            'externalReferences' => [['type' => 'distribution', 'url' => $download . $file]],
            'properties' => props(['draco:file' => $file, 'draco:requires' => $requires, 'draco:third-party-code' => 'none']),
        ];
        if (!$hasCore) {
            $c['properties'][] = ['name' => 'draco:engines', 'value' => 'TypeScript port of src/Core, checked against the same test vectors (tests/vectors)'];
        }
        $components[] = $c;
        $shipped[] = $ref;
        $dependencies[] = ['ref' => $ref, 'dependsOn' => $hasCore ? [$coreRef] : []];
        continue 2;
    }
}

// The Docker add-on image, by digest, and the base it is built on.
$digest = getenv('DRACO_DOCKER_DIGEST') ?: (is_file("$dir/docker-digest.txt") ? trim((string) file_get_contents("$dir/docker-digest.txt")) : '');
if (preg_match('/@(sha256:[a-f0-9]{64})$/', $digest, $m)) {
    $image = 'ghcr.io/' . strtolower($repo);
    $base = trim((string) shell_exec('sed -n "s/^FROM \([^ ]*\).*/\1/p" ' . escapeshellarg("$root/server/docker/Dockerfile")));
    $components[] = [
        'type' => 'container',
        'bom-ref' => 'docker-image',
        'supplier' => $supplier,
        'name' => 'draco-insomnis',
        'version' => $version,
        'description' => 'Docker add-on for PHP containers (the server edition, ready to mount). Signed by digest with cosign.',
        'hashes' => [['alg' => 'SHA-256', 'content' => substr($m[1], 7)]],
        'licenses' => $license,
        'purl' => 'pkg:oci/draco-insomnis@' . rawurlencode($m[1]) . '?repository_url=' . rawurlencode($image) . '&tag=' . $version,
        'externalReferences' => [['type' => 'distribution', 'url' => "https://$image"]],
        'properties' => props(['draco:requires' => 'Any image built on the official PHP ones (8.0 or newer)']),
    ];
    $components[] = [
        'type' => 'container',
        'bom-ref' => "base-image:$base",
        'name' => explode(':', $base)[0],
        'version' => explode(':', $base)[1] ?? 'latest',
        'description' => 'Base of the add-on image: only carries the files that are copied into the app container.',
        'purl' => 'pkg:docker/library/' . str_replace(':', '@', $base),
        'scope' => 'required',
    ];
    $shipped[] = 'docker-image';
    $dependencies[] = ['ref' => 'docker-image', 'dependsOn' => [$coreRef, "base-image:$base"]];
    $dependencies[] = ['ref' => "base-image:$base", 'dependsOn' => []];
}

// The country list: not inside any package, downloaded monthly when the country filter is on.
$components[] = [
    'type' => 'data',
    'bom-ref' => 'geo-data',
    'name' => 'draco-geo.bin',
    'description' => 'IP-to-country table, built monthly by .github/workflows/geo.yml from DB-IP "IP to Country Lite". Downloaded at run time only when the country filter is switched on; not inside any package.',
    'scope' => 'optional',
    'licenses' => [['license' => ['id' => 'CC-BY-4.0']]],
    'externalReferences' => [
        ['type' => 'distribution', 'url' => "$gh/releases/download/geo/draco-geo.bin"],
        ['type' => 'website', 'url' => 'https://db-ip.com/db/lite.php'],
    ],
];

// Every outside service Draco can talk to. None is used unless the site's owner switches it on.
$services = [
    ['hibp', 'Have I Been Pwned', 'Pwned Passwords range API', ['https://api.pwnedpasswords.com/range/'], false,
        'Only with "refuse breached passwords" on, when someone chooses a password. k-anonymity: the password never leaves the server. 3-second timeout; if there is no answer, the password is accepted.',
        [['flow' => 'outbound', 'classification' => 'first 5 hexadecimal characters of the SHA-1 of the new password']]],
    ['rdap', 'rdap.org', 'RDAP bootstrap (forwards to ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC)', ['https://rdap.org/ip/'], false,
        'Only when an administrator opens "Report" for an address, to find the abuse contact of its network. The report itself is sent by the site\'s own mail, after a person reads it.',
        [['flow' => 'outbound', 'classification' => 'the IP address being reported']]],
    ['geo', 'GitHub (this project\'s releases)', 'Country list download', ["$gh/releases/download/geo/draco-geo.bin"], false,
        'Only with the country filter on: once a month at most.',
        [['flow' => 'inbound', 'classification' => 'public IP-to-country data (CC BY 4.0)']]],
    ['crowdsec', 'CrowdSec (the site owner\'s own Local API)', 'CrowdSec bouncer', ['<crowdsec_lapi_url>/v1/decisions/stream'], true,
        'Server edition only, only when crowdsec_lapi_url and crowdsec_api_key are set: reads the decisions of the owner\'s own CrowdSec.',
        [['flow' => 'inbound', 'classification' => 'blocked addresses and ranges decided by CrowdSec']]],
];
$svc = [];
foreach ($services as [$id, $provider, $name, $endpoints, $auth, $desc, $data]) {
    $svc[] = [
        'bom-ref' => "service:$id",
        'provider' => ['name' => $provider],
        'name' => $name,
        'description' => $desc,
        'endpoints' => $endpoints,
        'authenticated' => $auth,
        'x-trust-boundary' => true,
        'data' => $data,
    ];
}
$dependencies[] = ['ref' => $coreRef, 'dependsOn' => array_map(static fn (array $s): string => $s['bom-ref'], $svc)];
$appRef = "draco-insomnis@$version";
array_unshift($dependencies, ['ref' => $appRef, 'dependsOn' => $shipped]);
$dependencies[] = ['ref' => 'geo-data', 'dependsOn' => []];

if ($shipped === []) {
    fwrite(STDERR, "no Draco packages in $dir\n");
    exit(1);
}

$bom = [
    'bomFormat' => 'CycloneDX',
    'specVersion' => '1.6',
    'serialNumber' => 'urn:uuid:' . uuid5("draco-insomnis|$version|$commit"),
    'version' => 1,
    'metadata' => [
        'timestamp' => $time,
        'lifecycles' => [['phase' => 'build']],
        'tools' => ['components' => [['type' => 'application', 'name' => 'bin/build-sbom.php', 'version' => $version, 'externalReferences' => [['type' => 'vcs', 'url' => "$gh/blob/v$version/bin/build-sbom.php"]]]]],
        'supplier' => $supplier,
        'manufacturer' => $supplier,
        'component' => [
            'type' => 'application',
            'bom-ref' => $appRef,
            'supplier' => $supplier,
            'name' => 'draco-insomnis',
            'version' => $version,
            'description' => 'Draco Insomnis: sign-up shield without captchas, application firewall, anti-copy pace limit, country filter and password rules, one package per platform from the same engines.',
            'licenses' => $license,
            'purl' => "pkg:github/$repo@v$version",
            'externalReferences' => [
                ['type' => 'vcs', 'url' => "$gh/tree/$commit"],
                ['type' => 'release-notes', 'url' => "$gh/releases/tag/v$version"],
                ['type' => 'issue-tracker', 'url' => "$gh/issues"],
                ['type' => 'security-contact', 'url' => "$gh/blob/v$version/SECURITY.md"],
            ],
            'properties' => props(['draco:commit' => $commit]),
        ],
    ],
    'components' => $components,
    'services' => $svc,
    'dependencies' => $dependencies,
    // First-party: the list is complete. Platforms (WordPress, PHP, Node.js…) are requirements, not contents.
    'compositions' => [['aggregate' => 'complete', 'assemblies' => array_merge([$coreRef], $shipped)]],
];

file_put_contents($out, json_encode($bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
fwrite(STDERR, sprintf("%s: %d packages, %d core files, %d services\n", $out, count($shipped), count($coreParts), count($svc)));
echo $out, "\n";
