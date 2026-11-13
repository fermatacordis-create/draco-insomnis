<?php

declare(strict_types=1);

/*
 * Turns the DB-IP "IP to Country Lite" CSV (https://db-ip.com/db/lite.php, CC BY 4.0) into the compact
 * file src/Core/Geo.php reads: no PHP extension needed, a few MB, looked up with a binary search.
 *
 *   php bin/build-geo.php dbip-country-lite-YYYY-MM.csv.gz draco-geo.bin
 *
 * Format: "DRGEO1" · built YYYYMMDD (8) · IPv4 count (uint32 BE) · IPv6 count (uint32 BE) · IPv4 records
 * (start 4 bytes + country 2) · IPv6 records (start 16 bytes + country 2). Records are sorted by start;
 * each one runs until the next start. Gaps and unknown ranges get "--". Neighbouring ranges of the same
 * country are merged.
 */

[$self, $in, $out] = $argv + [null, null, null];
if ($in === null || $out === null) {
    fwrite(STDERR, "usage: php bin/build-geo.php <dbip-country-lite.csv[.gz]> <out.bin>\n");
    exit(1);
}
$fh = str_ends_with($in, '.gz') ? gzopen($in, 'rb') : fopen($in, 'rb');
if ($fh === false) {
    fwrite(STDERR, "cannot open $in\n");
    exit(1);
}
$tables = ['4' => [], '6' => []];
$last = ['4' => null, '6' => null];
$rows = 0;
while (($line = fgets($fh)) !== false) {
    $parts = str_getcsv(trim($line), ',', '"', '');
    if (count($parts) < 3) {
        continue;
    }
    [$from, $to, $cc] = $parts;
    $start = @inet_pton($from);
    $end = @inet_pton($to);
    if ($start === false || $end === false || strlen($start) !== strlen($end)) {
        continue;
    }
    $rows++;
    $fam = strlen($start) === 4 ? '4' : '6';
    $cc = preg_match('/^[A-Z]{2}$/', $cc) === 1 && $cc !== 'ZZ' ? $cc : '--';
    $prevEnd = $last[$fam];
    if ($prevEnd !== null && strcmp($start, inc($prevEnd)) > 0) {
        add($tables[$fam], inc($prevEnd), '--'); // a gap in the list
    }
    add($tables[$fam], $start, $cc);
    $last[$fam] = $end;
}
fclose($fh);
if ($rows < 100000) {
    fwrite(STDERR, "only $rows rows: refusing to build a partial file\n");
    exit(1);
}
$bin = 'DRGEO1' . gmdate('Ymd') . pack('NN', count($tables['4']), count($tables['6']));
foreach (['4', '6'] as $fam) {
    foreach ($tables[$fam] as [$start, $cc]) {
        $bin .= $start . $cc;
    }
}
file_put_contents($out, $bin);
printf("%d rows → IPv4 %d, IPv6 %d records, %.1f MB\n", $rows, count($tables['4']), count($tables['6']), strlen($bin) / 1048576);

/** @param list<array{0: string, 1: string}> $table */
function add(array &$table, string $start, string $cc): void
{
    $n = count($table);
    if ($n > 0 && $table[$n - 1][1] === $cc) {
        return; // same country as the range before: merged
    }
    $table[] = [$start, $cc];
}

function inc(string $bin): string
{
    for ($i = strlen($bin) - 1; $i >= 0; $i--) {
        $byte = ord($bin[$i]);
        if ($byte < 255) {
            return substr($bin, 0, $i) . chr($byte + 1) . str_repeat("\0", strlen($bin) - $i - 1);
        }
    }

    return $bin; // the very last address
}
