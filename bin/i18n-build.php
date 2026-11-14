<?php
/**
 * Translations of the non-WordPress packages, from one source per language.
 *
 *   i18n/<lang>.json   {"<English text>": "<translation>"} — the English texts come from the catalogue
 *                      (bin/i18n-catalogue.php), shared by Joomla, Moodle, PrestaShop, Drupal and Laravel.
 *
 *   php bin/i18n-build.php seed           first i18n/*.json from the WordPress translations (and the
 *                                         existing Spanish of Joomla, PrestaShop and Laravel)
 *   php bin/i18n-build.php missing <lang> the English texts still to translate, as JSON
 *   php bin/i18n-build.php check          placeholders, HTML and coverage of every language
 *   php bin/i18n-build.php write          the language files of each CMS
 */
declare(strict_types=1);

$root = dirname(__DIR__);
const LANGS = [
    // key      Joomla   Moodle   PrestaShop Drupal    Laravel  WordPress
    'ar'    => ['ar-AA', 'ar',    'ar-SA',  'ar',      'ar',    'ar'],
    'bn'    => ['bn-BD', 'bn',    'bn-BD',  'bn',      'bn',    'bn_BD'],
    'ca'    => ['ca-ES', 'ca',    'ca-ES',  'ca',      'ca',    'ca'],
    'de'    => ['de-DE', 'de',    'de-DE',  'de',      'de',    'de_DE'],
    'es'    => ['es-ES', 'es',    'es-ES',  'es',      'es',    'es_ES'],
    'fa'    => ['fa-IR', 'fa',    'fa-IR',  'fa',      'fa',    'fa_IR'],
    'fr'    => ['fr-FR', 'fr',    'fr-FR',  'fr',      'fr',    'fr_FR'],
    'hi'    => ['hi-IN', 'hi',    'hi-IN',  'hi',      'hi',    'hi_IN'],
    'id'    => ['id-ID', 'id',    'id-ID',  'id',      'id',    'id_ID'],
    'it'    => ['it-IT', 'it',    'it-IT',  'it',      'it',    'it_IT'],
    'ja'    => ['ja-JP', 'ja',    'ja-JP',  'ja',      'ja',    'ja'],
    'ko'    => ['ko-KR', 'ko',    'ko-KR',  'ko',      'ko',    'ko_KR'],
    'ms'    => ['ms-MY', 'ms',    'ms-MY',  'ms',      'ms',    'ms_MY'],
    'nl'    => ['nl-NL', 'nl',    'nl-NL',  'nl',      'nl',    'nl_NL'],
    'pl'    => ['pl-PL', 'pl',    'pl-PL',  'pl',      'pl',    'pl_PL'],
    'pt_BR' => ['pt-BR', 'pt_br', 'pt-BR',  'pt-br',   'pt_BR', 'pt_BR'],
    'pt_PT' => ['pt-PT', 'pt',    'pt-PT',  'pt-pt',   'pt',    'pt_PT'],
    'ru'    => ['ru-RU', 'ru',    'ru-RU',  'ru',      'ru',    'ru_RU'],
    'sw'    => ['sw-KE', 'sw',    'sw-KE',  'sw',      'sw',    'sw'],
    'ta'    => ['ta-IN', 'ta',    'ta-IN',  'ta',      'ta',    'ta_IN'],
    'th'    => ['th-TH', 'th',    'th-TH',  'th',      'th',    'th'],
    'tl'    => ['tl-PH', 'tl',    'tl-PH',  'tl',      'tl',    'tl'],
    'tr'    => ['tr-TR', 'tr',    'tr-TR',  'tr',      'tr',    'tr_TR'],
    'uk'    => ['uk-UA', 'uk',    'uk-UA',  'uk',      'uk',    'uk'],
    'ur'    => ['ur-PK', 'ur',    'ur-PK',  'ur',      'ur',    'ur'],
    'vi'    => ['vi-VN', 'vi',    'vi-VN',  'vi',      'vi',    'vi'],
    'zh_CN' => ['zh-CN', 'zh_cn', 'zh-CN',  'zh-hans', 'zh_CN', 'zh_CN'],
];

function catalogue(string $root): array
{
    exec('php ' . escapeshellarg("$root/bin/i18n-catalogue.php"), $out, $code);
    $c = json_decode(implode("\n", $out), true);
    if ($code !== 0 || !is_array($c)) {
        fwrite(STDERR, "catalogue failed\n");
        exit(1);
    }

    return $c;
}

function load(string $root, string $lang): array
{
    $f = "$root/i18n/$lang.json";

    return is_file($f) ? (json_decode((string) file_get_contents($f), true) ?: []) : [];
}

function save(string $root, string $lang, array $t): void
{
    ksort($t);
    @mkdir("$root/i18n", 0755, true);
    file_put_contents("$root/i18n/$lang.json", json_encode($t, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
}

/** What must survive translation: printf, Moodle, Drupal and Laravel placeholders, HTML tags, entities. @return list<string> */
function marks(string $s): array
{
    preg_match_all('/%(?:\d+\$)?[sd]|\{\$a(?:->\w+)?\}|[@%]\w+|(?<![\w:]):[a-z_]+\b|<\/?[a-z][^>]*>|&\w+;/i', $s, $m);
    $out = $m[0];
    // An HTML attribute value (link target) must stay, its text may change: compare tags without attributes but href.
    $out = array_map(static fn ($x) => preg_match('/^<a\s/i', $x) ? preg_replace('/\s(?!href)\w+="[^"]*"/i', '', $x) : (preg_match('/^<\w/', $x) ? preg_replace('/\s.*>/', '>', $x) : $x), $out);
    sort($out);

    return $out;
}

$cmd = $argv[1] ?? '';
$cat = catalogue($root);
$english = array_keys($cat['strings']);

if ($cmd === 'seed') {
    foreach (LANGS as $lang => $codes) {
        $t = load($root, $lang);
        foreach ($cat['wp'][$codes[5]] ?? [] as $en => $tr) {
            $t[$en] ??= $tr;
        }
        save($root, $lang, $t);
    }
    // The Spanish already in the packages.
    $es = load($root, 'es');
    $joomla = [];
    foreach (glob("$root/cms/joomla/plg_system_dracoinsomnis/language/es-ES/*.ini") as $f) {
        $en = parse_ini_file(str_replace('es-ES', 'en-GB', $f), false, INI_SCANNER_RAW) ?: [];
        foreach (parse_ini_file($f, false, INI_SCANNER_RAW) ?: [] as $k => $v) {
            if (isset($en[$k])) {
                $es[trim($en[$k])] ??= trim($v);
            }
        }
    }
    $xlf = simplexml_load_file(glob("$root/cms/prestashop/dracoinsomnis/translations/es-ES/*.xlf")[0]);
    foreach ($xlf->xpath('//*[local-name()="trans-unit"]') as $u) {
        $es[trim((string) $u->source)] ??= trim((string) $u->target);
    }
    $enL = require "$root/cms/laravel/lang/en/messages.php";
    foreach (require "$root/cms/laravel/lang/es/messages.php" as $k => $v) {
        if (isset($enL[$k])) {
            $es[$enL[$k]] ??= $v;
        }
    }
    save($root, 'es', array_intersect_key($es, array_flip($english)));
    foreach (array_keys(LANGS) as $lang) {
        echo $lang, ': ', count(array_intersect_key(load($root, $lang), array_flip($english))), '/', count($english), "\n";
    }
    exit(0);
}

if ($cmd === 'missing') {
    $t = load($root, $argv[2] ?? '');
    echo json_encode(array_values(array_diff($english, array_keys($t))), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), "\n";
    exit(0);
}

if ($cmd === 'check') {
    $bad = 0;
    foreach (array_keys(LANGS) as $lang) {
        $t = load($root, $lang);
        $done = 0;
        foreach ($english as $en) {
            if (!isset($t[$en])) {
                continue;
            }
            $done++;
            if (marks($en) !== marks($t[$en])) {
                $bad++;
                fwrite(STDERR, "$lang: placeholders differ in \"" . substr($en, 0, 60) . "\": " . implode(' ', marks($en)) . ' ≠ ' . implode(' ', marks($t[$en])) . "\n");
            }
        }
        foreach (array_diff(array_keys($t), $english) as $old) {
            fwrite(STDERR, "$lang: not in the catalogue any more: \"" . substr($old, 0, 60) . "\"\n");
        }
        printf("%-6s %3d/%d\n", $lang, $done, count($english));
    }
    exit($bad === 0 ? 0 : 1);
}

if ($cmd === 'write') {
    $jx = "$root/cms/joomla/plg_system_dracoinsomnis";
    $enIni = [];
    foreach (glob("$jx/language/en-GB/*.ini") as $f) {
        $enIni[basename($f)] = parse_ini_file($f, false, INI_SCANNER_RAW) ?: [];
    }
    $moodle = (static function () use ($root): array {
        defined('MOODLE_INTERNAL') || define('MOODLE_INTERNAL', true);
        $string = [];
        include "$root/cms/moodle/local_dracoinsomnis/lang/en/local_dracoinsomnis.php";

        return $string;
    })();
    $laravel = require "$root/cms/laravel/lang/en/messages.php";
    $manifest = [];
    foreach (LANGS as $lang => [$jtag, $mcode, $ploc, $dcode, $lcode]) {
        $t = load($root, $lang);
        // Only complete languages ship: half-translated screens read worse than English.
        if (count(array_intersect_key($t, array_flip($english))) < count($english)) {
            continue;
        }
        $tr = static fn (string $en): ?string => isset($t[trim($en)]) && $t[trim($en)] !== '' ? $t[trim($en)] : null;

        // Joomla: complete files (English where a text is not translated yet). No straight double quotes in INI values.
        foreach ($enIni as $file => $keys) {
            $lines = ['; Draco Insomnis — ' . $jtag . ' (generated from i18n/' . $lang . '.json by bin/i18n-build.php)', '; (C) 2026 Notorius Vision. GNU General Public License version 2 or later.', ''];
            foreach ($keys as $k => $v) {
                $text = $tr($v) ?? $v;
                $text = preg_replace('/"([^"]*)"/u', '“$1”', $text) ?? $text;
                $lines[] = $k . '="' . str_replace('"', '”', $text) . '"';
            }
            @mkdir("$jx/language/$jtag", 0755, true);
            file_put_contents("$jx/language/$jtag/" . str_replace('en-GB', $jtag, $file), implode("\n", $lines) . "\n");
            $manifest[] = "\t\t<language tag=\"$jtag\">language/$jtag/$file</language>";
        }

        // Moodle: only what is translated (Moodle falls back to English), keys in order.
        $out = [];
        foreach ($moodle as $k => $v) {
            if (($x = $tr($v)) !== null) {
                $out[$k] = $x;
            }
        }
        ksort($out);
        $php = "<?php\n// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis\n//\n// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the\n// GNU General Public License as published by the Free Software Foundation, either version 2 of the\n// License, or (at your option) any later version.\n\n/**\n * Strings for component 'local_dracoinsomnis', language '$mcode' (generated from i18n/$lang.json).\n *\n * @package    local_dracoinsomnis\n * @copyright  2026 Notorius Vision\n * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later\n */\n\ndefined('MOODLE_INTERNAL') || die();\n\n";
        foreach ($out as $k => $v) {
            $php .= '$string[\'' . $k . '\'] = \'' . str_replace(['\\', "'"], ['\\\\', "\\'"], $v) . "';\n";
        }
        @mkdir("$root/cms/moodle/local_dracoinsomnis/lang/$mcode", 0755, true);
        file_put_contents("$root/cms/moodle/local_dracoinsomnis/lang/$mcode/local_dracoinsomnis.php", $php);

        // PrestaShop: the XLIFF catalogue of the module.
        $units = '';
        $id = 0;
        foreach ($cat['strings'] as $en => $where) {
            if (!preg_grep('/^prestashop/', $where) || ($x = $tr($en)) === null) {
                continue;
            }
            $id++;
            $units .= "      <trans-unit id=\"$id\">\n        <source>" . htmlspecialchars($en, ENT_XML1) . "</source>\n        <target>" . htmlspecialchars($x, ENT_XML1) . "</target>\n      </trans-unit>\n";
        }
        @mkdir("$root/cms/prestashop/dracoinsomnis/translations/$ploc", 0755, true);
        file_put_contents("$root/cms/prestashop/dracoinsomnis/translations/$ploc/ModulesDracoinsomnisAdmin.$ploc.xlf",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xliff xmlns=\"urn:oasis:names:tc:xliff:document:1.2\" version=\"1.2\">\n  <file original=\"modules/dracoinsomnis\" source-language=\"en-US\" target-language=\"$ploc\" datatype=\"plaintext\">\n    <body>\n$units    </body>\n  </file>\n</xliff>\n");

        // Drupal: one .po per language, imported by the locale module.
        $po = "# Draco Insomnis for Drupal — $dcode (generated from i18n/$lang.json)\nmsgid \"\"\nmsgstr \"\"\n\"Content-Type: text/plain; charset=UTF-8\\n\"\n\"Content-Transfer-Encoding: 8bit\\n\"\n\"Language: $dcode\\n\"\n\n";
        $q = static fn (string $s): string => '"' . str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], $s) . '"';
        foreach ($cat['strings'] as $en => $where) {
            if (preg_grep('/^drupal/', $where) && ($x = $tr($en)) !== null) {
                $po .= 'msgid ' . $q($en) . "\nmsgstr " . $q($x) . "\n\n";
            }
        }
        @mkdir("$root/cms/drupal/draco_insomnis/translations", 0755, true);
        file_put_contents("$root/cms/drupal/draco_insomnis/translations/$dcode.po", $po);

        // Laravel: the package's lang folder.
        $out = [];
        foreach ($laravel as $k => $v) {
            if (($x = $tr($v)) !== null) {
                $out[$k] = $x;
            }
        }
        $php = "<?php\n\n// Generated from i18n/$lang.json by bin/i18n-build.php.\nreturn [\n";
        foreach ($out as $k => $v) {
            $php .= "    '" . $k . "' => '" . str_replace(['\\', "'"], ['\\\\', "\\'"], $v) . "',\n";
        }
        @mkdir("$root/cms/laravel/lang/$lcode", 0755, true);
        file_put_contents("$root/cms/laravel/lang/$lcode/messages.php", $php . "];\n");
    }

    // Joomla manifest: English plus every language written.
    $xml = (string) file_get_contents("$jx/dracoinsomnis.xml");
    $list = "\t<languages>\n\t\t<language tag=\"en-GB\">language/en-GB/plg_system_dracoinsomnis.ini</language>\n\t\t<language tag=\"en-GB\">language/en-GB/plg_system_dracoinsomnis.sys.ini</language>\n" . implode("\n", $manifest) . "\n\t</languages>";
    file_put_contents("$jx/dracoinsomnis.xml", preg_replace('#\t<languages>.*?</languages>#s', $list, $xml));
    echo 'written: ', count($manifest) / 2, " complete languages × 5 CMS\n";
    exit(0);
}

fwrite(STDERR, "usage: php bin/i18n-build.php seed | missing <lang> | check | write\n");
exit(1);
