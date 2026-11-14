<?php
/**
 * Every English text of the non-WordPress packages, in one catalogue, to translate them once for all.
 *   php bin/i18n-catalogue.php > catalogue.json
 * Output: {"strings": {"<english>": ["joomla:KEY", "moodle:key", …]}, "wp": {"<locale>": {"<english>": "<translation>"}}}
 * The "wp" part has the WordPress translations of the same English texts, when there are.
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$strings = [];
$add = static function (string $english, string $where) use (&$strings): void {
    $english = trim($english);
    if ($english !== '') {
        $strings[$english][] = $where;
    }
};

// Joomla: INI files.
foreach (glob("$root/cms/joomla/plg_system_dracoinsomnis/language/en-GB/*.ini") as $file) {
    foreach (parse_ini_file($file, false, INI_SCANNER_RAW) ?: [] as $key => $value) {
        $add((string) $value, 'joomla:' . basename($file) . ':' . $key);
    }
}

// Moodle: $string[] array (the file stops unless MOODLE_INTERNAL is defined).
define('MOODLE_INTERNAL', true);
$string = [];
include "$root/cms/moodle/local_dracoinsomnis/lang/en/local_dracoinsomnis.php";
foreach ($string as $key => $value) {
    $add($value, 'moodle:' . $key);
}

// Laravel: messages.php.
foreach (require "$root/cms/laravel/lang/en/messages.php" as $key => $value) {
    $add($value, 'laravel:' . $key);
}

// PrestaShop: the sources of the xlf catalogue (English is the source language).
$xlf = simplexml_load_file(glob("$root/cms/prestashop/dracoinsomnis/translations/es-ES/*.xlf")[0]);
$xlf->registerXPathNamespace('x', 'urn:oasis:names:tc:xliff:document:1.2');
foreach ($xlf->xpath('//x:source') ?: $xlf->xpath('//source') as $source) {
    $add((string) $source, 'prestashop');
}

// Drupal: t('…') and $this->t('…') literals (single or double quotes) in PHP code.
$files = array_merge(glob("$root/cms/drupal/draco_insomnis/*.module"), glob("$root/cms/drupal/draco_insomnis/src/{,*/,*/*/}*.php", GLOB_BRACE));
foreach ($files as $file) {
    $tokens = token_get_all((string) file_get_contents($file));
    foreach ($tokens as $i => $tok) {
        if (is_array($tok) && $tok[0] === T_STRING && in_array($tok[1], ['t', 'formatPlural'], true)) {
            $j = $i + 1;
            while (isset($tokens[$j]) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                $j++;
            }
            if (($tokens[$j] ?? null) !== '(') {
                continue;
            }
            $j++;
            while (isset($tokens[$j]) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                $j++;
            }
            if (is_array($tokens[$j] ?? null) && $tokens[$j][0] === T_CONSTANT_ENCAPSED_STRING) {
                $add((string) eval('return ' . $tokens[$j][1] . ';'), 'drupal');
            }
        }
    }
}
// Drupal YAML labels shown to the site's owner.
foreach (['draco_insomnis.info.yml' => ['name', 'description'], 'draco_insomnis.links.menu.yml' => ['title', 'description'], 'draco_insomnis.permissions.yml' => ['title', 'description'], 'draco_insomnis.routing.yml' => ['_title']] as $yml => $keys) {
    foreach (file("$root/cms/drupal/draco_insomnis/$yml") ?: [] as $line) {
        if (preg_match('/^\s*(' . implode('|', $keys) . "):\s*'?(.*?)'?\s*$/", $line, $m) && $m[2] !== '') {
            $add(str_replace("''", "'", $m[2]), 'drupal:yml');
        }
    }
}

// WordPress translations of the same texts.
$wp = [];
foreach (glob("$root/languages/draco-insomnis-*.l10n.php") as $file) {
    $locale = preg_replace('/^draco-insomnis-(.+)\.l10n\.php$/', '$1', basename($file));
    $messages = (require $file)['messages'] ?? [];
    foreach ($strings as $english => $where) {
        if (isset($messages[$english]) && is_string($messages[$english]) && $messages[$english] !== '') {
            $wp[$locale][$english] = $messages[$english];
        }
    }
}

echo json_encode(['strings' => $strings, 'wp' => $wp], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), "\n";
