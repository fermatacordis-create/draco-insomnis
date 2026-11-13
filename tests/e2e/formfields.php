<?php
// Reads an HTML page on stdin and prints the fields of the form with the given id as a query string,
// with the values a browser would send by default (hidden, text, selected options, checked boxes).
// Usage: php draco-formfields.php <form-id> < page.html
$html = stream_get_contents(STDIN);
$doc = new DOMDocument();
@$doc->loadHTML($html);
$xp = new DOMXPath($doc);
// An id, or an XPath when it starts with "//".
$form = $xp->query(str_starts_with($argv[1], '//') ? $argv[1] : '//form[@id="' . $argv[1] . '"]')->item(0);
if (!$form) {
    exit(1);
}
$out = [];
foreach ($xp->query('.//input[@name]|.//select[@name]|.//textarea[@name]', $form) as $el) {
    $name = $el->getAttribute('name');
    $tag = strtolower($el->nodeName);
    if ($tag === 'select') {
        $selected = $xp->query('.//option[@selected]', $el)->item(0) ?? $xp->query('.//option', $el)->item(0);
        $out[] = rawurlencode($name) . '=' . rawurlencode($selected ? $selected->getAttribute('value') : '');
    } elseif ($tag === 'textarea') {
        $out[] = rawurlencode($name) . '=' . rawurlencode($el->textContent);
    } else {
        $type = strtolower($el->getAttribute('type') ?: 'text');
        if (in_array($type, ['submit', 'button', 'file', 'image', 'reset'], true)) {
            continue;
        }
        if (in_array($type, ['checkbox', 'radio'], true) && !$el->hasAttribute('checked')) {
            continue;
        }
        $out[] = rawurlencode($name) . '=' . rawurlencode($el->getAttribute('value'));
    }
}
echo implode('&', $out);
