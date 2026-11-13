<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * The block list (with unblock) and the last suspicious attempts (with a CSV per address).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');

use local_dracoinsomnis\moodle_host;
use local_dracoinsomnis\store;

admin_externalpage_setup('local_dracoinsomnis_evidence');

$action = optional_param('action', '', PARAM_ALPHA);
if ($action === 'unblock') {
    require_sesskey();
    store::unblock(required_param('id', PARAM_INT));
    redirect($PAGE->url, get_string('unblocked', 'local_dracoinsomnis'));
}
if ($action === 'block') {
    require_sesskey();
    $value = required_param('blockvalue', PARAM_RAW_TRIMMED);
    $days = required_param('blockdays', PARAM_INT);
    $reason = optional_param('blockreason', '', PARAM_TEXT);
    $done = (new store())->block('ip', $value, $days, $reason);
    redirect($PAGE->url, $done ? get_string('blockdone', 'local_dracoinsomnis', s($value)) : get_string('blockrefused', 'local_dracoinsomnis'),
        null, $done ? \core\output\notification::NOTIFY_SUCCESS : \core\output\notification::NOTIFY_ERROR);
}
if ($action === 'csv') {
    require_sesskey();
    $ip = required_param('ip', PARAM_RAW_TRIMMED);
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        throw new moodle_exception('invalidparameter');
    }
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="draco-evidence-' . str_replace(':', '-', $ip) . '.csv"');
    header('Cache-Control: no-store');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['created_at_utc', 'ip', 'remote_addr', 'endpoint', 'verdict', 'score', 'reasons', 'user_agent', 'fields'], ',', '"', '\\');
    foreach (store::by_ip($ip) as $row) {
        fputcsv($out, [gmdate('Y-m-d H:i:s', (int) $row->timecreated), $row->ip, $row->remoteaddr, $row->endpoint, $row->verdict,
            $row->score, $row->reasons, $row->useragent, $row->fields], ',', '"', '\\');
    }
    fclose($out);
    die();
}

echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('evidence', 'local_dracoinsomnis'));
$request = moodle_host::request();
echo html_writer::tag('p', get_string('yourip', 'local_dracoinsomnis', (object) [
    'ip' => s($request->via(moodle_host::get())),
    'remote' => s($request->remote()),
]));
$host = moodle_host::get();
if ($request->proxyHeaderIgnored($host->setting('proxy_header'), $host->setting('trusted_proxies'))) {
    echo $OUTPUT->notification(get_string('proxyignored', 'local_dracoinsomnis', s($request->remote())), 'warning');
}

echo $OUTPUT->heading(get_string('blocks', 'local_dracoinsomnis'), 3);
$blocks = store::active_blocks();
if (!$blocks) {
    echo html_writer::tag('p', get_string('noblocks', 'local_dracoinsomnis'));
} else {
    $table = new html_table();
    $table->head = [get_string('colvalue', 'local_dracoinsomnis'), get_string('colreason', 'local_dracoinsomnis'),
        get_string('coluntil', 'local_dracoinsomnis'), ''];
    foreach ($blocks as $row) {
        $url = new moodle_url($PAGE->url, ['action' => 'unblock', 'id' => $row->id, 'sesskey' => sesskey()]);
        $until = \DracoInsomnis\Core\Blocklist::isForever((int) $row->timeuntil) ? get_string('forever', 'local_dracoinsomnis') : gmdate('Y-m-d H:i', (int) $row->timeuntil);
        $table->data[] = [html_writer::tag('code', s($row->value)), s($row->reason), $until,
            html_writer::link($url, get_string('unblock', 'local_dracoinsomnis'), ['class' => 'btn btn-sm btn-secondary'])];
    }
    echo html_writer::table($table);
}

echo $OUTPUT->heading(get_string('blockadd', 'local_dracoinsomnis'), 4);
echo html_writer::tag('p', get_string('blockadd_desc', 'local_dracoinsomnis'), ['class' => 'text-muted']);
$days = [7 => get_string('days7', 'local_dracoinsomnis'), 15 => get_string('days15', 'local_dracoinsomnis'),
    30 => get_string('days30', 'local_dracoinsomnis'), 90 => get_string('days90', 'local_dracoinsomnis'), 0 => get_string('forever', 'local_dracoinsomnis')];
echo html_writer::start_tag('form', ['method' => 'post', 'action' => $PAGE->url->out(false), 'class' => 'form-inline mb-4']);
echo html_writer::empty_tag('input', ['type' => 'hidden', 'name' => 'sesskey', 'value' => sesskey()]);
echo html_writer::empty_tag('input', ['type' => 'hidden', 'name' => 'action', 'value' => 'block']);
echo html_writer::empty_tag('input', ['type' => 'text', 'name' => 'blockvalue', 'required' => 'required', 'class' => 'form-control mr-2',
    'placeholder' => get_string('blockvalue', 'local_dracoinsomnis'), 'aria-label' => get_string('blockvalue', 'local_dracoinsomnis')]);
echo html_writer::select($days, 'blockdays', 30, false, ['class' => 'custom-select mr-2', 'aria-label' => get_string('blockdays', 'local_dracoinsomnis')]);
echo html_writer::empty_tag('input', ['type' => 'text', 'name' => 'blockreason', 'class' => 'form-control mr-2',
    'placeholder' => get_string('colreason', 'local_dracoinsomnis'), 'aria-label' => get_string('colreason', 'local_dracoinsomnis')]);
echo html_writer::empty_tag('input', ['type' => 'submit', 'value' => get_string('block', 'local_dracoinsomnis'), 'class' => 'btn btn-secondary']);
echo html_writer::end_tag('form');

echo $OUTPUT->heading(get_string('events', 'local_dracoinsomnis'), 3);
echo html_writer::tag('p', get_string('events_help', 'local_dracoinsomnis'), ['class' => 'text-muted']);
$events = store::recent(50);
if (!$events) {
    echo html_writer::tag('p', get_string('noevents', 'local_dracoinsomnis'));
} else {
    $table = new html_table();
    $table->head = [get_string('coldate', 'local_dracoinsomnis'), get_string('colip', 'local_dracoinsomnis'),
        get_string('colwhere', 'local_dracoinsomnis'), get_string('colverdict', 'local_dracoinsomnis'),
        get_string('colsigns', 'local_dracoinsomnis'), get_string('coldata', 'local_dracoinsomnis'), ''];
    foreach ($events as $row) {
        $fields = json_decode((string) $row->fields, true);
        $data = is_array($fields) ? implode(' · ', array_filter(array_map('strval', $fields))) : '';
        $badge = $row->verdict === 'bot' ? 'bg-danger' : 'bg-warning text-dark';
        $csv = new moodle_url($PAGE->url, ['action' => 'csv', 'ip' => $row->ip, 'sesskey' => sesskey()]);
        $table->data[] = [gmdate('Y-m-d H:i:s', (int) $row->timecreated), html_writer::tag('code', s($row->ip)), s($row->endpoint),
            html_writer::span(s($row->verdict), 'badge ' . $badge), s(str_replace(',', ', ', $row->reasons)),
            s(core_text::substr($data, 0, 70)), html_writer::link($csv, 'CSV', ['class' => 'btn btn-sm btn-secondary'])];
    }
    echo html_writer::table($table);
}
echo $OUTPUT->footer();
