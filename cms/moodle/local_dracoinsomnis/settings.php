<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Settings, under Site administration > Plugins > Local plugins, and the evidence page.
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

if ($hassiteconfig) {
    $settings = new admin_settingpage('local_dracoinsomnis', get_string('pluginname', 'local_dracoinsomnis'));
    $modes = [
        'off' => get_string('modeoff', 'local_dracoinsomnis'),
        'log' => get_string('modelog', 'local_dracoinsomnis'),
        'block' => get_string('modeblock', 'local_dracoinsomnis'),
    ];
    $settings->add(new admin_setting_heading('local_dracoinsomnis/intro', '',
        get_string('intro', 'local_dracoinsomnis', (new moodle_url('/local/dracoinsomnis/evidence.php'))->out(false))));
    $settings->add(new admin_setting_configcheckbox('local_dracoinsomnis/shield',
        get_string('shield', 'local_dracoinsomnis'), get_string('shield_desc', 'local_dracoinsomnis'), 0));
    $settings->add(new admin_setting_configselect('local_dracoinsomnis/waf_mode',
        get_string('waf', 'local_dracoinsomnis'), get_string('waf_desc', 'local_dracoinsomnis'), 'off', $modes));
    $settings->add(new admin_setting_configselect('local_dracoinsomnis/pace_mode',
        get_string('pace', 'local_dracoinsomnis'), get_string('pace_desc', 'local_dracoinsomnis'), 'off', $modes));
    $settings->add(new admin_setting_configtext('local_dracoinsomnis/anticopy_rate_ip',
        get_string('rateip', 'local_dracoinsomnis'), '', 120, PARAM_INT));
    $settings->add(new admin_setting_configtext('local_dracoinsomnis/anticopy_rate_net',
        get_string('ratenet', 'local_dracoinsomnis'), get_string('ratenet_desc', 'local_dracoinsomnis'), 600, PARAM_INT));
    $settings->add(new admin_setting_configselect('local_dracoinsomnis/proxy_header',
        get_string('proxy', 'local_dracoinsomnis'), get_string('proxy_desc', 'local_dracoinsomnis'), '', [
            '' => get_string('proxynone', 'local_dracoinsomnis'),
            'cf' => get_string('proxycf', 'local_dracoinsomnis'),
            'xff' => get_string('proxyxff', 'local_dracoinsomnis'),
        ]));
    $settings->add(new admin_setting_configtextarea('local_dracoinsomnis/hosting_nets',
        get_string('nets', 'local_dracoinsomnis'), get_string('nets_desc', 'local_dracoinsomnis'), '', PARAM_RAW_TRIMMED, 60, 4));
    $ADMIN->add('localplugins', $settings);

    $ADMIN->add('localplugins', new admin_externalpage('local_dracoinsomnis_evidence',
        get_string('evidence', 'local_dracoinsomnis'), new moodle_url('/local/dracoinsomnis/evidence.php'), 'moodle/site:config'));
}
