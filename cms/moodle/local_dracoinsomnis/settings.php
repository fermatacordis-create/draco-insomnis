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
    $settings->add(new admin_setting_configtextarea('local_dracoinsomnis/trusted_proxies',
        get_string('trusted', 'local_dracoinsomnis'), get_string('trusted_desc', 'local_dracoinsomnis'), '', PARAM_RAW_TRIMMED, 60, 2));
    $settings->add(new admin_setting_configtextarea('local_dracoinsomnis/hosting_nets',
        get_string('nets', 'local_dracoinsomnis'), get_string('nets_desc', 'local_dracoinsomnis'), '', PARAM_RAW_TRIMMED, 60, 4));
    $settings->add(new admin_setting_heading('local_dracoinsomnis/geoheading', get_string('geo', 'local_dracoinsomnis'),
        get_string('geo_desc', 'local_dracoinsomnis')));
    $geomode = new admin_setting_configselect('local_dracoinsomnis/geo_mode', get_string('geomode', 'local_dracoinsomnis'), '', 'off', [
        'off' => get_string('modeoff', 'local_dracoinsomnis'),
        'block' => get_string('georefuse', 'local_dracoinsomnis'),
        'allow' => get_string('geoonly', 'local_dracoinsomnis'),
    ]);
    $geomode->set_updatedcallback('local_dracoinsomnis_geo_updated');
    $settings->add($geomode);
    $settings->add(new admin_setting_configselect('local_dracoinsomnis/geo_scope', get_string('geoscope', 'local_dracoinsomnis'), '', 'sensitive', [
        'sensitive' => get_string('geosensitive', 'local_dracoinsomnis'),
        'site' => get_string('geosite', 'local_dracoinsomnis'),
    ]));
    $settings->add(new admin_setting_configselect('local_dracoinsomnis/geo_action', get_string('geoaction', 'local_dracoinsomnis'), '', 'log', [
        'log' => get_string('modelog', 'local_dracoinsomnis'),
        'block' => get_string('modeblock', 'local_dracoinsomnis'),
    ]));
    $settings->add(new admin_setting_configtext('local_dracoinsomnis/geo_countries', get_string('geocountries', 'local_dracoinsomnis'),
        get_string('geocredit', 'local_dracoinsomnis'), '', PARAM_TEXT));
    $settings->add(new admin_setting_configcheckbox('local_dracoinsomnis/headers', get_string('headers', 'local_dracoinsomnis'),
        get_string('headers_desc', 'local_dracoinsomnis'), 0));
    $settings->add(new admin_setting_configcheckbox('local_dracoinsomnis/hsts', get_string('hsts', 'local_dracoinsomnis'),
        get_string('hsts_desc', 'local_dracoinsomnis'), 0));
    $settings->add(new admin_setting_configtext('local_dracoinsomnis/pwd_min', get_string('pwdmin', 'local_dracoinsomnis'),
        get_string('pwdmin_desc', 'local_dracoinsomnis'), 0, PARAM_INT));
    $settings->add(new admin_setting_configcheckbox('local_dracoinsomnis/pwd_breached', get_string('pwdbreached', 'local_dracoinsomnis'),
        get_string('pwdbreached_desc', 'local_dracoinsomnis'), 0));
    $ADMIN->add('localplugins', $settings);

    $ADMIN->add('localplugins', new admin_externalpage('local_dracoinsomnis_evidence',
        get_string('evidence', 'local_dracoinsomnis'), new moodle_url('/local/dracoinsomnis/evidence.php'), 'moodle/site:config'));
}
