<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * Install: the per-site secret and the starting settings (everything off).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

/**
 * Runs once, when the plugin is installed.
 *
 * @return bool
 */
function xmldb_local_dracoinsomnis_install() {
    set_config('secret', bin2hex(random_bytes(32)), 'local_dracoinsomnis');
    return true;
}
