<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

namespace local_dracoinsomnis\task;

defined('MOODLE_INTERNAL') || die();

/**
 * Daily: removes evidence older than 90 days, finished blocks and expired counters.
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */
class cleanup extends \core\task\scheduled_task {

    public function get_name() {
        return get_string('taskcleanup', 'local_dracoinsomnis');
    }

    public function execute() {
        \local_dracoinsomnis\store::cleanup();
    }
}
