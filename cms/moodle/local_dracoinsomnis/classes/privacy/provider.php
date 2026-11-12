<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

namespace local_dracoinsomnis\privacy;

use core_privacy\local\metadata\collection;

defined('MOODLE_INTERNAL') || die();

/**
 * Privacy: the evidence of suspicious attempts. It is not linked to Moodle accounts (most of it comes
 * from bots that never got one) and is deleted after 90 days.
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */
class provider implements \core_privacy\local\metadata\provider {

    /**
     * What is stored and why.
     *
     * @param collection $collection
     * @return collection
     */
    public static function get_metadata(collection $collection): collection {
        $collection->add_database_table('local_dracoinsomnis_events', [
            'timecreated' => 'privacy:metadata:events:timecreated',
            'ip' => 'privacy:metadata:events:ip',
            'useragent' => 'privacy:metadata:events:useragent',
            'fields' => 'privacy:metadata:events:fields',
        ], 'privacy:metadata:events');
        $collection->add_database_table('local_dracoinsomnis_blocks', [
            'value' => 'privacy:metadata:blocks:value',
        ], 'privacy:metadata:blocks');
        return $collection;
    }
}
