<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * The shield on the self-registration form (login/signup.php).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/engine/autoload.php');

/**
 * Adds the signed page stamp and the invisible trap to the sign-up form.
 *
 * @param MoodleQuickForm $mform
 */
function local_dracoinsomnis_extend_signup_form($mform) {
    if (!\local_dracoinsomnis\moodle_host::shield_on()) {
        return;
    }
    $shield = new \DracoInsomnis\Core\Shield(\local_dracoinsomnis\moodle_host::get());
    $mform->addElement('html', $shield->fieldsHtml(time()));
}

/**
 * Judges the sign-up before the account exists. A bot gets a plain refusal after a short wait.
 *
 * @param array $data The submitted form values.
 * @return array Errors by field.
 */
function local_dracoinsomnis_validate_extend_signup_form($data) {
    if (!\local_dracoinsomnis\moodle_host::shield_on()) {
        return [];
    }
    $host = \local_dracoinsomnis\moodle_host::get();
    $shield = new \DracoInsomnis\Core\Shield($host);
    $result = $shield->judge(\local_dracoinsomnis\moodle_host::request(), 'moodle_signup', [
        'username' => (string) ($data['username'] ?? ''),
        'email' => (string) ($data['email'] ?? ''),
        'role' => '',
    ], null, time());
    if ($result['verdict'] !== 'bot') {
        return [];
    }
    $shield->slowDown();
    return ['email' => get_string('rejected', 'local_dracoinsomnis')];
}

/**
 * Draco's password rules (minimum length, refusing breached passwords), next to Moodle's own policy.
 * Moodle asks plugins only while "Password policy" is on in Site administration > Security.
 *
 * @param string $password The new password.
 * @param stdClass|null $user Whose password it is.
 * @return string Why it is refused, or '' when it is fine.
 */
function local_dracoinsomnis_check_password_policy($password, $user = null) {
    return \DracoInsomnis\Core\Passwords::problem(\local_dracoinsomnis\moodle_host::get(), (string) $password);
}

/**
 * The country filter was switched on: download the country list if it is not there yet.
 */
function local_dracoinsomnis_geo_updated(): void {
    $host = \local_dracoinsomnis\moodle_host::get();
    if (in_array($host->setting('geo_mode'), ['block', 'allow'], true) && \DracoInsomnis\Core\Geo::built($host->setting('geo_file')) === '') {
        \DracoInsomnis\Core\GeoUpdate::update($host->setting('geo_file'));
    }
}
