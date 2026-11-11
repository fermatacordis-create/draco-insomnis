<?php
/**
 * Plugin Name: Draco CI mail capture
 * Description: Test sites only. Writes every outgoing e-mail to wp-content/ci-mail.jsonl instead of sending it.
 */
defined('ABSPATH') || exit;

add_filter('pre_wp_mail', static function ($return, array $atts) {
    if ($return !== null) {
        return $return;
    }
    file_put_contents(WP_CONTENT_DIR . '/ci-mail.jsonl', wp_json_encode([
        'to' => $atts['to'] ?? '',
        'subject' => $atts['subject'] ?? '',
        'message' => $atts['message'] ?? '',
    ]) . "\n", FILE_APPEND | LOCK_EX);

    return true;
}, 2000, 2);
