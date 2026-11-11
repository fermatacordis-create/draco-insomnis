<?php
/**
 * Removing the plugin removes everything it stored: its tables and its options.
 */

declare(strict_types=1);

defined('WP_UNINSTALL_PLUGIN') || exit;

global $wpdb;
$wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'draco_events'); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'draco_blocks'); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'draco_submissions'); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

foreach (['draco_waf_enabled', 'draco_waf_mode', 'draco_waf_hide_users', 'draco_waf_xmlrpc_off', 'draco_waf_login_limit', 'draco_mfa_enabled','draco_mfa_who', 'draco_mfa_trust', 'draco_gate_schema','draco_gate_enabled', 'draco_gate_registration', 'draco_gate_comments', 'draco_mail_credit', 'draco_schema','draco_shield_enabled', 'draco_admin_ips', 'draco_secret', 'draco_hosting_nets', 'draco_proxy_header', 'draco_mail', 'draco_mail_log'] as $draco_option) {
    delete_option($draco_option);
}
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_draco\\_%' OR option_name LIKE '\\_transient\\_timeout\\_draco\\_%'"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
foreach (['_draco_trusted_devices', '_draco_recovery_email', '_draco_recovery_pending', '_draco_recovery_force'] as $draco_meta) {
    delete_metadata('user', 0, $draco_meta, '', true);
}
wp_clear_scheduled_hook('draco_cleanup');
wp_clear_scheduled_hook('draco_gate_cleanup');
