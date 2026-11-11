<?php
/**
 * Removing the plugin removes everything it stored: its tables and its options.
 */

declare(strict_types=1);

defined('WP_UNINSTALL_PLUGIN') || exit;

global $wpdb;
$wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'draco_events'); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'draco_blocks'); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

foreach (['draco_schema', 'draco_shield_enabled', 'draco_admin_ips', 'draco_secret', 'draco_hosting_nets', 'draco_proxy_header', 'draco_mail', 'draco_mail_log'] as $option) {
    delete_option($option);
}
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_draco\\_%' OR option_name LIKE '\\_transient\\_timeout\\_draco\\_%'"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
wp_clear_scheduled_hook('draco_cleanup');
