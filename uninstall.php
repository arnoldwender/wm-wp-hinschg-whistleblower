<?php
/**
 * WM HinSchG Whistleblower Desk — uninstaller.
 *
 * Runs when the plugin is deleted in wp-admin. It removes the reports, the messages, the audit log,
 * the key pair and the rate-limit counters: after this the stored reports are gone for good.
 *
 * Until 2026-09-15 it deleted wm_hinschg_notification_email and wm_hinschg_tip_hash, which no code
 * writes, and left wm_whistle_audit_tip (the chain tip) and wm_hinschg_settings behind.
 *
 * Wrapped in a closure so no variable lands in the global scope (Plugin Check flags every one).
 *
 * @package WMCyber\HinSchG
 */

declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

( static function (): void {
	global $wpdb;

	$delete_all = '1' === (string) get_option( 'wm_hinschg_delete_data_on_uninstall', '0' );

	// Ephemeral options and legacy unused settings are always cleaned on uninstall.
	foreach ( [ 'wm_hinschg_settings', 'wm_hinschg_delete_data_on_uninstall' ] as $ephemeral ) {
		delete_option( $ephemeral );
		delete_site_option( $ephemeral );
	}

	wp_clear_scheduled_hook( 'wm_hinschg_hourly_sla_check' );

	// Rate-limit counters (RateLimiter: wm_hinschg_rl_<bucket>_<hash>), one-time test-report token, and offline key transient.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_wm_hinschg_rl_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_wm_hinschg_rl_' ) . '%',
			$wpdb->esc_like( '_transient_wm_hinschg_test_report_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_wm_hinschg_test_report_' ) . '%',
			$wpdb->esc_like( '_transient_wm_hinschg_offline_key_once' ) . '%',
			$wpdb->esc_like( '_transient_timeout_wm_hinschg_offline_key_once' ) . '%'
		)
	);

	// Statutory 3-year documentation retention (§ 11 Abs. 5 HinSchG): reports, messages, audit log,
	// key pair and Meldestelle role are preserved by default unless the administrator opted into full deletion.
	if ( ! $delete_all ) {
		return;
	}

	// The role and the capability the plugin brought with it. Required by hand: the uninstaller runs
	// without the plugin's autoloader.
	require_once __DIR__ . '/includes/Security/Capabilities.php';
	\WMCyber\HinSchG\Security\Capabilities::remove();

	// Options the plugin writes: the key pair (Schema::activate), the chain tip (Vault::AUDIT_TIP_OPTION),
	// and the settings array the removed settings tab stored on installs that saved it.
	foreach ( [ 'wm_hinschg_public_key', 'wm_hinschg_recovery_public_key', 'wm_hinschg_private_key', 'wm_whistle_audit_tip', 'wm_hinschg_db_version', 'wm_hinschg_settings', 'wm_hinschg_delete_data_on_uninstall' ] as $option ) {
		delete_option( $option );
		delete_site_option( $option );
	}

	foreach ( [ 'wm_whistle_messages', 'wm_whistle_reports', 'wm_whistle_audit_log' ] as $table ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$table}" );
	}
} )();
