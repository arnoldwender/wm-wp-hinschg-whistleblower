<?php
/**
 * WM Suite HinSchG Whistleblower — Suite Hub Spoke Adapter
 *
 * Implements the WM Suite Hub contract (WM_Plugin_Module_Interface): health, telemetry,
 * the audit-chain check and the deadline check for the hub cockpit.
 *
 * @package WMCyber\HinSchG
 */

declare(strict_types=1);

namespace WMCyber\HinSchG\Adapters;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! interface_exists( 'ArnoldWender\SuiteHub\Contracts\WM_Plugin_Module_Interface' ) ) {
	return;
}

use ArnoldWender\SuiteHub\Contracts\WM_Plugin_Module_Interface;
use WMCyber\HinSchG\Core\Plugin;
use WMCyber\HinSchG\Crypto\Vault;

final class HinSchG_Spoke_Adapter implements WM_Plugin_Module_Interface {

	public function get_module_slug(): string {
		return 'wm-hinschg-whistleblower';
	}

	public function get_name(): string {
		return 'WM HinSchG Whistleblower Desk';
	}

	public function get_version(): string {
		return defined( 'WM_HINSCHG_VERSION' ) ? WM_HINSCHG_VERSION : '1.4.0';
	}

	public function get_description(): string {
		return 'Internes Meldeformular mit verschlüsselter Speicherung der Meldungen und Fristenberechnung nach § 17 HinSchG.';
	}

	public function get_health_status(): string {
		// Without the reports table or the key pair nothing can be stored: that is not "healthy" (was HEALTHY until 2026-09-15).
		if ( ! self::reports_table_exists() || '' === Plugin::instance()->get_vault()->get_public_key() ) {
			return 'NEEDS_CONFIG';
		}

		$audit = Vault::verify_audit_chain();
		if ( ! $audit['valid'] ) {
			return 'ERROR';
		}

		// status_counts(), not execute_hourly_check(): a hub page view must not fire wm_hinschg_sla_breach_detected.
		$sla = Plugin::instance()->get_sla_manager()->status_counts();
		if ( $sla['breached_ack'] > 0 || $sla['breached_feedback'] > 0 ) {
			return 'DEGRADED';
		}

		return 'HEALTHY';
	}

	private static function reports_table_exists(): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'wm_whistle_reports';
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
	}

	public function get_sbom_data(): array {
		return [
			'bom-ref'     => 'pkg:wordpress/wm-hinschg-whistleblower@' . $this->get_version(),
			'type'        => 'application',
			'name'        => $this->get_name(),
			'version'     => $this->get_version(),
			'description' => $this->get_description(),
			'scope'       => 'required',
			'hashes'      => [
				[
					'alg'     => 'SHA-256',
					'content' => hash_file( 'sha256', WM_HINSCHG_FILE ),
				],
			],
			'licenses'    => [
				[
					'license' => [
						'id' => 'GPL-2.0-or-later',
					],
				],
			],
			// No "wm:compliance:*" properties: they declared HinSchG, GoBD § 147 AO "Unveränderbarkeit" and
			// Directive 2019/1937 conformance that nothing in this plugin tests or could test.
		];
	}

	public function get_dependencies(): array {
		return [];
	}

	public function get_settings_url(): ?string {
		// The menu slug is wm-hinschg-desk (AdminDashboard::register_admin_menu); wm-hinschg-dashboard never existed.
		return admin_url( 'admin.php?page=wm-hinschg-desk' );
	}

	public function get_telemetry_metrics(): array {
		global $wpdb;
		$table_reports = $wpdb->prefix . 'wm_whistle_reports';
		if ( ! self::reports_table_exists() ) {
			// Missing data is reported as missing, not as zero cases and zero breaches.
			return [ 'reports_table' => 'missing' ];
		}

		$total_cases = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_reports} WHERE id >= %d", 0 ) );
		$sla         = Plugin::instance()->get_sla_manager()->status_counts();
		$audit       = Vault::verify_audit_chain();

		return [
			'total_cases'         => $total_cases,
			'open_cases'          => $sla['open'],
			'breached_ack_sla'    => $sla['breached_ack'],
			'breached_feed_sla'   => $sla['breached_feedback'],
			'impending_warnings'  => $sla['impending_ack'],
			// INVALID, not TAMPERED: a missing key or a legacy entry fails the check as well.
			'audit_chain_status'  => $audit['valid'] ? 'VALID' : 'INVALID',
			'verified_records'    => $audit['checked'] ?? 0,
		];
	}

	public function execute_action( string $action, array $params = [] ): array {
		switch ( $action ) {
			case 'self_test':
			case 'audit_chain':
				$audit = Vault::verify_audit_chain();
				return [
					'success' => $audit['valid'],
					'message' => $audit['valid']
						? sprintf( 'Audit-Protokoll geprüft: %d Einträge, keine nachträgliche Änderung erkennbar.', (int) ( $audit['checked'] ?? 0 ) )
						: sprintf( 'Audit-Protokoll: Prüfung fehlgeschlagen (%s).', (string) ( $audit['error'] ?? 'unbekannter Fehler' ) ),
				];

			case 'sla_check':
				$sla_manager = Plugin::instance()->get_sla_manager();
				$sla = $sla_manager->execute_hourly_check();
				$breaches = ( $sla['breached_ack'] ?? 0 ) + ( $sla['breached_feedback'] ?? 0 );
				return [
					'success' => 0 === $breaches,
					'message' => sprintf( 'Fristenprüfung abgeschlossen: %d überschrittene Fristen (Eingangsbestätigung: %d, Rückmeldung: %d).', $breaches, (int) ( $sla['breached_ack'] ?? 0 ), (int) ( $sla['breached_feedback'] ?? 0 ) ),
				];

			default:
				return [
					'success' => false,
					'message' => sprintf( 'Unbekannte Spoke-Aktion "%s".', esc_html( $action ) ),
				];
		}
	}
}
