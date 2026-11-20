<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\HinSchG\Crypto\Vault;
use WMCyber\HinSchG\Compliance\HinSchGSlaManager;
use WMCyber\HinSchG\Compliance\CaseStatus;
use WMCyber\HinSchG\Compliance\ReportCategories;
use WMCyber\HinSchG\Security\Capabilities;

/**
 * The HinSchG desk in wp-admin and its dashboard widget.
 *
 * Until 2026-09-15 the desk was Spanish, showed a fixed "0 Retrasos" for both deadlines and three status badges
 * ("CANAL ACTIVO Y PROTEGIDO", "CIFRADO AES-256", "CONTROL DE PLAZOS OK") whatever the data said, told site owners
 * to paste a shortcode that is not registered, and had a settings tab whose values no code read. Everything shown
 * here is counted from the reports table or states what the code does.
 */
final class AdminDashboard {
	public function __construct(
		private readonly Vault $vault,
		private readonly HinSchGSlaManager $sla_manager
	) {}

	public function init(): void {
		add_action( 'admin_menu', [ $this, 'register_admin_menu' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );
		add_action( 'admin_init', [ $this, 'handle_form_actions' ] );
		add_action( 'wp_dashboard_setup', [ $this, 'register_dashboard_widget' ] );
	}

	public function register_dashboard_widget(): void {
		if ( ! Capabilities::may_read() ) {
			return;
		}

		wp_add_dashboard_widget(
			'wm_hinschg_widget',
			__( 'WM HinSchG — Meldestelle', 'wm-hinschg-whistleblower' ),
			[ $this, 'render_dashboard_widget' ]
		);
	}

	/** Reports table present on this install. */
	private function reports_table_exists(): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'wm_whistle_reports';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
	}

	public function render_dashboard_widget(): void {
		global $wpdb;
		$table_reports = $wpdb->prefix . 'wm_whistle_reports';
		$count         = 0;
		$counts        = [ 'breached_ack' => 0, 'breached_feedback' => 0, 'impending_ack' => 0, 'open' => 0 ];
		$has_table     = $this->reports_table_exists();
		if ( $has_table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$count  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_reports} WHERE id >= %d", 0 ) );
			$counts = $this->sla_manager->status_counts();
		}
		$overdue = $counts['breached_ack'] + $counts['breached_feedback'];
		?>
		<div class="wm-dash-widget-box" data-wm-theme="<?php echo esc_attr( function_exists( 'wm_get_suite_theme' ) ? wm_get_suite_theme() : 'cyber-events' ); ?>">
			<div class="wm-dash-banner <?php echo ( $has_table && 0 === $overdue ) ? 'is-valid' : 'is-warning'; ?>">
				<span class="wm-dash-banner-icon"><span class="dashicons dashicons-megaphone" aria-hidden="true"></span></span>
				<div>
					<div class="wm-dash-banner-title">
						<?php
						if ( ! $has_table ) {
							esc_html_e( 'Tabelle der Meldungen fehlt (Plugin neu aktivieren)', 'wm-hinschg-whistleblower' );
						} elseif ( $overdue > 0 ) {
							/* translators: %d: number of passed deadlines */
							echo esc_html( sprintf( _n( '%d Frist überschritten', '%d Fristen überschritten', $overdue, 'wm-hinschg-whistleblower' ), $overdue ) );
						} else {
							esc_html_e( 'Keine Frist überschritten', 'wm-hinschg-whistleblower' );
						}
						?>
					</div>
					<div class="wm-dash-banner-sub"><?php esc_html_e( 'Eingangsbestätigung nach 7 Tagen, Rückmeldung nach 3 Monaten (§ 17 HinSchG)', 'wm-hinschg-whistleblower' ); ?></div>
				</div>
			</div>

			<div class="wm-dash-kpi-grid">
				<div class="wm-dash-kpi-card">
					<div class="wm-dash-kpi-val"><?php echo esc_html( (string) $count ); ?></div>
					<div class="wm-dash-kpi-lbl"><?php esc_html_e( 'Vorgänge', 'wm-hinschg-whistleblower' ); ?></div>
				</div>
				<div class="wm-dash-kpi-card">
					<div class="wm-dash-kpi-val"><?php echo esc_html( (string) $counts['open'] ); ?></div>
					<div class="wm-dash-kpi-lbl"><?php esc_html_e( 'Offen', 'wm-hinschg-whistleblower' ); ?></div>
				</div>
				<div class="wm-dash-kpi-card">
					<div class="wm-dash-kpi-val <?php echo $overdue > 0 ? 'is-off' : 'is-on'; ?>"><?php echo esc_html( (string) $overdue ); ?></div>
					<div class="wm-dash-kpi-lbl"><?php esc_html_e( 'Überfällig', 'wm-hinschg-whistleblower' ); ?></div>
				</div>
			</div>

			<div class="wm-dash-actions">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wm-hinschg-desk' ) ); ?>" class="wm-dash-btn">
					<span><?php esc_html_e( 'Meldestelle öffnen', 'wm-hinschg-whistleblower' ); ?></span>
					<span class="dashicons dashicons-arrow-right-alt" aria-hidden="true"></span>
				</a>
			</div>
		</div>
		<?php
	}

	/**
	 * Family menu icon: a monochrome hub-and-spoke mark, filled shapes only so the WordPress
	 * svg-painter can recolour it with the admin colour scheme. Placeholder until the family
	 * icon is decided (hackaton plan D12).
	 */
	public static function family_menu_icon(): string {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><circle cx="10" cy="10" r="2.6" fill="black"/><circle cx="10" cy="3" r="1.8" fill="black"/><circle cx="16.1" cy="13.5" r="1.8" fill="black"/><circle cx="3.9" cy="13.5" r="1.8" fill="black"/><rect x="9.3" y="4.5" width="1.4" height="3.4" fill="black"/><rect x="9.3" y="12.1" width="1.4" height="3.4" fill="black" transform="rotate(-60 10 10)"/><rect x="9.3" y="12.1" width="1.4" height="3.4" fill="black" transform="rotate(60 10 10)"/></svg>';
		return 'data:image/svg+xml;base64,' . base64_encode( $svg );
	}

	public function register_admin_menu(): void {
		add_menu_page(
			__( 'HinSchG-Meldestelle', 'wm-hinschg-whistleblower' ),
			__( 'Meldestelle (HinSchG)', 'wm-hinschg-whistleblower' ),
			Capabilities::READ_CASES,
			'wm-hinschg-desk',
			[ $this, 'render_dashboard_page' ],
			self::family_menu_icon(),
			28
		);
	}

	public function enqueue_admin_assets( string $hook ): void {
		if ( $hook !== 'toplevel_page_wm-hinschg-desk' ) {
			return;
		}

		$root = dirname( __DIR__, 2 ) . '/assets/css/';
		wp_enqueue_style(
			'wm-admin-tokens',
			WM_HINSCHG_URL . 'assets/css/wm-admin-tokens.css',
			[],
			(string) ( @filemtime( $root . 'wm-admin-tokens.css' ) ?: WM_HINSCHG_VERSION )
		);
		wp_enqueue_style(
			'wm-admin-ui',
			WM_HINSCHG_URL . 'assets/css/wm-admin-ui.css',
			[ 'wm-admin-tokens' ],
			(string) ( @filemtime( $root . 'wm-admin-ui.css' ) ?: WM_HINSCHG_VERSION )
		);

		$js_root = dirname( __DIR__, 2 ) . '/assets/js/';
		wp_enqueue_script(
			'wm-hinschg-zero-knowledge',
			WM_HINSCHG_URL . 'assets/js/wm-hinschg-zero-knowledge.js',
			[],
			(string) ( @filemtime( $js_root . 'wm-hinschg-zero-knowledge.js' ) ?: WM_HINSCHG_VERSION ),
			true
		);
		wp_localize_script(
			'wm-hinschg-zero-knowledge',
			'wmHinschgZkConfig',
			[
				'restUrl'   => esc_url_raw( rest_url( 'wm-hinschg/v1' ) ),
				'restNonce' => wp_create_nonce( 'wp_rest' ),
				'i18n'      => [
					'invalidPem'    => __( 'Kein gültiger PKCS#8-Privatschlüssel (BEGIN PRIVATE KEY) erkannt.', 'wm-hinschg-whistleblower' ),
					'noWebCrypto'   => __( 'WebCrypto ist nur über HTTPS oder localhost verfügbar.', 'wm-hinschg-whistleblower' ),
					'generating'    => __( 'RSA-4096-Schlüsselpaar wird lokal im Browser berechnet …', 'wm-hinschg-whistleblower' ),
					'generated'     => __( 'Privater Schlüssel lokal heruntergeladen. Prüfen und speichern Sie nun den öffentlichen Schlüssel.', 'wm-hinschg-whistleblower' ),
					'errorPrefix'   => __( 'Fehler: ', 'wm-hinschg-whistleblower' ),
					'decrypting'    => __( 'Lokale Entschlüsselung im Browser läuft …', 'wm-hinschg-whistleblower' ),
					'reportHeading' => __( 'Meldungstext (lokal im Browser entschlüsselt)', 'wm-hinschg-whistleblower' ),
					'threadHeading' => __( 'Verlauf', 'wm-hinschg-whistleblower' ),
					'officerRole'   => __( 'Meldestelle', 'wm-hinschg-whistleblower' ),
					'reporterRole'  => __( 'Hinweisgebende Person', 'wm-hinschg-whistleblower' ),
					'decryptedOk'   => __( 'Meldung lokal im Browser entschlüsselt. Der private Schlüssel hat den Browser nicht verlassen.', 'wm-hinschg-whistleblower' ),
					'decryptFailed' => __( 'Entschlüsselung fehlgeschlagen: ', 'wm-hinschg-whistleblower' ),
					'ackSending'    => __( 'Eingangsbestätigung wird gespeichert …', 'wm-hinschg-whistleblower' ),
					'ackDone'       => __( 'Eingangsbestätigung gespeichert. Ansicht wird aktualisiert …', 'wm-hinschg-whistleblower' ),
					'replySending'  => __( 'Antwort wird verschlüsselt gespeichert …', 'wm-hinschg-whistleblower' ),
					'replyDone'     => __( 'Antwort verschlüsselt gespeichert. Ansicht wird aktualisiert …', 'wm-hinschg-whistleblower' ),
					'replyEmpty'    => __( 'Bitte geben Sie einen Nachrichtentext ein.', 'wm-hinschg-whistleblower' ),
					'retryAfter'    => __( 'Audit-Protokoll vorübergehend belegt. Bitte in 2 Sekunden erneut versuchen.', 'wm-hinschg-whistleblower' ),
				],
			]
		);
	}

	public function handle_form_actions(): void {
		if ( ! isset( $_POST['wm_hinschg_action'] ) || ! Capabilities::may_read() ) {
			return;
		}

		check_admin_referer( 'wm_hinschg_admin_action', 'wm_hinschg_nonce' );

		$action = sanitize_text_field( wp_unslash( $_POST['wm_hinschg_action'] ) );

		if ( $action === 'seed_demo_data' ) {
			$this->seed_demo_data();
			wp_safe_redirect( admin_url( 'admin.php?page=wm-hinschg-desk&tab=desk&seeded=1' ) );
			exit;
		}

		if ( $action === 'submit_test_report' ) {
			$category = ReportCategories::normalize( sanitize_key( wp_unslash( $_POST['report_category'] ?? '' ) ) );
			$details  = sanitize_textarea_field( wp_unslash( $_POST['report_details'] ?? '' ) );
			$this->create_test_report( $category, $details );
			wp_safe_redirect( admin_url( 'admin.php?page=wm-hinschg-desk&tab=desk&created=1' ) );
			exit;
		}

		if ( $action === 'save_uninstall_options' && current_user_can( 'manage_options' ) ) {
			$delete_all = isset( $_POST['delete_data_on_uninstall'] ) ? '1' : '0';
			update_option( Vault::UNINSTALL_DELETE_OPTION, $delete_all, false );
			wp_safe_redirect( admin_url( 'admin.php?page=wm-hinschg-desk&tab=uninstall&saved=1' ) );
			exit;
		}

		if ( $action === 'save_zero_knowledge_public_key' && current_user_can( 'manage_options' ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- openssl_pkey_get_public() validates strict PEM structure in Vault::install_zero_knowledge_public_key().
			$public_pem      = isset( $_POST['zk_public_key_pem'] ) ? trim( (string) wp_unslash( $_POST['zk_public_key_pem'] ) ) : '';
			$confirm_replace = isset( $_POST['zk_confirm_replace'] ) && '1' === sanitize_text_field( wp_unslash( (string) $_POST['zk_confirm_replace'] ) );
			$res             = Vault::install_zero_knowledge_public_key( $public_pem, $confirm_replace );
			$code            = $res['ok'] ? 'saved' : ( str_contains( $public_pem, 'PRIVATE KEY' ) ? 'refused_private' : ( str_contains( $res['message'], 'bereits verschlüsselte Vorgänge' ) ? 'refused_existing' : 'refused_invalid' ) );
			wp_safe_redirect( admin_url( 'admin.php?page=wm-hinschg-desk&tab=custody&zk_status=' . $code ) );
			exit;
		}

		if ( $action === 'save_recovery_public_key' && current_user_can( 'manage_options' ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- openssl_pkey_get_public() validates strict PEM structure in Vault::install_recovery_public_key().
			$public_pem = isset( $_POST['zk_recovery_public_key_pem'] ) ? trim( (string) wp_unslash( $_POST['zk_recovery_public_key_pem'] ) ) : '';
			$res        = Vault::install_recovery_public_key( $public_pem );
			if ( $res['ok'] ) {
				$code = '' === $public_pem ? 'recovery_cleared' : 'recovery_saved';
			} elseif ( str_contains( $public_pem, 'PRIVATE KEY' ) ) {
				$code = 'refused_private';
			} else {
				$code = 'refused_invalid';
			}
			wp_safe_redirect( admin_url( 'admin.php?page=wm-hinschg-desk&tab=custody&zk_status=' . $code ) );
			exit;
		}

		// No "save_settings" any more: the tab stored an officer e-mail, deadlines, uploads and retention in
		// wm_hinschg_settings, and no code ever read that option (measured 2026-09-15).
	}

	/**
	 * Demo cases. They used to be base64 of the text with a random "key" — readable in any
	 * database dump under a column called encrypted_payload — and a token hash the portal could
	 * never match. They now take the same envelope as a real report; the demo tokens are
	 * token_demo_1..3 so the portal can be tried against them.
	 */
	private function seed_demo_data(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'wm_whistle_reports';

		$sample_cases = [
			[
				'case_public_id'        => 'CASE-2026-9481',
				'category'              => 'financial_fraud',
				'description'           => 'Unregelmäßigkeiten bei der Auftragsvergabe (Demo-Fall).',
				'token'                 => 'token_demo_1',
				'status'                => 'received',
				'ack_sla_deadline'      => gmdate( 'Y-m-d H:i:s', time() + ( 86400 * 5 ) ),
				'feedback_sla_deadline' => gmdate( 'Y-m-d H:i:s', time() + ( 86400 * 85 ) ),
				'ack_sent_at'           => null,
				'feedback_sent_at'      => null,
				'created_at'            => gmdate( 'Y-m-d H:i:s', time() - 86400 * 2 ),
			],
			[
				'case_public_id'        => 'CASE-2026-3829',
				'category'              => 'data_protection',
				'description'           => 'Mögliche DSGVO-Verletzung bei der Speicherung von Kundendaten (Demo-Fall).',
				'token'                 => 'token_demo_2',
				'status'                => 'in_investigation',
				'ack_sla_deadline'      => gmdate( 'Y-m-d H:i:s', time() - ( 86400 * 1 ) ),
				'feedback_sla_deadline' => gmdate( 'Y-m-d H:i:s', time() + ( 86400 * 60 ) ),
				'ack_sent_at'           => gmdate( 'Y-m-d H:i:s', time() - ( 86400 * 2 ) ),
				'feedback_sent_at'      => null,
				'created_at'            => gmdate( 'Y-m-d H:i:s', time() - 86400 * 8 ),
			],
			[
				'case_public_id'        => 'CASE-2026-1102',
				'category'              => 'workplace_safety',
				'description'           => 'Fehlende Schutzkleidung und Notausgänge im Lagerbereich (Demo-Fall).',
				'token'                 => 'token_demo_3',
				'status'                => 'closed',
				'ack_sla_deadline'      => gmdate( 'Y-m-d H:i:s', time() - ( 86400 * 30 ) ),
				'feedback_sla_deadline' => gmdate( 'Y-m-d H:i:s', time() - ( 86400 * 5 ) ),
				'ack_sent_at'           => gmdate( 'Y-m-d H:i:s', time() - ( 86400 * 31 ) ),
				'feedback_sent_at'      => gmdate( 'Y-m-d H:i:s', time() - ( 86400 * 6 ) ),
				'created_at'            => gmdate( 'Y-m-d H:i:s', time() - 86400 * 35 ),
			],
		];

		foreach ( $sample_cases as $case ) {
			$envelope = $this->vault->encrypt_envelope(
				[
					'category'    => $case['category'],
					'description' => $case['description'],
					'metadata'    => [ 'demo' => true ],
					'created_at'  => $case['created_at'],
				]
			);

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- demo rows into the plugin's own table.
			$wpdb->insert(
				$table,
				[
					'case_public_id'        => $case['case_public_id'],
					'category'              => $case['category'],
					'encrypted_payload'     => $envelope['payload'],
					'encrypted_key'         => Vault::encode_key_meta( $envelope ),
					'token_auth_hash'       => $this->vault->hash_token( $case['token'] ),
					'status'                => $case['status'],
					'ack_sla_deadline'      => $case['ack_sla_deadline'],
					'feedback_sla_deadline' => $case['feedback_sla_deadline'],
					'ack_sent_at'           => $case['ack_sent_at'],
					'feedback_sent_at'      => $case['feedback_sent_at'],
					'created_at'            => $case['created_at'],
					'updated_at'            => $case['created_at'],
				]
			);
		}
	}

	/**
	 * A test report from the admin "Testmeldung" tab.
	 *
	 * Was base64_encode( $details ) with a random "key" under a heading promising AES-256, and a
	 * token hash the portal could never match. It now takes the same path as a real submission,
	 * and the access token is shown once so the portal can actually be tried with it.
	 */
	private function create_test_report( string $category, string $details ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'wm_whistle_reports';

		$case_id   = 'CASE-' . strtoupper( bin2hex( random_bytes( 4 ) ) );
		$token_raw = $this->vault->generate_access_token();
		$envelope  = $this->vault->encrypt_envelope(
			[
				'category'    => $category,
				'description' => $details,
				'metadata'    => [ 'test_report' => true ],
				'created_at'  => current_time( 'mysql', true ),
			]
		);
		$deadlines = $this->sla_manager->compute_deadlines();
		$now       = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- the plugin's own table.
		$wpdb->insert(
			$table,
			[
				'case_public_id'        => $case_id,
				'category'              => $category,
				'encrypted_payload'     => $envelope['payload'],
				'encrypted_key'         => Vault::encode_key_meta( $envelope ),
				'token_auth_hash'       => $this->vault->hash_token( $token_raw ),
				'status'                => 'submitted',
				'ack_sla_deadline'      => $deadlines['ack_deadline'],
				'feedback_sla_deadline' => $deadlines['feedback_deadline'],
				'ack_sent_at'           => null,
				'feedback_sent_at'      => null,
				'created_at'            => $now,
				'updated_at'            => $now,
			]
		);

		$this->vault->log_audit_event( $case_id, 'TEST_REPORT_CREATED', 'COMPLIANCE_OFFICER', get_current_user_id() );

		// Shown once on the next page load, then gone: the token is the only way into the case.
		set_transient( 'wm_hinschg_test_report_' . get_current_user_id(), [ 'case' => $case_id, 'token' => $token_raw ], 5 * MINUTE_IN_SECONDS );
	}

	public function render_dashboard_page(): void {
		global $wpdb;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- tab selection only.
		$current_tab   = sanitize_key( $_GET['tab'] ?? 'desk' );
		$table_reports = $wpdb->prefix . 'wm_whistle_reports';
		$has_table     = $this->reports_table_exists();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$cases         = $has_table ? (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table_reports} ORDER BY id DESC LIMIT %d", 50 ), ARRAY_A ) : [];
		$counts      = $has_table ? $this->sla_manager->status_counts() : [ 'breached_ack' => 0, 'breached_feedback' => 0, 'impending_ack' => 0, 'open' => 0 ];
		$overdue     = $counts['breached_ack'] + $counts['breached_feedback'];
		$has_key     = '' !== $this->vault->get_public_key();
		$now         = current_time( 'mysql', true );
		$tabs        = [
			'desk'      => __( 'Vorgänge & Fristen', 'wm-hinschg-whistleblower' ),
			'shortcode' => __( 'Formular einbinden', 'wm-hinschg-whistleblower' ),
			'submit'    => __( 'Testmeldung', 'wm-hinschg-whistleblower' ),
			'deadlines' => __( 'Fristen & Benachrichtigungen', 'wm-hinschg-whistleblower' ),
			'custody'   => __( 'Schlüsselverwahrung', 'wm-hinschg-whistleblower' ),
			'uninstall' => __( 'Deinstallation', 'wm-hinschg-whistleblower' ),
			'glossary'  => __( 'Begriffe', 'wm-hinschg-whistleblower' ),
		];
		?>
		<div class="wrap wm-admin wm-hinschg-admin-wrap">
			<header class="wm-admin-header">
				<div class="wm-header-title">
					<h1><?php esc_html_e( 'HinSchG-Meldestelle', 'wm-hinschg-whistleblower' ); ?></h1>
					<p class="wm-subtitle"><?php esc_html_e( 'Meldungen über das Formular entgegennehmen, verschlüsselt speichern und die Fristen nach § 17 HinSchG berechnen.', 'wm-hinschg-whistleblower' ); ?></p>
				</div>
				<div class="wm-header-badges">
					<span class="wm-badge-family" title="<?php esc_attr_e( 'Part of the WM Suite plugin family', 'wm-hinschg-whistleblower' ); ?>">
						<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="4" r="2"/><circle cx="19" cy="16" r="2"/><circle cx="5" cy="16" r="2"/><path d="M12 7v2M13.9 13.2l3.4 2M10.1 13.2l-3.4 2"/></svg>
						<?php esc_html_e( 'WM Suite', 'wm-hinschg-whistleblower' ); ?>
						<span class="wm-badge-family-state"><?php echo defined( 'WM_SUITE_HUB_VERSION' ) ? esc_html__( 'Hub', 'wm-hinschg-whistleblower' ) : esc_html__( 'Standalone', 'wm-hinschg-whistleblower' ); ?></span>
					</span>
					<span class="wm-badge <?php echo esc_attr( $has_key ? 'wm-badge-green' : 'wm-badge-red' ); ?>">
						<?php echo $has_key ? esc_html__( 'Schlüsselpaar vorhanden', 'wm-hinschg-whistleblower' ) : esc_html__( 'Kein Schlüsselpaar: Meldungen können nicht gespeichert werden', 'wm-hinschg-whistleblower' ); ?>
					</span>
					<span class="wm-badge <?php echo esc_attr( $overdue > 0 ? 'wm-badge-red' : 'wm-badge-green' ); ?>">
						<?php
						if ( $overdue > 0 ) {
							/* translators: %d: number of passed deadlines */
							echo esc_html( sprintf( _n( '%d Frist überschritten', '%d Fristen überschritten', $overdue, 'wm-hinschg-whistleblower' ), $overdue ) );
						} else {
							esc_html_e( 'Keine Frist überschritten', 'wm-hinschg-whistleblower' );
						}
						?>
					</span>
				</div>
			</header>

			<section class="wm-quick-guide">
				<h2 class="wm-quick-guide-title"><?php esc_html_e( 'Was die Meldestelle leisten muss', 'wm-hinschg-whistleblower' ); ?></h2>
				<p class="wm-quick-guide-desc">
					<?php esc_html_e( 'Beschäftigungsgeber mit in der Regel mindestens 50 Beschäftigten müssen eine interne Meldestelle einrichten (§ 12 Abs. 2 HinSchG); für die in § 12 Abs. 3 genannten Unternehmen, etwa Kreditinstitute, Wertpapierdienstleistungsunternehmen und Versicherungsunternehmen, gilt das unabhängig von der Zahl der Beschäftigten. Die Meldestelle bestätigt den Eingang einer Meldung spätestens nach sieben Tagen und gibt innerhalb von drei Monaten nach der Bestätigung eine Rückmeldung (§ 17). Meldungen müssen schriftlich und mündlich möglich sein, auf Wunsch auch persönlich (§ 16 Abs. 3); dieses Plugin deckt nur den schriftlichen Weg ab. Anonyme Meldungen soll die Meldestelle bearbeiten, muss sie aber nicht ermöglichen (§ 16 Abs. 1). Die Dokumentation ist drei Jahre nach Abschluss des Verfahrens zu löschen (§ 11 Abs. 5); das Plugin löscht nichts selbst. Ob eine Einrichtung ihre Pflichten erfüllt, prüft das Plugin nicht.', 'wm-hinschg-whistleblower' ); ?>
				</p>
			</section>

			<?php if ( isset( $_GET['seeded'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Drei Demo-Vorgänge angelegt (Zugangsschlüssel token_demo_1 bis token_demo_3).', 'wm-hinschg-whistleblower' ); ?></p></div>
			<?php endif; ?>
			<?php
			if ( isset( $_GET['created'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$test_report = get_transient( 'wm_hinschg_test_report_' . get_current_user_id() );
				delete_transient( 'wm_hinschg_test_report_' . get_current_user_id() );
				?>
				<div class="notice notice-success is-dismissible">
					<p><?php esc_html_e( 'Testmeldung verschlüsselt gespeichert.', 'wm-hinschg-whistleblower' ); ?></p>
					<?php if ( is_array( $test_report ) ) : ?>
						<p>
							<?php esc_html_e( 'Vorgangs-ID:', 'wm-hinschg-whistleblower' ); ?> <code><?php echo esc_html( (string) $test_report['case'] ); ?></code>
							&middot; <?php esc_html_e( 'Zugangsschlüssel (nur jetzt sichtbar):', 'wm-hinschg-whistleblower' ); ?> <code><?php echo esc_html( (string) $test_report['token'] ); ?></code>
						</p>
					<?php endif; ?>
				</div>
			<?php endif; ?>

			<nav class="wm-nav-tabs" aria-label="<?php esc_attr_e( 'Bereiche der Meldestelle', 'wm-hinschg-whistleblower' ); ?>">
				<?php foreach ( $tabs as $slug => $label ) : ?>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wm-hinschg-desk&tab=' . $slug ) ); ?>" class="wm-tab-link <?php echo $current_tab === $slug ? 'active' : ''; ?>"<?php echo $current_tab === $slug ? ' aria-current="page"' : ''; ?>><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</nav>

			<?php if ( $current_tab === 'desk' ) :
				$chain_status = \WMCyber\HinSchG\Crypto\Vault::verify_audit_chain();
				$key_source   = \WMCyber\HinSchG\Crypto\Vault::private_key_source();
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- selects which case to show; reading is capability-gated by the page itself and recorded in the audit log.
				$open_case    = sanitize_text_field( (string) ( $_GET['case'] ?? '' ) );
				?>
				<?php if ( $key_source['dump_is_enough'] ) : ?>
					<div class="notice notice-warning inline">
						<p>
							<strong><?php esc_html_e( 'Der private Schlüssel liegt ungeschützt in der Datenbank.', 'wm-hinschg-whistleblower' ); ?></strong>
							<?php echo esc_html( $key_source['label'] ); ?>
						</p>
						<p>
							<?php
							printf(
								/* translators: 1: master key constant name, 2: passphrase constant name, 3: WP-CLI command */
								esc_html__( 'Setzen Sie %1$s (empfohlen, Libsodium XSalsa20-Poly1305, migriert automatisch) oder %2$s in der wp-config.php und führen Sie %3$s aus. Das Schlüsselpaar bleibt dabei erhalten; nur die gespeicherte Form ändert sich, sodass alle bisherigen Meldungen lesbar bleiben.', 'wm-hinschg-whistleblower' ),
								'<code>' . esc_html( \WMCyber\HinSchG\Crypto\Vault::MASTER_KEY_CONSTANT ) . '</code>',
								'<code>' . esc_html( \WMCyber\HinSchG\Crypto\Vault::PASSPHRASE_CONSTANT ) . '</code>',
								'<code>wp hinschg protect-key</code>'
							);
							?>
						</p>
					</div>
				<?php endif; ?>

				<?php
				// Who can open a report is a HinSchG question, not a WordPress detail: § 8 keeps the
				// content with the people entrusted with the channel. The plugin cannot decide that
				// for an install, so it counts and states it instead of staying silent.
				$readers    = Capabilities::holders();
				$admins_too = in_array( 'administrator', Capabilities::roles_with_access(), true );
				?>
				<div class="notice <?php echo $admins_too ? 'notice-warning' : 'notice-info'; ?> inline">
					<p>
						<strong>
							<?php
							/* translators: %d: number of users who can open a report */
							echo esc_html( sprintf( _n( '%d Person darf Meldungen öffnen.', '%d Personen dürfen Meldungen öffnen.', count( $readers ), 'wm-hinschg-whistleblower' ), count( $readers ) ) );
							?>
						</strong>
						<?php if ( $admins_too ) : ?>
							<?php
							printf(
								/* translators: 1: role name, 2: WP-CLI command, 3: WP-CLI command */
								esc_html__( 'Darunter die Rolle %1$s, also jede Person, die diese Website verwaltet. § 8 HinSchG hält den Inhalt bei den mit der Meldestelle betrauten Personen. Mit %2$s sehen Sie die Liste; vergeben Sie die Rolle „Meldestelle (HinSchG)" und entziehen Sie die Berechtigung danach mit %3$s.', 'wm-hinschg-whistleblower' ),
								'<code>administrator</code>',
								'<code>wp hinschg access</code>',
								'<code>wp hinschg revoke-access --role=administrator</code>'
							);
							?>
						<?php else : ?>
							<?php esc_html_e( 'Administratoren dieser Website können Meldungen nicht öffnen, solange sie die Berechtigung nicht haben.', 'wm-hinschg-whistleblower' ); ?>
						<?php endif; ?>
					</p>
				</div>

				<?php
				if ( '' !== $open_case ) :
					// Every open is appended to the audit chain by the same route the REST API uses — one path, one record.
					$case_view     = ( new \WMCyber\HinSchG\API\RestController( $this->vault, $this->sla_manager ) )
						->handle_admin_read_case( new \WP_REST_Request( [ 'case_public_id' => $open_case ] ) );
					$is_rest_error = $case_view instanceof \WP_REST_Response && $case_view->get_status() >= 400;
					$case_row      = null;
					if ( $has_table ) {
						// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
						$case_row = $wpdb->get_row( $wpdb->prepare( "SELECT case_public_id, category, status, ack_sla_deadline, feedback_sla_deadline, ack_sent_at, feedback_sent_at, created_at FROM {$table_reports} WHERE case_public_id = %s", $open_case ), ARRAY_A );
					}
					?>
					<div class="wm-card">
						<h2>
							<?php
							/* translators: %s: case reference */
							printf( esc_html__( 'Meldung %s', 'wm-hinschg-whistleblower' ), '<code>' . esc_html( $open_case ) . '</code>' );
							?>
						</h2>
						<?php if ( is_wp_error( $case_view ) || $is_rest_error ) :
							$error_message = is_wp_error( $case_view )
								? (string) $case_view->get_error_message()
								: (string) ( ( (array) $case_view->get_data() )['message'] ?? __( 'Vorgang konnte nicht geladen werden.', 'wm-hinschg-whistleblower' ) );
							?>
							<p class="wm-field-desc"><strong><?php echo esc_html( $error_message ); ?></strong></p>
							<?php
							if ( is_wp_error( $case_view ) && 'decryption_failed' === $case_view->get_error_code() && 'offline-custody' === $key_source['source'] ) :
								$offline_bundle = $this->build_offline_envelope_bundle( $open_case );
								if ( null !== $offline_bundle ) :
									?>
									<div class="wm-field-card" data-wm-hinschg-offline-envelope="<?php echo esc_attr( (string) wp_json_encode( $offline_bundle ) ); ?>">
										<label class="wm-field-title" for="wm-hinschg-zk-keyfile"><?php esc_html_e( 'Lokale Browser-Entschlüsselung (Offline-Privatschlüssel wählen)', 'wm-hinschg-whistleblower' ); ?></label>
										<p class="wm-field-desc"><?php esc_html_e( 'Wählen Sie Ihre lokal gespeicherte PKCS#8-Schlüsseldatei (.pem). Die Entschlüsselung erfolgt ausschließlich im Arbeitsspeicher Ihres Browsers; der private Schlüssel wird nicht an den Server übertragen.', 'wm-hinschg-whistleblower' ); ?></p>
										<input type="file" id="wm-hinschg-zk-keyfile" accept=".pem,.key" class="wm-input" />
										<p id="wm-hinschg-zk-decrypt-status" class="wm-field-desc"></p>
										<div id="wm-hinschg-zk-decrypt-output"></div>
									</div>
									<?php
								endif;
							endif;
							?>
						<?php
						else :
							$view = (array) $case_view->get_data();
							?>
							<p class="wm-field-desc">
								<?php echo esc_html( \WMCyber\HinSchG\Compliance\ReportCategories::label( (string) ( $view['category'] ?? '' ) ) ); ?>
								&middot; <?php echo esc_html( \WMCyber\HinSchG\Compliance\CaseStatus::label( (string) ( $view['status'] ?? '' ) ) ); ?>
								&middot; <?php echo esc_html( substr( (string) ( $view['submitted_at'] ?? '' ), 0, 16 ) ); ?>
							</p>
							<h3><?php esc_html_e( 'Meldungstext', 'wm-hinschg-whistleblower' ); ?></h3>
							<p style="white-space:pre-wrap"><?php echo esc_html( (string) ( $view['description'] ?? '' ) ); ?></p>
							<?php if ( ! empty( $view['messages'] ) ) : ?>
								<h3><?php esc_html_e( 'Verlauf', 'wm-hinschg-whistleblower' ); ?></h3>
								<?php foreach ( (array) $view['messages'] as $m ) : ?>
									<p>
										<strong><?php echo 'compliance_officer' === ( $m['sender_role'] ?? '' ) ? esc_html__( 'Meldestelle', 'wm-hinschg-whistleblower' ) : esc_html__( 'Hinweisgebende Person', 'wm-hinschg-whistleblower' ); ?></strong>
										<span class="wm-field-desc"><?php echo esc_html( substr( (string) ( $m['created_at'] ?? '' ), 0, 16 ) ); ?></span><br />
										<?php if ( ! empty( $m['unreadable'] ) ) : ?>
											<em><?php esc_html_e( 'Diese Nachricht ließ sich nicht entschlüsseln.', 'wm-hinschg-whistleblower' ); ?></em>
										<?php else : ?>
											<span style="white-space:pre-wrap"><?php echo esc_html( (string) ( $m['message'] ?? '' ) ); ?></span>
										<?php endif; ?>
									</p>
								<?php endforeach; ?>
							<?php endif; ?>
							<p class="wm-field-desc">
								<?php esc_html_e( 'Jeder Aufruf dieser Meldung wird im Audit-Protokoll vermerkt (§ 8 HinSchG: der Inhalt ist auch innerhalb der Einrichtung vertraulich).', 'wm-hinschg-whistleblower' ); ?>
							</p>
						<?php endif; ?>
						<?php
						$case_exists = ( ! is_wp_error( $case_view ) && ! $is_rest_error )
							|| ( is_array( $case_row ) && ! $is_rest_error );
						if ( $case_exists ) :
							$action_meta      = ( ! is_wp_error( $case_view ) && ! $is_rest_error ) ? (array) $case_view->get_data() : (array) $case_row;
							$ack_sent_at      = (string) ( $action_meta['ack_sent_at'] ?? '' );
							$feedback_sent_at = (string) ( $action_meta['feedback_sent_at'] ?? '' );
							?>
							<div class="wm-field-card" id="wm-hinschg-case-actions" data-case-id="<?php echo esc_attr( $open_case ); ?>" data-ack-sent="<?php echo esc_attr( '' !== $ack_sent_at ? '1' : '0' ); ?>">
								<h3><?php esc_html_e( 'Fallbearbeitung nach § 17 HinSchG', 'wm-hinschg-whistleblower' ); ?></h3>
								<p class="wm-field-desc">
									<?php
									if ( '' !== $ack_sent_at ) {
										/* translators: %s: timestamp */
										echo esc_html( sprintf( __( 'Eingangsbestätigung erfasst am %s.', 'wm-hinschg-whistleblower' ), substr( $ack_sent_at, 0, 16 ) ) );
									} else {
										esc_html_e( 'Eingang noch nicht bestätigt (§ 17 Abs. 1 Nr. 1 HinSchG: Frist 7 Tage).', 'wm-hinschg-whistleblower' );
									}
									if ( '' !== $feedback_sent_at ) {
										echo ' ';
										/* translators: %s: timestamp */
										echo esc_html( sprintf( __( 'Abschließende Rückmeldung erfasst am %s.', 'wm-hinschg-whistleblower' ), substr( $feedback_sent_at, 0, 16 ) ) );
									}
									?>
								</p>
								<p>
									<button type="button" id="wm-hinschg-ack-btn" class="button button-secondary"<?php echo '' !== $ack_sent_at ? ' disabled="disabled"' : ''; ?>><?php esc_html_e( 'Eingang bestätigen (§ 17 Abs. 1 HinSchG)', 'wm-hinschg-whistleblower' ); ?></button>
								</p>
								<div class="wm-field-card">
									<label class="wm-field-title" for="wm-hinschg-reply-text"><?php esc_html_e( 'Rückfrage oder Rückmeldung an die hinweisgebende Person', 'wm-hinschg-whistleblower' ); ?></label>
									<p class="wm-field-desc"><?php esc_html_e( 'Wird verschlüsselt gespeichert und für die hinweisgebende Person unter „Vorgang abrufen“ bereitgestellt. Das Plugin versendet keine E-Mails.', 'wm-hinschg-whistleblower' ); ?></p>
									<textarea id="wm-hinschg-reply-text" rows="4" class="wm-input"></textarea>
								</div>
								<p>
									<label for="wm-hinschg-reply-final">
										<input type="checkbox" id="wm-hinschg-reply-final" value="1" />
										<?php esc_html_e( 'Abschließende Rückmeldung nach § 17 Abs. 2 HinSchG', 'wm-hinschg-whistleblower' ); ?>
									</label>
								</p>
								<p>
									<button type="button" id="wm-hinschg-reply-btn" class="button button-primary"><?php esc_html_e( 'Antwort verschlüsselt senden', 'wm-hinschg-whistleblower' ); ?></button>
								</p>
								<p id="wm-hinschg-case-action-status" class="wm-field-desc" role="status" aria-live="polite"></p>
							</div>
						<?php endif; ?>
						<p><a class="button button-secondary" href="<?php echo esc_url( admin_url( 'admin.php?page=wm-hinschg-desk' ) ); ?>"><?php esc_html_e( 'Zurück zur Übersicht', 'wm-hinschg-whistleblower' ); ?></a></p>
					</div>
				<?php endif; ?>

				<div class="wm-card">
					<h2><?php echo $chain_status['valid'] ? esc_html__( 'Audit-Protokoll: Kette geprüft, keine nachträgliche Änderung erkennbar', 'wm-hinschg-whistleblower' ) : esc_html__( 'Audit-Protokoll: Integritätsprüfung fehlgeschlagen', 'wm-hinschg-whistleblower' ); ?></h2>
					<p class="wm-field-desc">
						<?php if ( $chain_status['valid'] ) : ?>
							<?php
							printf(
								/* translators: 1: checked count, 2: key source */
								esc_html__( '%1$d Protokolleinträge geprüft. Signaturschlüssel: %2$s.', 'wm-hinschg-whistleblower' ),
								(int) $chain_status['checked'],
								'<code>' . esc_html( $chain_status['key_source'] ) . '</code>'
							);
							?>
							<?php if ( (int) $chain_status['unkeyed_legacy'] > 0 ) : ?>
								<?php
								/* translators: %d: number of audit entries written before the signing key existed (unkeyed SHA-256) */
								$unkeyed_text = __( '%d historische Alt-Einträge ohne Signatur', 'wm-hinschg-whistleblower' );
								echo esc_html( '(' . sprintf( $unkeyed_text, (int) $chain_status['unkeyed_legacy'] ) . ')' );
								?>
							<?php endif; ?>
						<?php else : ?>
							<strong><?php echo esc_html( $chain_status['error'] ?? __( 'Unbekannter Fehler bei der Prüfung.', 'wm-hinschg-whistleblower' ) ); ?></strong>
						<?php endif; ?>
					</p>
				</div>

				<div class="wm-grid-4">
					<div class="wm-stat-card">
						<span class="wm-stat-label"><?php esc_html_e( 'Offene Vorgänge', 'wm-hinschg-whistleblower' ); ?></span>
						<span class="wm-stat-value"><?php echo esc_html( (string) $counts['open'] ); ?></span>
						<span class="wm-stat-delta"><?php esc_html_e( 'ohne abschließende Rückmeldung', 'wm-hinschg-whistleblower' ); ?></span>
					</div>
					<div class="wm-stat-card">
						<span class="wm-stat-label"><?php esc_html_e( 'Eingangsbestätigung überfällig', 'wm-hinschg-whistleblower' ); ?></span>
						<span class="wm-stat-value"><?php echo esc_html( (string) $counts['breached_ack'] ); ?></span>
						<span class="wm-stat-delta"><?php esc_html_e( 'nicht bestätigt, 7-Tage-Frist vorbei', 'wm-hinschg-whistleblower' ); ?></span>
					</div>
					<div class="wm-stat-card">
						<span class="wm-stat-label"><?php esc_html_e( 'Bestätigung in 48 Stunden fällig', 'wm-hinschg-whistleblower' ); ?></span>
						<span class="wm-stat-value"><?php echo esc_html( (string) $counts['impending_ack'] ); ?></span>
						<span class="wm-stat-delta"><?php esc_html_e( 'noch nicht bestätigt', 'wm-hinschg-whistleblower' ); ?></span>
					</div>
					<div class="wm-stat-card">
						<span class="wm-stat-label"><?php esc_html_e( 'Rückmeldung überfällig', 'wm-hinschg-whistleblower' ); ?></span>
						<span class="wm-stat-value"><?php echo esc_html( (string) $counts['breached_feedback'] ); ?></span>
						<span class="wm-stat-delta"><?php esc_html_e( 'keine Rückmeldung, Frist des Plugins vorbei', 'wm-hinschg-whistleblower' ); ?></span>
					</div>
				</div>

				<div class="wm-card">
					<h2><?php esc_html_e( 'Vorgänge', 'wm-hinschg-whistleblower' ); ?></h2>
					<p class="wm-field-desc"><?php esc_html_e( 'Die letzten 50 Vorgänge mit Status und Fristen. Die Inhalte bleiben verschlüsselt.', 'wm-hinschg-whistleblower' ); ?></p>

					<table class="wm-table widefat">
						<thead>
							<tr>
								<th scope="col"><?php esc_html_e( 'Vorgang', 'wm-hinschg-whistleblower' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Kategorie', 'wm-hinschg-whistleblower' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Status', 'wm-hinschg-whistleblower' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Eingangsbestätigung', 'wm-hinschg-whistleblower' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Rückmeldung', 'wm-hinschg-whistleblower' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Eingang', 'wm-hinschg-whistleblower' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php if ( empty( $cases ) ) : ?>
								<tr>
									<td colspan="6">
										<p><?php esc_html_e( 'Noch keine Vorgänge.', 'wm-hinschg-whistleblower' ); ?></p>
										<form method="post">
											<?php wp_nonce_field( 'wm_hinschg_admin_action', 'wm_hinschg_nonce' ); ?>
											<input type="hidden" name="wm_hinschg_action" value="seed_demo_data" />
											<button type="submit" class="button button-secondary"><?php esc_html_e( 'Drei Demo-Vorgänge anlegen', 'wm-hinschg-whistleblower' ); ?></button>
										</form>
									</td>
								</tr>
							<?php else : ?>
								<?php
								foreach ( $cases as $c ) :
									// Same rule as HinSchGSlaManager::status_counts(), so a row and the counter never disagree.
									$closed       = 'closed' === (string) $c['status'];
									$ack_overdue  = empty( $c['ack_sent_at'] ) && ! $closed && (string) $c['ack_sla_deadline'] < $now;
									$feed_overdue = empty( $c['feedback_sent_at'] ) && ! $closed && (string) $c['feedback_sla_deadline'] < $now;
									?>
									<tr>
										<td>
											<a href="<?php echo esc_url( admin_url( 'admin.php?page=wm-hinschg-desk&case=' . rawurlencode( (string) $c['case_public_id'] ) ) ); ?>">
												<code><?php echo esc_html( (string) $c['case_public_id'] ); ?></code>
											</a>
										</td>
										<td><?php echo esc_html( ReportCategories::label( (string) $c['category'] ) ); ?></td>
										<td><?php echo esc_html( CaseStatus::label( (string) $c['status'] ) ); ?></td>
										<td>
											<?php if ( ! empty( $c['ack_sent_at'] ) ) : ?>
												<?php
												/* translators: %s: date */
												echo esc_html( sprintf( __( 'bestätigt am %s', 'wm-hinschg-whistleblower' ), substr( (string) $c['ack_sent_at'], 0, 10 ) ) );
												?>
											<?php else : ?>
												<?php
												/* translators: %s: date */
												echo esc_html( sprintf( __( 'Frist %s', 'wm-hinschg-whistleblower' ), substr( (string) $c['ack_sla_deadline'], 0, 10 ) ) );
												?>
												<?php if ( $ack_overdue ) : ?><strong><?php esc_html_e( 'überfällig', 'wm-hinschg-whistleblower' ); ?></strong><?php endif; ?>
											<?php endif; ?>
										</td>
										<td>
											<?php if ( ! empty( $c['feedback_sent_at'] ) ) : ?>
												<?php
												/* translators: %s: date */
												echo esc_html( sprintf( __( 'gegeben am %s', 'wm-hinschg-whistleblower' ), substr( (string) $c['feedback_sent_at'], 0, 10 ) ) );
												?>
											<?php else : ?>
												<?php
												/* translators: %s: date */
												echo esc_html( sprintf( __( 'Frist %s', 'wm-hinschg-whistleblower' ), substr( (string) $c['feedback_sla_deadline'], 0, 10 ) ) );
												?>
												<?php if ( $feed_overdue ) : ?><strong><?php esc_html_e( 'überfällig', 'wm-hinschg-whistleblower' ); ?></strong><?php endif; ?>
											<?php endif; ?>
										</td>
										<td><?php echo esc_html( substr( (string) $c['created_at'], 0, 10 ) ); ?></td>
									</tr>
								<?php endforeach; ?>
							<?php endif; ?>
						</tbody>
					</table>
				</div>

			<?php elseif ( $current_tab === 'shortcode' ) : ?>
				<div class="wm-card">
					<h2><?php esc_html_e( 'Meldeformular auf der Website einbinden', 'wm-hinschg-whistleblower' ); ?></h2>
					<ol>
						<li><?php esc_html_e( 'Eine Seite anlegen, zum Beispiel „Hinweisgebersystem“.', 'wm-hinschg-whistleblower' ); ?></li>
						<li>
							<?php esc_html_e( 'Den Shortcode einfügen:', 'wm-hinschg-whistleblower' ); ?>
							<code>[wm_whistleblower_portal]</code>
							<?php esc_html_e( '(gleichwertig: [wm_hinschg_portal] oder der Block „wm/hinschg-portal“).', 'wm-hinschg-whistleblower' ); ?>
						</li>
						<li><?php esc_html_e( 'Die Seite dort verlinken, wo Beschäftigte sie finden, etwa im Intranet oder im Footer.', 'wm-hinschg-whistleblower' ); ?></li>
					</ol>
					<p class="wm-field-desc">
						<?php esc_html_e( 'Nach dem Absenden erhält die hinweisgebende Person eine Vorgangs-ID und einen Zugangsschlüssel. Mit beiden ruft sie im selben Formular den Status ab und schreibt Nachrichten, ohne Namen oder E-Mail-Adresse anzugeben. Gespeichert wird nur ein HMAC des Schlüssels; geht er verloren, gibt es keinen Zugang mehr zum Vorgang.', 'wm-hinschg-whistleblower' ); ?>
					</p>
				</div>

			<?php elseif ( $current_tab === 'submit' ) : ?>
				<div class="wm-card">
					<h2><?php esc_html_e( 'Testmeldung anlegen', 'wm-hinschg-whistleblower' ); ?></h2>
					<p class="wm-field-desc"><?php esc_html_e( 'Legt einen Vorgang auf demselben Weg an wie das Formular und zeigt den Zugangsschlüssel einmal an, damit das Formular damit ausprobiert werden kann.', 'wm-hinschg-whistleblower' ); ?></p>

					<form method="post" action="">
						<?php wp_nonce_field( 'wm_hinschg_admin_action', 'wm_hinschg_nonce' ); ?>
						<input type="hidden" name="wm_hinschg_action" value="submit_test_report" />

						<div class="wm-field-card">
							<label class="wm-field-title" for="wm-hinschg-test-category"><?php esc_html_e( 'Kategorie', 'wm-hinschg-whistleblower' ); ?></label>
							<select id="wm-hinschg-test-category" name="report_category" class="wm-input">
								<?php foreach ( ReportCategories::all() as $key => $label ) : ?>
									<option value="<?php echo esc_attr( $key ); ?>"<?php echo ReportCategories::DEFAULT === $key ? ' selected' : ''; ?>><?php echo esc_html( $label ); ?></option>
								<?php endforeach; ?>
							</select>
						</div>

						<div class="wm-field-card">
							<label class="wm-field-title" for="wm-hinschg-test-details"><?php esc_html_e( 'Sachverhalt', 'wm-hinschg-whistleblower' ); ?></label>
							<p class="wm-field-desc"><?php esc_html_e( 'Wird mit AES-256-GCM verschlüsselt gespeichert; der Schlüssel dafür wird mit dem RSA-Schlüssel des Plugins versiegelt.', 'wm-hinschg-whistleblower' ); ?></p>
							<textarea id="wm-hinschg-test-details" name="report_details" rows="5" class="wm-input" required></textarea>
						</div>

						<button type="submit" class="button button-primary"><?php esc_html_e( 'Testmeldung speichern', 'wm-hinschg-whistleblower' ); ?></button>
					</form>
				</div>

			<?php elseif ( $current_tab === 'deadlines' ) : ?>
				<div class="wm-card">
					<h2><?php esc_html_e( 'Fristen & Benachrichtigungen', 'wm-hinschg-whistleblower' ); ?></h2>
					<ul>
						<li>
							<?php
							/* translators: %d: days */
							echo esc_html( sprintf( __( 'Eingangsbestätigung: Eingang + %d Tage. § 17 Abs. 1 Nr. 1 HinSchG verlangt die Bestätigung spätestens nach sieben Tagen.', 'wm-hinschg-whistleblower' ), HinSchGSlaManager::ACK_DAYS ) );
							?>
						</li>
						<li>
							<?php
							/* translators: %d: months */
							echo esc_html( sprintf( __( 'Rückmeldung: Eingang + %d Monate. § 17 Abs. 2 HinSchG rechnet drei Monate ab der Eingangsbestätigung (ohne Bestätigung drei Monate und sieben Tage ab Eingang); die Frist des Plugins liegt damit früher.', 'wm-hinschg-whistleblower' ), HinSchGSlaManager::FEEDBACK_MONTHS ) );
							?>
						</li>
						<li><?php esc_html_e( 'Die Fristen sind im Code festgelegt und nicht einstellbar.', 'wm-hinschg-whistleblower' ); ?></li>
						<li><?php esc_html_e( 'Das Plugin versendet keine E-Mails. Eine stündliche Prüfung (WP-Cron) löst bei überschrittenen Fristen die Aktion wm_hinschg_sla_breach_detected aus, an die eine eigene Benachrichtigung angeschlossen werden kann.', 'wm-hinschg-whistleblower' ); ?></li>
					</ul>
					<p class="wm-field-desc"><?php esc_html_e( 'Bis zum 15.09.2026 stand hier eine Einstellungsseite für E-Mail, Fristen, Uploads und Aufbewahrung. Das Plugin hat diese Werte nie verwendet.', 'wm-hinschg-whistleblower' ); ?></p>
				</div>

			<?php elseif ( $current_tab === 'custody' ) :
				$custody_source = Vault::private_key_source();
				$audit_source   = Vault::audit_key_source();
				$recovery_pem   = (string) get_option( Vault::RECOVERY_PUBLIC_KEY_OPTION, '' );
				$has_recovery   = '' !== trim( $recovery_pem );
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display status code only.
				$zk_status      = sanitize_key( (string) ( $_GET['zk_status'] ?? '' ) );
				?>
				<?php if ( 'saved' === $zk_status ) : ?>
					<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Öffentlicher RSA-Schlüssel gespeichert und etwaiger serverseitiger Privatschlüssel entfernt (Offline-Verwahrung aktiv).', 'wm-hinschg-whistleblower' ); ?></p></div>
				<?php elseif ( 'recovery_saved' === $zk_status ) : ?>
					<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Öffentlicher Notfall- und Vertretungsschlüssel (2. betraute Person / Ombudsperson) gespeichert.', 'wm-hinschg-whistleblower' ); ?></p></div>
				<?php elseif ( 'recovery_cleared' === $zk_status ) : ?>
					<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Notfall- und Vertretungsschlüssel entfernt.', 'wm-hinschg-whistleblower' ); ?></p></div>
				<?php elseif ( 'refused_private' === $zk_status ) : ?>
					<div class="notice notice-error is-dismissible"><p><?php esc_html_e( 'Abgelehnt: Es wurde ein privater Schlüssel übermittelt. Bitte ausschließlich den öffentlichen Schlüssel (BEGIN PUBLIC KEY) einreichen.', 'wm-hinschg-whistleblower' ); ?></p></div>
				<?php elseif ( 'refused_existing' === $zk_status ) : ?>
					<div class="notice notice-warning is-dismissible"><p><?php esc_html_e( 'Es sind bereits verschlüsselte Vorgänge vorhanden. Bitte bestätigen Sie den Schlüsselwechsel ausdrücklich über das Kontrollkästchen.', 'wm-hinschg-whistleblower' ); ?></p></div>
				<?php elseif ( '' !== $zk_status ) : ?>
					<div class="notice notice-error is-dismissible"><p><?php esc_html_e( 'Der übermittelte Text ist kein gültiger öffentlicher RSA-Schlüssel (mindestens 2048 Bit, empfohlen 4096 Bit).', 'wm-hinschg-whistleblower' ); ?></p></div>
				<?php endif; ?>

				<div class="wm-card">
					<h2><?php esc_html_e( 'Aktive Schlüsselverwahrung & Audit-Signatur', 'wm-hinschg-whistleblower' ); ?></h2>
					<p class="wm-field-desc">
						<strong><?php esc_html_e( 'RSA-Schlüsselquelle:', 'wm-hinschg-whistleblower' ); ?></strong>
						<code><?php echo esc_html( $custody_source['source'] ); ?></code> — <?php echo esc_html( $custody_source['label'] ); ?>
					</p>
					<p class="wm-field-desc">
						<strong><?php esc_html_e( 'Notfall- & Vertretungsschlüssel:', 'wm-hinschg-whistleblower' ); ?></strong>
						<?php echo $has_recovery ? esc_html__( 'hinterlegt (Dual-Envelope für 2. betraute Person / Ombudsperson aktiv)', 'wm-hinschg-whistleblower' ) : esc_html__( 'nicht hinterlegt', 'wm-hinschg-whistleblower' ); ?>
					</p>
					<p class="wm-field-desc">
						<strong><?php esc_html_e( 'Audit-Kettenschlüssel:', 'wm-hinschg-whistleblower' ); ?></strong>
						<code><?php echo esc_html( $audit_source ); ?></code>
						<?php
						printf(
							/* translators: %s: constant name */
							esc_html__( '(für unabhängige Schlüsselrotation unabhängig von AUTH_KEY setzen Sie %s in der wp-config.php).', 'wm-hinschg-whistleblower' ),
							'<code>' . esc_html( Vault::AUDIT_KEY_CONSTANT ) . '</code>'
						);
						?>
					</p>
				</div>

				<div class="wm-card">
					<h2><?php esc_html_e( 'Browser-Schlüsselerzeugung (Offline-Verwahrung ohne Server-Privatschlüssel)', 'wm-hinschg-whistleblower' ); ?></h2>
					<p class="wm-field-desc">
						<?php esc_html_e( 'Erzeugt ein RSA-OAEP-4096-Schlüsselpaar lokal in Ihrem Browser (WebCrypto). Der private Schlüssel wird direkt als .pem-Datei auf Ihr Gerät heruntergeladen und berührt niemals PHP, den Webserver oder die MySQL-Datenbank. Auf dem Server wird ausschließlich der öffentliche Schlüssel zum Versiegeln eingehender Meldungen gespeichert.', 'wm-hinschg-whistleblower' ); ?>
					</p>
					<?php if ( current_user_can( 'manage_options' ) ) : ?>
						<p>
							<button type="button" id="wm-hinschg-zk-generate-btn" class="button button-secondary"><?php esc_html_e( 'RSA-4096-Schlüsselpaar lokal im Browser erzeugen & privaten Schlüssel herunterladen', 'wm-hinschg-whistleblower' ); ?></button>
						</p>
						<p id="wm-hinschg-zk-status" class="wm-field-desc"></p>
						<form method="post" action="">
							<?php wp_nonce_field( 'wm_hinschg_admin_action', 'wm_hinschg_nonce' ); ?>
							<input type="hidden" name="wm_hinschg_action" value="save_zero_knowledge_public_key" />
							<div class="wm-field-card">
								<label class="wm-field-title" for="wm-hinschg-zk-public-pem"><?php esc_html_e( 'Öffentlicher RSA-Schlüssel (BEGIN PUBLIC KEY)', 'wm-hinschg-whistleblower' ); ?></label>
								<textarea id="wm-hinschg-zk-public-pem" name="zk_public_key_pem" rows="7" class="wm-input" required><?php echo esc_textarea( (string) get_option( 'wm_hinschg_public_key', '' ) ); ?></textarea>
							</div>
							<div class="wm-field-card">
								<label for="wm-hinschg-zk-confirm-replace">
									<input type="checkbox" id="wm-hinschg-zk-confirm-replace" name="zk_confirm_replace" value="1" />
									<?php esc_html_e( 'Vorhandenen Schlüssel ersetzen (bestehende Meldungen benötigen weiterhin den bisherigen privaten Schlüssel)', 'wm-hinschg-whistleblower' ); ?>
								</label>
							</div>
							<button type="submit" id="wm-hinschg-zk-save-btn" class="button button-primary"><?php esc_html_e( 'Nur öffentlichen Schlüssel speichern (Offline-Verwahrung aktivieren)', 'wm-hinschg-whistleblower' ); ?></button>
						</form>
					<?php else : ?>
						<p class="wm-field-desc"><?php esc_html_e( 'Nur Website-Administratoren (manage_options) können den öffentlichen Schlüssel der Meldestelle hinterlegen.', 'wm-hinschg-whistleblower' ); ?></p>
					<?php endif; ?>
				</div>

				<div class="wm-card">
					<h2><?php esc_html_e( 'Notfall- & Vertretungsschlüssel (2. betraute Person der Meldestelle / Ombudsperson)', 'wm-hinschg-whistleblower' ); ?></h2>
					<p class="wm-field-desc">
						<?php esc_html_e( 'Optionales Dual-Envelope für neue Meldungen und Nachrichten: Der AES-256-Sitzungsschlüssel wird zusätzlich mit diesem öffentlichen RSA-Schlüssel versiegelt, damit eine Vertretung im Abwesenheitsfall lokal im Browser entschlüsseln kann. Nach § 8 Abs. 1 und § 15 HinSchG darf die Verwahrung dieses privaten Schlüssels ausschließlich bei einer zweiten mit der Meldestelle betrauten Person oder einer unabhängigen Ombudsperson liegen — niemals bei der Geschäftsführung oder der allgemeinen IT-Administration. Zum Entfernen das Feld leeren und speichern.', 'wm-hinschg-whistleblower' ); ?>
					</p>
					<?php if ( current_user_can( 'manage_options' ) ) : ?>
						<p>
							<button type="button" id="wm-hinschg-zk-generate-recovery-btn" class="button button-secondary"><?php esc_html_e( 'Vertretungs-Schlüsselpaar (RSA-4096) lokal im Browser erzeugen & privaten Schlüssel herunterladen', 'wm-hinschg-whistleblower' ); ?></button>
						</p>
						<p id="wm-hinschg-zk-recovery-status" class="wm-field-desc"></p>
						<form method="post" action="">
							<?php wp_nonce_field( 'wm_hinschg_admin_action', 'wm_hinschg_nonce' ); ?>
							<input type="hidden" name="wm_hinschg_action" value="save_recovery_public_key" />
							<div class="wm-field-card">
								<label class="wm-field-title" for="wm-hinschg-zk-recovery-public-pem"><?php esc_html_e( 'Öffentlicher Notfall- & Vertretungsschlüssel (BEGIN PUBLIC KEY)', 'wm-hinschg-whistleblower' ); ?></label>
								<textarea id="wm-hinschg-zk-recovery-public-pem" name="zk_recovery_public_key_pem" rows="7" class="wm-input"><?php echo esc_textarea( $recovery_pem ); ?></textarea>
							</div>
							<button type="submit" id="wm-hinschg-zk-recovery-save-btn" class="button button-primary"><?php esc_html_e( 'Notfall- & Vertretungsschlüssel speichern', 'wm-hinschg-whistleblower' ); ?></button>
						</form>
					<?php else : ?>
						<p class="wm-field-desc"><?php esc_html_e( 'Nur Website-Administratoren (manage_options) können den öffentlichen Notfall- und Vertretungsschlüssel hinterlegen.', 'wm-hinschg-whistleblower' ); ?></p>
					<?php endif; ?>
				</div>

			<?php elseif ( $current_tab === 'uninstall' ) :
				$delete_on_uninstall = '1' === (string) get_option( Vault::UNINSTALL_DELETE_OPTION, '0' );
				?>
				<?php if ( isset( $_GET['saved'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
					<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Deinstallations-Einstellung gespeichert.', 'wm-hinschg-whistleblower' ); ?></p></div>
				<?php endif; ?>
				<div class="wm-card">
					<h2><?php esc_html_e( 'Gesetzliche Aufbewahrung (§ 11 HinSchG) & Deinstallation', 'wm-hinschg-whistleblower' ); ?></h2>
					<p class="wm-field-desc">
						<?php esc_html_e( 'Nach § 11 Abs. 5 HinSchG ist die Dokumentation drei Jahre nach Abschluss des Verfahrens aufzubewahren. Standardmäßig bleiben Meldungen, Nachrichten, Audit-Protokoll und Schlüsselpaar beim Löschen des Plugins erhalten, damit ein Plugin-Update oder eine Neuinstallation keine gesetzlich aufzubewahrenden Vorgänge vernichtet.', 'wm-hinschg-whistleblower' ); ?>
					</p>
					<?php if ( current_user_can( 'manage_options' ) ) : ?>
						<form method="post" action="">
							<?php wp_nonce_field( 'wm_hinschg_admin_action', 'wm_hinschg_nonce' ); ?>
							<input type="hidden" name="wm_hinschg_action" value="save_uninstall_options" />
							<div class="wm-field-card">
								<label for="wm-hinschg-delete-uninstall">
									<input type="checkbox" id="wm-hinschg-delete-uninstall" name="delete_data_on_uninstall" value="1" <?php checked( $delete_on_uninstall ); ?> />
									<strong><?php esc_html_e( 'Beim Deinstallieren des Plugins alle Meldungen, Nachrichten, Audit-Einträge und Schlüssel unwiderruflich löschen', 'wm-hinschg-whistleblower' ); ?></strong>
								</label>
							</div>
							<button type="submit" class="button button-secondary"><?php esc_html_e( 'Deinstallations-Option speichern', 'wm-hinschg-whistleblower' ); ?></button>
						</form>
					<?php else : ?>
						<p class="wm-field-desc"><?php esc_html_e( 'Nur Website-Administratoren (manage_options) können das Verhalten bei der Plugin-Deinstallation ändern.', 'wm-hinschg-whistleblower' ); ?></p>
					<?php endif; ?>
				</div>

			<?php elseif ( $current_tab === 'glossary' ) : ?>
				<div class="wm-card">
					<h2><?php esc_html_e( 'Begriffe', 'wm-hinschg-whistleblower' ); ?></h2>
					<dl class="wm-glossary-grid">
						<dt class="wm-glossary-term"><?php esc_html_e( 'Vorgangs-ID und Zugangsschlüssel', 'wm-hinschg-whistleblower' ); ?></dt>
						<dd class="wm-glossary-def"><?php esc_html_e( 'Die hinweisgebende Person erhält beide einmal nach dem Absenden. Der Schlüssel ist 64 Zeichen lang; das Plugin speichert nur einen HMAC davon.', 'wm-hinschg-whistleblower' ); ?></dd>

						<dt class="wm-glossary-term"><?php esc_html_e( 'Eingangsbestätigung', 'wm-hinschg-whistleblower' ); ?></dt>
						<dd class="wm-glossary-def"><?php esc_html_e( 'Spätestens nach sieben Tagen (§ 17 Abs. 1 Nr. 1 HinSchG).', 'wm-hinschg-whistleblower' ); ?></dd>

						<dt class="wm-glossary-term"><?php esc_html_e( 'Rückmeldung', 'wm-hinschg-whistleblower' ); ?></dt>
						<dd class="wm-glossary-def"><?php esc_html_e( 'Innerhalb von drei Monaten nach der Eingangsbestätigung, mit geplanten und ergriffenen Folgemaßnahmen (§ 17 Abs. 2 HinSchG).', 'wm-hinschg-whistleblower' ); ?></dd>

						<dt class="wm-glossary-term"><?php esc_html_e( 'Verschlüsselung', 'wm-hinschg-whistleblower' ); ?></dt>
						<dd class="wm-glossary-def"><?php esc_html_e( 'Meldung und Nachrichten werden mit AES-256-GCM verschlüsselt, der AES-Schlüssel mit RSA-OAEP versiegelt (optional zusätzlich als Dual-Envelope für den Notfall- & Vertretungsschlüssel einer 2. betrauten Person / Ombudsperson). Wo der private RSA-Schlüssel liegt, zeigen der Reiter „Schlüsselverwahrung“ und wp hinschg key-status: in der wp-config.php (WM_HINSCHG_PRIVATE_KEY), per Libsodium XSalsa20-Poly1305 versiegelt (WM_HINSCHG_MASTER_KEY oder AUTH_KEY), OpenSSL-verschlüsselt (WM_HINSCHG_KEY_PASSPHRASE) oder ausschließlich lokal im Browser ohne Server-Privatschlüssel (Offline-Verwahrung). Rückmeldungen der Meldestelle erhalten zusätzlich eine für den Zugangsschlüssel versiegelte Box, während Eingaben der hinweisgebenden Person rein asymmetrisch versiegelt bleiben. Zwischen Browser und Server schützt HTTPS.', 'wm-hinschg-whistleblower' ); ?></dd>

						<dt class="wm-glossary-term"><?php esc_html_e( 'Berechtigung zum Öffnen einer Meldung', 'wm-hinschg-whistleblower' ); ?></dt>
						<dd class="wm-glossary-def"><?php esc_html_e( 'Das Plugin prüft die eigene Berechtigung wm_hinschg_read_cases und bringt dafür die Rolle „Meldestelle (HinSchG)“ mit. Wer sie hat, verwaltet WordPress — über die Rollen oder ein Rechte-Plugin, nicht in dieser Oberfläche. Bei der Installation bekommt die Rolle „Administrator“ sie, damit niemand ausgesperrt wird; sie danach zu entziehen ist der eigentliche Zweck. wp hinschg access zeigt, wer sie hat.', 'wm-hinschg-whistleblower' ); ?></dd>

						<dt class="wm-glossary-term"><?php esc_html_e( 'Audit-Protokoll', 'wm-hinschg-whistleblower' ); ?></dt>
						<dd class="wm-glossary-def"><?php esc_html_e( 'Jeder Eintrag enthält einen HMAC-SHA256 über den vorherigen. Nachträgliche Änderungen, Löschungen und Einschübe werden erkannt; wer den Schlüssel aus wp-config.php kennt, kann die Kette neu schreiben.', 'wm-hinschg-whistleblower' ); ?></dd>
					</dl>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Build the ciphertext envelope bundle for local browser decryption when the server holds no private key.
	 *
	 * Called only on the capability-gated desk view AFTER RestController::handle_admin_read_case() has verified
	 * wm_hinschg_read_cases and recorded CASE_OPENED_BY_COMPLIANCE_OFFICER in the audit chain.
	 *
	 * @return array{report:array{payload:string,key:string,tag:string,iv:string,recovery_key?:string},messages:list<array<string,mixed>>}|null
	 */
	private function build_offline_envelope_bundle( string $case_public_id ): ?array {
		global $wpdb;
		$table_reports  = $wpdb->prefix . 'wm_whistle_reports';
		$table_messages = $wpdb->prefix . 'wm_whistle_messages';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$report = $wpdb->get_row( $wpdb->prepare( "SELECT id, encrypted_payload, encrypted_key FROM {$table_reports} WHERE case_public_id = %s", $case_public_id ), ARRAY_A );
		if ( ! is_array( $report ) ) {
			return null;
		}
		$key_parts = json_decode( (string) ( $report['encrypted_key'] ?? '' ), true );
		if ( ! is_array( $key_parts ) || ! isset( $key_parts['key'], $key_parts['tag'], $key_parts['iv'] ) ) {
			return null;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT sender_role, encrypted_message, created_at FROM {$table_messages} WHERE report_id = %d ORDER BY id ASC", (int) $report['id'] ), ARRAY_A );
		$msgs = [];
		foreach ( $rows as $row ) {
			$decoded = json_decode( (string) ( $row['encrypted_message'] ?? '' ), true );
			$is_env  = is_array( $decoded ) && isset( $decoded['payload'], $decoded['key'], $decoded['tag'], $decoded['iv'] );
			$msg_env = null;
			if ( $is_env ) {
				$msg_env = [
					'payload' => (string) $decoded['payload'],
					'key'     => (string) $decoded['key'],
					'tag'     => (string) $decoded['tag'],
					'iv'      => (string) $decoded['iv'],
				];
				if ( ! empty( $decoded['recovery_key'] ) ) {
					$msg_env['recovery_key'] = (string) $decoded['recovery_key'];
				}
			}
			$msgs[] = [
				'sender_role'  => (string) ( $row['sender_role'] ?? '' ),
				'created_at'   => (string) ( $row['created_at'] ?? '' ),
				'envelope'     => $msg_env,
				'plain_legacy' => $is_env ? '' : (string) ( $row['encrypted_message'] ?? '' ),
			];
		}

		$report_env = [
			'payload' => (string) $report['encrypted_payload'],
			'key'     => (string) $key_parts['key'],
			'tag'     => (string) $key_parts['tag'],
			'iv'      => (string) $key_parts['iv'],
		];
		if ( ! empty( $key_parts['recovery_key'] ) ) {
			$report_env['recovery_key'] = (string) $key_parts['recovery_key'];
		}

		return [
			'report'   => $report_env,
			'messages' => $msgs,
		];
	}
}
