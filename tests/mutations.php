<?php
/**
 * Mutations for tests/run-mutations.sh: each entry undoes one correction with literal replacements
 * [ file, search, replace ]; tests/test-suite.php must turn red for every one of them.
 *
 * Single-quoted strings only: the code under test is full of "$" and a double-quoted search string
 * would interpolate and never match.
 *
 * @package WMCyber\HinSchG
 */

return [
	[
		'acknowledgment breaches counted without looking at ack_sent_at',
		[
			[ 'includes/Compliance/HinSchGSlaManager.php', 'WHERE ack_sent_at IS NULL AND ack_sla_deadline < %s', 'WHERE ack_sla_deadline < %s' ],
		],
	],
	[
		'closed cases counted as feedback breaches',
		[
			[ 'includes/Compliance/HinSchGSlaManager.php', 'WHERE feedback_sent_at IS NULL AND feedback_sla_deadline < %s AND status != \'closed\'', 'WHERE feedback_sent_at IS NULL AND feedback_sla_deadline < %s' ],
		],
	],
	[
		'closed cases counted as open',
		[
			[
				'includes/Compliance/HinSchGSlaManager.php',
				'"SELECT COUNT(*) FROM {$table_reports} WHERE feedback_sent_at IS NULL AND status != %s",
			\'closed\'',
				'"SELECT COUNT(*) FROM {$table_reports} WHERE feedback_sent_at IS NULL AND id >= %d",
			0',
			],
		],
	],
	[
		'the dashboard widget back to fixed zeros',
		[
			[ 'includes/Admin/AdminDashboard.php', '			$counts = $this->sla_manager->status_counts();', '			$counts = [ \'breached_ack\' => 0, \'breached_feedback\' => 0, \'impending_ack\' => 0, \'open\' => 0 ];' ],
		],
	],
	[
		'the desk page back to fixed zeros',
		[
			[ 'includes/Admin/AdminDashboard.php', '$counts      = $has_table ? $this->sla_manager->status_counts() :', '$counts      = false ? null :' ],
		],
	],
	[
		'a closed case marked overdue in its row',
		[
			[ 'includes/Admin/AdminDashboard.php', '$closed       = \'closed\' === (string) $c[\'status\'];', '$closed       = false;' ],
		],
	],
	[
		'the embed tab names a shortcode nobody registers',
		[
			[ 'includes/Admin/AdminDashboard.php', '<code>[wm_whistleblower_portal]</code>', '<code>[wm_whistleblower_form]</code>' ],
		],
	],
	[
		'the settings handler that writes an option nobody reads is back',
		[
			[ 'includes/Admin/AdminDashboard.php', '		// No "save_settings" any more:', '		if ( $action === \'save_settings\' ) { update_option( \'wm_hinschg_settings\', [ \'officer_email\' => \'x\' ] ); }' . "\n" . '		// No "save_settings" any more:' ],
		],
	],
	[
		'hub health runs the hourly check and fires the breach action on every read',
		[
			[ 'includes/Adapters/HinSchG_Spoke_Adapter.php', '$sla = Plugin::instance()->get_sla_manager()->status_counts();', '$sla = Plugin::instance()->get_sla_manager()->execute_hourly_check();' ],
		],
	],
	[
		'hub health HEALTHY without a key pair',
		[
			[ 'includes/Adapters/HinSchG_Spoke_Adapter.php', 'if ( ! self::reports_table_exists() || \'\' === Plugin::instance()->get_vault()->get_public_key() ) {', 'if ( false ) {' ],
		],
	],
	[
		'hub settings link back to the page that never existed',
		[
			[ 'includes/Adapters/HinSchG_Spoke_Adapter.php', 'admin.php?page=wm-hinschg-desk', 'admin.php?page=wm-hinschg-dashboard' ],
		],
	],
	[
		'the certification badge back on the portal',
		[
			[ 'includes/Frontend/WhistlePortal.php', '<h2 class="wm-portal-title">', '<div class="wm-portal-badge">HinSchG § 8 &amp; § 17 BSI-Geprüft</div><h2 class="wm-portal-title">' ],
		],
	],
	[
		'the portal drops a category the desk knows',
		[
			[ 'includes/Frontend/WhistlePortal.php', 'foreach ( ReportCategories::all() as $key => $label )', 'foreach ( array_slice( ReportCategories::all(), 0, 5 ) as $key => $label )' ],
		],
	],
	[
		'the portal script promises end-to-end encryption with an emoji again',
		[
			[ 'assets/js/portal-crypto.js', 'const SUBMIT_LABEL = \'Hinweis absenden\';', 'const SUBMIT_LABEL = \'🔒 Hinweis Ende-zu-Ende verschlüsselt absenden\';' ],
		],
	],
	[
		'the portal shows the raw status key',
		[
			[ 'assets/js/portal-crypto.js', 'Status: ${esc(statusLabel(data.status))}', 'Status: ${esc(data.status)}' ],
		],
	],
	[
		'any string stored as the category again',
		[
			[ 'includes/API/RestController.php', 'ReportCategories::normalize( sanitize_key( (string) ( $params[\'category\'] ?? \'\' ) ) )', 'sanitize_text_field( $params[\'category\'] ?? \'general_compliance\' )' ],
		],
	],
	[
		'a second acknowledgment overwrites the first date',
		[
			[ 'includes/API/RestController.php', 'if ( ! empty( $report[\'ack_sent_at\'] ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'an acknowledgment downgrades a case that already has feedback',
		[
			[ 'includes/API/RestController.php', 'if ( in_array( (string) ( $report[\'status\'] ?? \'\' ), [ \'submitted\', \'received\' ], true ) ) {', 'if ( true ) {' ],
		],
	],
	[
		'an unknown status shown as closed',
		[
			[ 'includes/Compliance/CaseStatus.php', 'return self::labels()[ $status ] ?? $status;', 'return self::labels()[ $status ] ?? \'Abgeschlossen\';' ],
		],
	],
	[
		'uninstall leaves the audit chain tip behind',
		[
			[ 'uninstall.php', '\'wm_whistle_audit_tip\', ', '' ],
		],
	],
	[
		'uninstall leaves the rate-limit counters behind',
		[
			[ 'uninstall.php', '$wpdb->esc_like( \'_transient_wm_hinschg_rl_\' )', '$wpdb->esc_like( \'_transient_wm_hinschg_nothing_\' )' ],
		],
	],
	[
		'uninstall leaves the messages table behind',
		[
			[ 'uninstall.php', '[ \'wm_whistle_messages\', \'wm_whistle_reports\', \'wm_whistle_audit_log\' ]', '[ \'wm_whistle_reports\', \'wm_whistle_audit_log\' ]' ],
		],
	],
	[
		'the quick guide calls § 12 Abs. 3 exceptions again',
		[
			[ 'includes/Admin/AdminDashboard.php', '(§ 12 Abs. 2 HinSchG); für die in § 12 Abs. 3 genannten Unternehmen, etwa Kreditinstitute, Wertpapierdienstleistungsunternehmen und Versicherungsunternehmen, gilt das unabhängig von der Zahl der Beschäftigten.', '(§ 12 Abs. 2 HinSchG; Ausnahmen in Abs. 3).' ],
		],
	],
	[
		'a signature mismatch blamed on editing only',
		[
			[ 'includes/Crypto/Vault.php', '\'Eintrag #%d passt nicht zu seiner Signatur: Er wurde nachträglich verändert, oder das Protokoll wurde mit einem anderen AUTH_KEY geschrieben (etwa vor einem Umzug der Website).\'', '\'Der Inhalt des Eintrags #%d wurde nachträglich verändert.\'' ],
		],
	],
	[
		'the audit-log forgery test runs on any install again',
		[
			[ 'tests/test-audit-chain-forgery.php', 'if ( \'1\' !== getenv( \'WM_HINSCHG_SCRATCH_INSTALL\' ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'the desk stops linking each case to its view',
		[
			[ 'includes/Admin/AdminDashboard.php', 'admin_url( \'admin.php?page=wm-hinschg-desk&case=\' . rawurlencode( (string) $c[\'case_public_id\'] ) )', 'admin_url( \'admin.php?page=wm-hinschg-desk\' )' ],
		],
	],
	[
		'an unprotected private key is no longer stated on the desk',
		[
			[ 'includes/Admin/AdminDashboard.php', '<?php if ( $key_source[\'dump_is_enough\'] ) : ?>', '<?php if ( false ) : ?>' ],
		],
	],
	[
		'reading a case leaves no trace in the audit chain',
		[
			[ 'includes/API/RestController.php', '$this->vault->log_audit_event( $case_public_id, \'CASE_OPENED_BY_COMPLIANCE_OFFICER\', \'COMPLIANCE_OFFICER\', get_current_user_id() );', '' ],
		],
	],
	[
		'a case that cannot be decrypted hands out the ciphertext instead of saying why',
		[
			[
				'includes/API/RestController.php',
				'return new WP_Error(
				\'decryption_failed\',',
				'return new WP_REST_Response( [ \'success\' => true, \'description\' => (string) $report[\'encrypted_payload\'] ] );
			return new WP_Error(
				\'decryption_failed\',',
			],
		],
	],
	[
		'an unprotected private key is reported as if a database dump were not enough',
		[
			[ 'includes/Crypto/Vault.php', '\'source\'         => \'database-plain\',
			\'dump_is_enough\' => true,', '\'source\'         => \'database-plain\',
			\'dump_is_enough\' => false,' ],
		],
	],
	[
		'the stale option in the database wins over the key moved to wp-config.php',
		[
			[ 'includes/Crypto/Vault.php', '	private function private_key_pem(): string {
		if ( defined( self::KEY_CONSTANT ) ) {', '	private function private_key_pem(): string {
		if ( false ) {' ],
		],
	],
	[
		'the migration overwrites a key encrypted with a different passphrase',
		[
			[ 'includes/Database/Schema.php', '			if ( false === $with ) {', '			if ( false ) {' ],
		],
	],
	[
		'reading a report is back to manage_options, which no install can take from an administrator',
		[
			[ 'includes/Security/Capabilities.php', 'return current_user_can( self::READ_CASES );', 'return current_user_can( \'manage_options\' );' ],
		],
	],
	[
		'the desk menu is back to manage_options',
		[
			[ 'includes/Admin/AdminDashboard.php', '			Capabilities::READ_CASES,
			\'wm-hinschg-desk\',', '			\'manage_options\',
			\'wm-hinschg-desk\',' ],
		],
	],
	[
		'an install that already ran never receives the capability and loses its own desk',
		[
			[ 'includes/Security/Capabilities.php', '		if ( (int) get_option( self::VERSION_OPTION, 0 ) >= self::VERSION ) {', '		if ( true ) {' ],
		],
	],
	[
		'the Meldestelle role can administer the whole site',
		[
			[ 'includes/Security/Capabilities.php', '				\'read\'            => true,
				self::READ_CASES  => true,', '				\'read\'            => true,
				\'manage_options\' => true,
				self::READ_CASES  => true,' ],
		],
	],
	[
		'revoking the last access is allowed, leaving the reports with nobody able to open them',
		[
			[
				'includes/Security/Capabilities.php',
				'		$role->remove_cap( self::READ_CASES );

		if ( [] === self::holders() ) {
			$role->add_cap( self::READ_CASES );',
				'		$role->remove_cap( self::READ_CASES );

		if ( false ) {
			$role->add_cap( self::READ_CASES );',
			],
		],
	],
	[
		'uninstall leaves the role and the capability behind',
		[
			[ 'uninstall.php', '	\\WMCyber\\HinSchG\\Security\\Capabilities::remove();', '' ],
		],
	],
	// readme.txt is published text, not code, and it drifted the day after admin/case shipped: the
	// two mutations below are the exact state it was found in on 2026-09-19.
	[
		'the readme claims again that no route decrypts a report for the officer',
		[
			[ 'readme.txt', '**What it does not do.** ', '**What it does not do.** The Meldestelle cannot read a report in the product: no screen or route decrypts it for the officer. ' ],
		],
	],
	[
		'the readme stops naming the route that opens a case',
		[
			[ 'readme.txt', '`admin/case`, ', '' ],
		],
	],
	[
		'the developer guide loses the row for the route that opens a case',
		[
			[ 'docs/DEVELOPER-GUIDE.md', '| `admin/case` | GET | `wm_hinschg_read_cases` |', '| admin-case-removed | GET | `wm_hinschg_read_cases` |' ],
		],
	],
	[
		'the developer guide documents manage_options for the admin routes again',
		[
			[ 'docs/DEVELOPER-GUIDE.md', '| `admin/cases` | GET | `wm_hinschg_read_cases` |', '| `admin/cases` | GET | `manage_options` |' ],
		],
	],
	[
		'WM_HINSCHG_MASTER_KEY stops migrating a legacy plaintext PEM in wp_options',
		[
			[ 'includes/Crypto/Vault.php', '$this->maybe_migrate_legacy_key();', '// migration skipped' ],
		],
	],
	[
		'Schema::activate() writes a plaintext PEM to wp_options instead of sealing it with sodium_crypto_secretbox',
		[
			[ 'includes/Database/Schema.php', '$sealed = Vault::seal_private_key_sodium( $raw_pem, $fallback, Vault::SODIUM_AUTHKEY_PREFIX );', '$sealed = $raw_pem;' ],
		],
	],
	[
		'Schema::activate() without wp-config secrets generates a key instead of staying unconfigured for Zero-Knowledge custody',
		[
			[ 'includes/Database/Schema.php', 'if ( null === $master && null === $passphrase && null === $fallback ) {
				return;
			}', 'if ( false ) { return; }' ],
		],
	],
	[
		'Vault::install_zero_knowledge_public_key() accepts a private key PEM instead of refusing it',
		[
			[ 'includes/Crypto/Vault.php', 'if ( str_contains( $public_pem, \'PRIVATE KEY\' ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'Vault::log_audit_event() ignores failed GET_LOCK concurrency serialization',
		[
			[ 'includes/Crypto/Vault.php', 'if ( \'1\' !== (string) $locked && 1 !== $locked ) {', 'if ( false ) {' ],
		],
	],
	[
		'Vault::verify_audit_chain() ignores tampered AUDIT_TIP_OPTION HMAC signature',
		[
			[ 'includes/Crypto/Vault.php', 'if ( ! $tip_ok ) {', 'if ( false ) {' ],
		],
	],
	[
		'Vault::audit_hash() ignores dedicated WM_HINSCHG_AUDIT_KEY constant',
		[
			[ 'includes/Crypto/Vault.php', 'if ( defined( self::AUDIT_KEY_CONSTANT ) && \'\' !== trim( (string) constant( self::AUDIT_KEY_CONSTANT ) ) ) {
			$derived = hash_hkdf( \'sha256\', trim( (string) constant( self::AUDIT_KEY_CONSTANT ) ), 32, \'wm-hinschg-audit-chain-v1\' );', 'if ( false ) {
			$derived = \'\';' ],
		],
	],
	[
		'Schema::enforce_prerequisites() ignores missing PHP cryptographic extensions',
		[
			[ 'includes/Database/Schema.php', 'if ( [] === $missing ) {
			return;
		}', 'if ( true ) { return; }' ],
		],
	],
	[
		'default uninstall wipes statutory 3-year HinSchG § 11 records without administrator opt-in',
		[
			[ 'uninstall.php', '$delete_all = \'1\' === (string) get_option( \'wm_hinschg_delete_data_on_uninstall\', \'0\' );', '$delete_all = true;' ],
		],
	],
	[
		'Gutenberg block loses its editorScript and disappears from the Block Inserter',
		[
			[ 'blocks/portal/block.json', '"editorScript": "wm-hinschg-blocks-editor",', '' ],
		],
	],
	[
		'public report intake reverts to unconditional __return_true instead of check_anonymous_portal_access',
		[
			[ 'includes/API/RestController.php', '\'callback\'            => [ $this, \'handle_report_submit\' ],
				\'permission_callback\' => [ $this, \'check_anonymous_portal_access\' ],', '\'callback\'            => [ $this, \'handle_report_submit\' ],
				\'permission_callback\' => \'__return_true\',' ],
		],
	],
	[
		'RateLimiter ignores wm_hinschg_rest_rate_limit filter overrides',
		[
			[ 'includes/Security/RateLimiter.php', '$limit = max( 1, (int) apply_filters( \'wm_hinschg_rest_rate_limit\', $limit, $bucket, $window ) );', '// filter skipped' ],
		],
	],
	[
		'Plugin::boot stops firing wm_hinschg_ready lifecycle action',
		[
			[ 'includes/Core/Plugin.php', 'do_action( \'wm_hinschg_ready\', $this );', '// ready skipped' ],
		],
	],
	[
		'Block Bindings leaks open_cases count to unprivileged visitors',
		[
			[ 'includes/Frontend/WhistlePortal.php', 'if ( ! Capabilities::may_read() ) {
					return \'\';
				}', 'if ( false ) { return \'\'; }' ],
		],
	],
	[
		'Vault::encrypt_envelope omits dual-envelope recovery_key when recovery public key is set',
		[
			[ 'includes/Crypto/Vault.php', '$envelope[\'recovery_key\'] = base64_encode( $encrypted_recovery_key );', '// recovery_key omitted' ],
		],
	],
	[
		'Vault::install_recovery_public_key stops persisting the validated recovery key',
		[
			[ 'includes/Crypto/Vault.php', 'update_option( self::RECOVERY_PUBLIC_KEY_OPTION, $validated[\'key\'], false );', '// recovery key skipped' ],
		],
	],
	[
		'Vault::encode_key_meta drops recovery_key from encrypted_key JSON',
		[
			[ 'includes/Crypto/Vault.php', 'if ( ! empty( $envelope[\'recovery_key\'] ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'AdminDashboard::build_offline_envelope_bundle strips recovery_key from report bundle',
		[
			[ 'includes/Admin/AdminDashboard.php', '$report_env[\'recovery_key\'] = (string) $key_parts[\'recovery_key\'];', '// recovery_key stripped' ],
		],
	],
	[
		'wm-hinschg-zero-knowledge.js stops falling back to env.recovery_key',
		[
			[ 'assets/js/wm-hinschg-zero-knowledge.js', 'if (!env.recovery_key) {', 'if (true) {' ],
		],
	],
	[
		'Vault::seal_message leaks reporter_box onto whistleblower-authored messages',
		[
			[ 'includes/Crypto/Vault.php', 'if ( \'compliance_officer\' === $sender_role && \'\' !== $token_auth_hash ) {', 'if ( \'\' !== $token_auth_hash ) {' ],
		],
	],
	[
		'RestController::handle_report_status tries reporter_box for whistleblower messages',
		[
			[ 'includes/API/RestController.php', 'if ( \'compliance_officer\' === (string) $row[\'sender_role\'] ) {', 'if ( true ) {' ],
		],
	],
	[
		'RestController::handle_admin_send_ack omits token_auth_hash so offline-custody reporters cannot read ack',
		[
			[ 'includes/API/RestController.php', '$sealed_ack = $this->vault->seal_message( $ack_msg, \'compliance_officer\', (string) ( $report[\'token_auth_hash\'] ?? \'\' ) );', '$sealed_ack = $this->vault->seal_message( $ack_msg, \'compliance_officer\' );' ],
		],
	],
	[
		'RestController::handle_admin_send_reply omits token_auth_hash so offline-custody reporters cannot read reply',
		[
			[ 'includes/API/RestController.php', '$sealed_reply = $this->vault->seal_message( $reply_text, \'compliance_officer\', (string) ( $report[\'token_auth_hash\'] ?? \'\' ) );', '$sealed_reply = $this->vault->seal_message( $reply_text, \'compliance_officer\' );' ],
		],
	],
	[
		'AdminDashboard hides Fallbearbeitung § 17 UI in offline-custody mode',
		[
			[
				'includes/Admin/AdminDashboard.php',
				'$case_exists = ( ! is_wp_error( $case_view ) && ! $is_rest_error )
							|| ( is_array( $case_row ) && ! $is_rest_error );',
				'$case_exists = ( ! is_wp_error( $case_view ) && ! $is_rest_error );',
			],
		],
	],
	[
		'AdminDashboard drops restNonce from wmHinschgZkConfig localization',
		[
			[ 'includes/Admin/AdminDashboard.php', '\'restNonce\' => wp_create_nonce( \'wp_rest\' ),', '\'restNonce\' => \'\',' ],
		],
	],
	[
		'Vault::log_audit_event aborts immediately on first GET_LOCK contention instead of retrying',
		[
			[ 'includes/Crypto/Vault.php', 'if ( null === $locked || \'0\' !== (string) $locked ) {', 'if ( true ) {' ],
		],
	],
	[
		'RestController::audit_busy_response drops 503 status and Retry-After header',
		[
			[
				'includes/API/RestController.php',
				'503,
				[ \'Retry-After\' => \'2\' ]',
				'500,
				[]',
			],
		],
	],
	[
		'AdminDashboard ignores 503 WP_REST_Response errors in open case view',
		[
			[ 'includes/Admin/AdminDashboard.php', '$is_rest_error = $case_view instanceof \\WP_REST_Response && $case_view->get_status() >= 400;', '$is_rest_error = false;' ],
		],
	],
	[
		'wp_initialize_site activates schema on new blogs even when plugin is not network-activated',
		[
			[ 'wm-hinschg-whistleblower.php', 'if ( ! function_exists( \'is_plugin_active_for_network\' ) || ! is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'wp_initialize_site skips Schema::activate on new multisite blogs',
		[
			[ 'wm-hinschg-whistleblower.php', 'Database\\Schema::activate();', '// skipped site activation' ],
		],
	],
	[
		'1.4.1: the block style handle is no longer registered with the block (editor preview unstyled)',
		[
			[ 'includes/Frontend/WhistlePortal.php', "		\$this->register_portal_style();\n\n		register_block_type(", "		register_block_type(" ],
		],
	],
];
