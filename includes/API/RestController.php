<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\API;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\HinSchG\Crypto\Vault;
use WMCyber\HinSchG\Compliance\HinSchGSlaManager;
use WMCyber\HinSchG\Compliance\ReportCategories;
use WMCyber\HinSchG\Security\RateLimiter;
use WMCyber\HinSchG\Security\Capabilities;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

final class RestController {
	private const REST_NAMESPACE = 'wm-hinschg/v1';

	public function __construct(
		private readonly Vault $vault,
		private readonly HinSchGSlaManager $sla_manager
	) {}

	public function register_routes(): void {
		add_action( 'rest_api_init', function (): void {
			// Public report intake. No account, no name; rate-limited via blinded ephemeral bucket (§ 8 HinSchG).
			register_rest_route( self::REST_NAMESPACE, '/report/submit', [
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_report_submit' ],
				'permission_callback' => [ $this, 'check_anonymous_portal_access' ],
			] );

			// Public status check: case id plus the access token handed out once at submission.
			register_rest_route( self::REST_NAMESPACE, '/report/status', [
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_report_status' ],
				'permission_callback' => [ $this, 'check_anonymous_portal_access' ],
			] );

			// Whistleblower Reply via Token
			register_rest_route( self::REST_NAMESPACE, '/report/chat', [
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_whistleblower_reply' ],
				'permission_callback' => [ $this, 'check_anonymous_portal_access' ],
			] );

			// Admin case management. The check is the plugin's OWN capability, never manage_options:
			// an install cannot take manage_options away from an administrator, so gating on it meant
			// every administrator of the site could read every report and no role manager could change
			// that. Who holds wm_hinschg_read_cases is the install's decision; see Security\Capabilities.
			register_rest_route( self::REST_NAMESPACE, '/admin/cases', [
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_admin_list_cases' ],
				'permission_callback' => fn() => Capabilities::may_read(),
			] );

			register_rest_route( self::REST_NAMESPACE, '/admin/ack', [
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_admin_send_ack' ],
				'permission_callback' => fn() => Capabilities::may_read(),
			] );

			register_rest_route( self::REST_NAMESPACE, '/admin/reply', [
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_admin_send_reply' ],
				'permission_callback' => fn() => Capabilities::may_read(),
			] );

			// The Meldestelle reads the report it is legally required to process. Until 2026-09-19
			// no screen and no route decrypted one: the officer could acknowledge and answer a
			// report without ever being able to read it, which is not a whistleblowing channel.
			register_rest_route( self::REST_NAMESPACE, '/admin/case', [
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_admin_read_case' ],
				'permission_callback' => fn() => Capabilities::may_read(),
				'args'                => [
					'case_public_id' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
				],
			] );
		} );
	}

	/**
	 * Convert an audit-chain advisory-lock contention RuntimeException into a 503 Retry-After response.
	 */
	private function audit_busy_response( \RuntimeException $e ): WP_REST_Response {
		if ( str_contains( $e->getMessage(), 'lock' ) ) {
			return new WP_REST_Response(
				[
					'code'    => 'wm_hinschg_audit_busy',
					'message' => __( 'Das Audit-Protokoll ist vorübergehend belegt. Bitte in Kürze erneut versuchen.', 'wm-hinschg-whistleblower' ),
				],
				503,
				[ 'Retry-After' => '2' ]
			);
		}
		throw $e;
	}

	/**
	 * Gate anonymous whistleblower portal routes without requiring a WordPress account or storing raw IPs (§ 8 HinSchG).
	 *
	 * Enforces an ephemeral hourly portal flood-protection bucket (filterable via wm_hinschg_rest_rate_limit)
	 * before route-specific rate limits run inside each handler.
	 */
	public function check_anonymous_portal_access( ?WP_REST_Request $request = null ): bool|WP_Error {
		unset( $request );
		if ( ! RateLimiter::consume( 'portal', 60, HOUR_IN_SECONDS ) ) {
			return RateLimiter::refusal();
		}

		return true;
	}

	/**
	 * Decrypt one case for the Meldestelle: the report and the whole message thread.
	 *
	 * Every call appends CASE_OPENED_BY_COMPLIANCE_OFFICER to the audit chain, with the user id.
	 * That is not bookkeeping: § 8 HinSchG makes the identity of the reporting person and the
	 * content confidential towards everyone who is not running the channel, so WHO opened a case
	 * and WHEN is part of what the log exists to answer. The entry is written BEFORE the plaintext
	 * is returned, so a read that happened is recorded even if the response never arrives.
	 */
	public function handle_admin_read_case( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		global $wpdb;

		$case_public_id = sanitize_text_field( (string) $request->get_param( 'case_public_id' ) );
		if ( '' === $case_public_id ) {
			return new WP_Error( 'missing_params', __( 'Case ID is required.', 'wm-hinschg-whistleblower' ), [ 'status' => 400 ] );
		}

		$table_reports  = $wpdb->prefix . 'wm_whistle_reports';
		$table_messages = $wpdb->prefix . 'wm_whistle_messages';

		$report = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM $table_reports WHERE case_public_id = %s", $case_public_id ),
			ARRAY_A
		);

		if ( ! $report ) {
			return new WP_Error( 'not_found', __( 'Case not found.', 'wm-hinschg-whistleblower' ), [ 'status' => 404 ] );
		}

		try {
			$this->vault->log_audit_event( $case_public_id, 'CASE_OPENED_BY_COMPLIANCE_OFFICER', 'COMPLIANCE_OFFICER', get_current_user_id() );
		} catch ( \RuntimeException $e ) {
			return $this->audit_busy_response( $e );
		}

		$key_parts = json_decode( (string) $report['encrypted_key'], true );
		if ( ! is_array( $key_parts ) || ! isset( $key_parts['key'], $key_parts['tag'], $key_parts['iv'] ) ) {
			return new WP_Error(
				'unreadable',
				__( 'Der Umschlag dieser Meldung ist unvollständig gespeichert; sie lässt sich nicht entschlüsseln.', 'wm-hinschg-whistleblower' ),
				[ 'status' => 500 ]
			);
		}

		try {
			$plain = $this->vault->decrypt_envelope(
				(string) $report['encrypted_payload'],
				(string) $key_parts['key'],
				(string) $key_parts['tag'],
				(string) $key_parts['iv']
			);
		} catch ( \RuntimeException $e ) {
			// The ciphertext is never handed out as a consolation prize: an officer who cannot read
			// the report needs to know WHY, and a blob on screen is not an answer.
			return new WP_Error(
				'decryption_failed',
				sprintf(
					/* translators: %s: what this install does with the private key */
					__( 'Diese Meldung ließ sich nicht entschlüsseln. Schlüsselquelle: %s', 'wm-hinschg-whistleblower' ),
					Vault::private_key_source()['label']
				),
				[ 'status' => 500 ]
			);
		}

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, sender_role, encrypted_message, created_at FROM $table_messages WHERE report_id = %d ORDER BY id ASC",
				(int) $report['id']
			),
			ARRAY_A
		);

		$messages = array_map(
			function ( array $row ): array {
				$unreadable = false;
				try {
					$opened = $this->vault->open_message( (string) $row['encrypted_message'] );
				} catch ( \RuntimeException $e ) {
					$opened     = [ 'message' => '', 'sealed' => true ];
					$unreadable = true;
				}

				return [
					'id'          => (int) $row['id'],
					'sender_role' => (string) $row['sender_role'],
					'message'     => $opened['message'],
					'sealed'      => $opened['sealed'],
					'unreadable'  => $unreadable,
					'created_at'  => (string) $row['created_at'],
				];
			},
			(array) $rows
		);

		return new WP_REST_Response( [
			'success'           => true,
			'case_public_id'    => (string) $report['case_public_id'],
			'category'          => (string) $report['category'],
			'status'            => (string) $report['status'],
			'description'       => (string) ( $plain['description'] ?? '' ),
			'submitted_at'      => (string) ( $plain['created_at'] ?? $report['created_at'] ),
			'ack_sent_at'       => $report['ack_sent_at'] ?? null,
			'feedback_sent_at'  => $report['feedback_sent_at'] ?? null,
			'ack_deadline'      => $report['ack_sla_deadline'] ?? null,
			'feedback_deadline' => $report['feedback_sla_deadline'] ?? null,
			'messages'          => $messages,
			'key_source'        => Vault::private_key_source()['source'],
		] );
	}

	public function handle_report_submit( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		// Public by design (no account). § 16 Abs. 1 HinSchG does not require channels that enable anonymous reports; this one does. Public is not unmetered.
		if ( ! RateLimiter::consume( 'submit', 5, HOUR_IN_SECONDS ) ) {
			return RateLimiter::refusal();
		}

		global $wpdb;

		$params = $request->get_json_params();
		// Any string used to be stored as the category; the desk and the portal only know these keys.
		$category = ReportCategories::normalize( sanitize_key( (string) ( $params['category'] ?? '' ) ) );
		$description = sanitize_textarea_field( $params['description'] ?? '' );

		if ( empty( $description ) ) {
			return new WP_Error( 'invalid_report', __( 'Report description cannot be empty.', 'wm-hinschg-whistleblower' ), [ 'status' => 400 ] );
		}

		$case_public_id = 'CASE-' . strtoupper( bin2hex( random_bytes( 4 ) ) );
		$raw_token      = $this->vault->generate_access_token();
		$token_hash     = $this->vault->hash_token( $raw_token );

		// Envelope encryption
		$envelope = $this->vault->encrypt_envelope( [
			'category'    => $category,
			'description' => $description,
			'metadata'    => $params['metadata'] ?? [],
			'created_at'  => current_time( 'mysql', true ),
		] );

		$deadlines = $this->sla_manager->compute_deadlines();
		$now       = current_time( 'mysql', true );

		// Audit log entry (HMAC chain, see Vault::log_audit_event). Acquire chain lock before inserting report.
		try {
			$this->vault->log_audit_event( $case_public_id, 'REPORT_SUBMITTED', 'ANONYMOUS_WHISTLEBLOWER' );
		} catch ( \RuntimeException $e ) {
			return $this->audit_busy_response( $e );
		}

		$table_reports = $wpdb->prefix . 'wm_whistle_reports';
		$wpdb->insert(
			$table_reports,
			[
				'case_public_id'         => $case_public_id,
				'category'               => $category,
				'encrypted_payload'      => $envelope['payload'],
				'encrypted_key'          => Vault::encode_key_meta( $envelope ),
				'token_auth_hash'        => $token_hash,
				'status'                 => 'submitted',
				'ack_sla_deadline'       => $deadlines['ack_deadline'],
				'feedback_sla_deadline'  => $deadlines['feedback_deadline'],
				'created_at'             => $now,
				'updated_at'             => $now,
			],
			[ '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ]
		);

		$report_id = $wpdb->insert_id;

		return new WP_REST_Response( [
			'success'        => true,
			'case_public_id' => $case_public_id,
			'access_token'   => $raw_token,
			'ack_deadline'   => $deadlines['ack_deadline'],
			'feedback_deadline' => $deadlines['feedback_deadline'],
			'notice'         => __( 'Save this Access Token securely. It is the ONLY way to check your report status or communicate confidentially without revealing your identity.', 'wm-hinschg-whistleblower' ),
		], 201 );
	}

	public function handle_report_status( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		// Without this the endpoint is an offline oracle for guessing case tokens.
		if ( ! RateLimiter::consume( 'status', 20, HOUR_IN_SECONDS ) ) {
			return RateLimiter::refusal();
		}

		global $wpdb;

		$params = $request->get_json_params();
		$case_public_id = sanitize_text_field( $params['case_public_id'] ?? '' );
		$raw_token      = sanitize_text_field( $params['access_token'] ?? '' );

		if ( empty( $case_public_id ) || empty( $raw_token ) ) {
			return new WP_Error( 'missing_credentials', __( 'Case ID and Access Token are required.', 'wm-hinschg-whistleblower' ), [ 'status' => 400 ] );
		}

		$token_hash = $this->vault->hash_token( $raw_token );
		$table_reports  = $wpdb->prefix . 'wm_whistle_reports';
		$table_messages = $wpdb->prefix . 'wm_whistle_messages';

		$report = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM $table_reports WHERE case_public_id = %s AND token_auth_hash = %s",
			$case_public_id,
			$token_hash
		), ARRAY_A );

		if ( ! $report ) {
			return new WP_Error( 'invalid_auth', __( 'Invalid Case ID or Access Token.', 'wm-hinschg-whistleblower' ), [ 'status' => 403 ] );
		}

		// Retrieve messages and open them for the token holder. The ciphertext column is never
		// handed out: it was, under the name "encrypted_message", while holding plain text.
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT id, sender_role, encrypted_message, created_at FROM $table_messages WHERE report_id = %d ORDER BY id ASC",
			(int) $report['id']
		), ARRAY_A );

		$messages = array_map(
			function ( array $row ) use ( $token_hash ): array {
				$unreadable = false;
				try {
					$opened = $this->vault->open_message( (string) $row['encrypted_message'] );
				} catch ( \RuntimeException $e ) {
					// In offline-custody mode the server has no RSA private key; officer replies carry a
					// reporter_box sealed for the verified token holder, while whistleblower messages stay strictly RSA-OAEP.
					if ( 'compliance_officer' === (string) $row['sender_role'] ) {
						try {
							$opened = Vault::open_message_for_reporter( (string) $row['encrypted_message'], $token_hash );
						} catch ( \RuntimeException $re ) {
							$opened     = [ 'message' => '', 'sealed' => true ];
							$unreadable = true;
						}
					} else {
						// Wrong or rotated key: say so instead of leaking ciphertext or dying.
						$opened     = [ 'message' => '', 'sealed' => true ];
						$unreadable = true;
					}
				}

				return [
					'id'          => (int) $row['id'],
					'sender_role' => (string) $row['sender_role'],
					'message'     => $opened['message'],
					'sealed'      => $opened['sealed'],
					'unreadable'  => $unreadable,
					'created_at'  => (string) $row['created_at'],
				];
			},
			(array) $rows
		);

		return new WP_REST_Response( [
			'success'           => true,
			'case_public_id'    => $report['case_public_id'],
			'status'            => $report['status'],
			'category'          => $report['category'],
			'ack_sent_at'       => $report['ack_sent_at'] ?? null,
			'feedback_sent_at'  => $report['feedback_sent_at'] ?? null,
			'ack_deadline'      => $report['ack_sla_deadline'] ?? null,
			'feedback_deadline' => $report['feedback_sla_deadline'] ?? null,
			'messages'          => $messages,
		] );
	}

	public function handle_whistleblower_reply( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		if ( ! RateLimiter::consume( 'chat', 20, HOUR_IN_SECONDS ) ) {
			return RateLimiter::refusal();
		}

		global $wpdb;

		$params = $request->get_json_params();
		$case_public_id = sanitize_text_field( $params['case_public_id'] ?? '' );
		$raw_token      = sanitize_text_field( $params['access_token'] ?? '' );
		$message_text   = sanitize_textarea_field( $params['message'] ?? '' );

		if ( empty( $case_public_id ) || empty( $raw_token ) || empty( $message_text ) ) {
			return new WP_Error( 'missing_params', __( 'Case ID, Access Token, and message are required.', 'wm-hinschg-whistleblower' ), [ 'status' => 400 ] );
		}

		$token_hash = $this->vault->hash_token( $raw_token );
		$table_reports  = $wpdb->prefix . 'wm_whistle_reports';
		$table_messages = $wpdb->prefix . 'wm_whistle_messages';

		$report = $wpdb->get_row( $wpdb->prepare(
			"SELECT id FROM $table_reports WHERE case_public_id = %s AND token_auth_hash = %s",
			$case_public_id,
			$token_hash
		), ARRAY_A );

		if ( ! $report ) {
			return new WP_Error( 'invalid_auth', __( 'Invalid Case ID or Access Token.', 'wm-hinschg-whistleblower' ), [ 'status' => 403 ] );
		}

		$now            = current_time( 'mysql', true );
		$sealed_message = $this->vault->seal_message( $message_text, 'whistleblower' );

		try {
			$this->vault->log_audit_event( $case_public_id, 'MESSAGE_RECEIVED_FROM_WHISTLEBLOWER', 'ANONYMOUS_WHISTLEBLOWER' );
		} catch ( \RuntimeException $e ) {
			return $this->audit_busy_response( $e );
		}

		$wpdb->insert(
			$table_messages,
			[
				'report_id'         => (int) $report['id'],
				'sender_role'       => 'whistleblower',
				'encrypted_message' => $sealed_message,
				'created_at'        => $now,
			],
			[ '%d', '%s', '%s', '%s' ]
		);

		return new WP_REST_Response( [
			'success' => true,
			'message' => __( 'Confidential message appended successfully.', 'wm-hinschg-whistleblower' ),
		], 201 );
	}

	public function handle_admin_list_cases(): WP_REST_Response {
		global $wpdb;
		$table_reports = $wpdb->prefix . 'wm_whistle_reports';

		$cases = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, case_public_id, category, status, ack_sla_deadline, feedback_sla_deadline, ack_sent_at, feedback_sent_at, created_at FROM {$table_reports} ORDER BY id DESC LIMIT %d",
				100
			),
			ARRAY_A
		);

		return new WP_REST_Response( [
			'success' => true,
			'cases'   => $cases,
		] );
	}

	public function handle_admin_send_ack( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		global $wpdb;

		$params = $request->get_json_params();
		$case_public_id = sanitize_text_field( $params['case_public_id'] ?? '' );

		if ( empty( $case_public_id ) ) {
			return new WP_Error( 'missing_params', __( 'Case ID is required.', 'wm-hinschg-whistleblower' ), [ 'status' => 400 ] );
		}

		$table_reports  = $wpdb->prefix . 'wm_whistle_reports';
		$table_messages = $wpdb->prefix . 'wm_whistle_messages';

		$report = $wpdb->get_row( $wpdb->prepare(
			"SELECT id, status, ack_sent_at, token_auth_hash FROM $table_reports WHERE case_public_id = %s",
			$case_public_id
		), ARRAY_A );

		if ( ! $report ) {
			return new WP_Error( 'not_found', __( 'Case not found.', 'wm-hinschg-whistleblower' ), [ 'status' => 404 ] );
		}

		// A second call used to overwrite ack_sent_at with a later time, moving the recorded § 17 date.
		if ( ! empty( $report['ack_sent_at'] ) ) {
			return new WP_Error( 'already_acknowledged', __( 'The receipt of this report was already acknowledged.', 'wm-hinschg-whistleblower' ), [ 'status' => 409 ] );
		}

		$now        = current_time( 'mysql', true );
		$new_status = (string) ( $report['status'] ?? '' );
		$update     = [ 'ack_sent_at' => $now, 'updated_at' => $now ];
		// Only a case still at intake moves to "acknowledged"; a case with feedback or closed keeps its status.
		if ( in_array( (string) ( $report['status'] ?? '' ), [ 'submitted', 'received' ], true ) ) {
			$update['status'] = 'acknowledged';
			$new_status       = 'acknowledged';
		}

		$ack_msg    = __( 'Eingangsbestätigung: Ihre Meldung ist bei der internen Meldestelle eingegangen (§ 17 Abs. 1 Nr. 1 HinSchG).', 'wm-hinschg-whistleblower' );
		$sealed_ack = $this->vault->seal_message( $ack_msg, 'compliance_officer', (string) ( $report['token_auth_hash'] ?? '' ) );

		try {
			$this->vault->log_audit_event( $case_public_id, 'HINSCHG_ACK_ISSUED_§17', 'COMPLIANCE_OFFICER', get_current_user_id() );
		} catch ( \RuntimeException $e ) {
			return $this->audit_busy_response( $e );
		}

		$wpdb->update(
			$table_reports,
			$update,
			[ 'id' => (int) $report['id'] ],
			array_fill( 0, count( $update ), '%s' ),
			[ '%d' ]
		);

		$wpdb->insert(
			$table_messages,
			[
				'report_id'         => (int) $report['id'],
				'sender_role'       => 'compliance_officer',
				'encrypted_message' => $sealed_ack,
				'created_at'        => $now,
			],
			[ '%d', '%s', '%s', '%s' ]
		);

		return new WP_REST_Response( [
			'success'     => true,
			'ack_sent_at' => $now,
			'status'      => $new_status,
			'message'     => __( 'Acknowledgment recorded and sent to the reporting person\'s case view.', 'wm-hinschg-whistleblower' ),
		] );
	}

	public function handle_admin_send_reply( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		global $wpdb;

		$params = $request->get_json_params();
		$case_public_id = sanitize_text_field( $params['case_public_id'] ?? '' );
		$reply_text     = sanitize_textarea_field( $params['message'] ?? '' );
		$is_final_feedback = ! empty( $params['is_final_feedback'] );

		if ( empty( $case_public_id ) || empty( $reply_text ) ) {
			return new WP_Error( 'missing_params', __( 'Case ID and message are required.', 'wm-hinschg-whistleblower' ), [ 'status' => 400 ] );
		}

		$table_reports  = $wpdb->prefix . 'wm_whistle_reports';
		$table_messages = $wpdb->prefix . 'wm_whistle_messages';

		$report = $wpdb->get_row( $wpdb->prepare(
			"SELECT id, status, token_auth_hash FROM $table_reports WHERE case_public_id = %s",
			$case_public_id
		), ARRAY_A );

		if ( ! $report ) {
			return new WP_Error( 'not_found', __( 'Case not found.', 'wm-hinschg-whistleblower' ), [ 'status' => 404 ] );
		}

		$now          = current_time( 'mysql', true );
		$sealed_reply = $this->vault->seal_message( $reply_text, 'compliance_officer', (string) ( $report['token_auth_hash'] ?? '' ) );
		$audit_action = $is_final_feedback ? 'HINSCHG_FEEDBACK_ISSUED_§17' : 'MESSAGE_SENT_BY_COMPLIANCE_OFFICER';

		try {
			$this->vault->log_audit_event( $case_public_id, $audit_action, 'COMPLIANCE_OFFICER', get_current_user_id() );
		} catch ( \RuntimeException $e ) {
			return $this->audit_busy_response( $e );
		}

		$wpdb->insert(
			$table_messages,
			[
				'report_id'         => (int) $report['id'],
				'sender_role'       => 'compliance_officer',
				'encrypted_message' => $sealed_reply,
				'created_at'        => $now,
			],
			[ '%d', '%s', '%s', '%s' ]
		);

		$new_status = (string) ( $report['status'] ?? '' );
		if ( $is_final_feedback ) {
			$new_status = 'investigated';
			$wpdb->update(
				$table_reports,
				[ 'feedback_sent_at' => $now, 'status' => 'investigated', 'updated_at' => $now ],
				[ 'id' => (int) $report['id'] ],
				[ '%s', '%s', '%s' ],
				[ '%d' ]
			);
		}

		return new WP_REST_Response( [
			'success'          => true,
			'status'           => $new_status,
			'feedback_sent_at' => $is_final_feedback ? $now : null,
			'message'          => __( 'Reply stored in the reporting person\'s case view.', 'wm-hinschg-whistleblower' ),
		] );
	}
}
