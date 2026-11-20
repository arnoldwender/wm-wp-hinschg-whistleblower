<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_CLI;
use WP_CLI_Command;
use WMCyber\HinSchG\Core\Plugin;
use WMCyber\HinSchG\Crypto\Vault;
use WMCyber\HinSchG\Security\Capabilities;

final class HinSchGCommand extends WP_CLI_Command {
	public static function register(): void {
		WP_CLI::add_command( 'hinschg', self::class );
	}

	/**
	 * List all whistleblower cases and their HinSchG § 17 statutory deadlines.
	 *
	 * ## EXAMPLES
	 *
	 *     wp hinschg list
	 */
	public function list( array $args, array $assoc_args ): void {
		global $wpdb;
		$table_reports = $wpdb->prefix . 'wm_whistle_reports';

		$cases = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT case_public_id, category, status, ack_sla_deadline, feedback_sla_deadline, created_at FROM {$table_reports} WHERE id >= %d ORDER BY id DESC",
				0
			),
			ARRAY_A
		);

		if ( empty( $cases ) ) {
			WP_CLI::log( 'No cases recorded.' );
			return;
		}

		WP_CLI\Utils\format_items( 'table', $cases, [ 'case_public_id', 'category', 'status', 'ack_sla_deadline', 'feedback_sla_deadline', 'created_at' ] );
	}

	/**
	 * Count passed and upcoming § 17 HinSchG deadlines, and fire wm_hinschg_sla_breach_detected when one passed.
	 *
	 * ## EXAMPLES
	 *
	 *     wp hinschg sla-check
	 *     wp hinschg sla_check
	 *
	 * @subcommand sla-check
	 */
	public function sla_check( array $args, array $assoc_args ): void {
		$sla = Plugin::instance()->get_sla_manager();
		$res = $sla->execute_hourly_check();

		WP_CLI::line( '=== Deadlines (§ 17 HinSchG) ===' );
		WP_CLI::line( sprintf( 'Acknowledgment overdue (7 days):  %d', $res['breached_ack'] ) );
		WP_CLI::line( sprintf( 'Acknowledgment due within 48 h:   %d', $res['impending_ack'] ) );
		WP_CLI::line( sprintf( 'Feedback overdue (3 months):      %d', $res['breached_feedback'] ) );

		if ( $res['breached_ack'] > 0 || $res['breached_feedback'] > 0 ) {
			WP_CLI::warning( 'At least one deadline has passed.' );
		} else {
			WP_CLI::success( 'No deadline has passed.' );
		}
	}

	/**
	 * Verify the keyed hash chain of the audit log.
	 *
	 * ## EXAMPLES
	 *
	 *     wp hinschg audit
	 */
	public function audit( array $args, array $assoc_args ): void {
		// The verification formula used to live here as a second copy of the sprintf() in
		// Vault::log_audit_event(). Two copies of a security-critical serialisation drift without
		// anything failing, so both writer and verifier now go through Vault.
		$result = Vault::verify_audit_chain();

		if ( 'wp-config' !== $result['key_source'] ) {
			WP_CLI::warning(
				'AUTH_KEY ist nicht definiert. Der Kettenschluessel stammt aus der Datenbank -- also von dort, ' .
				'wo ein Angreifer ohnehin schreiben wuerde. Setzen Sie AUTH_KEY in der wp-config.php.'
			);
		}

		if ( ! $result['valid'] ) {
			$where = null === $result['broken_at_id'] ? 'am Ende des Protokolls' : 'bei Eintrag #' . $result['broken_at_id'];
			WP_CLI::error( "Audit-Kette NICHT integer {$where}: " . (string) $result['error'] );
		}

		if ( 0 === $result['checked'] && 0 === $result['unkeyed_legacy'] ) {
			WP_CLI::success( 'Audit log is empty (0 records).' );
			return;
		}

		// The chain shows that no entry was altered, removed or inserted by someone without the
		// wp-config.php key. It is tamper-evident rather than write-once, and proves no point in time.
		WP_CLI::success(
			sprintf(
				'Audit-Kette integer: %d verkettete Eintraege geprueft, keine nachtraegliche Aenderung erkennbar.',
				$result['checked']
			)
		);

		if ( $result['unkeyed_legacy'] > 0 ) {
			WP_CLI::warning(
				sprintf(
					'%d Eintrag/Eintraege stammen aus der Zeit vor dem Schluessel und tragen einen ungeschluesselten ' .
					'SHA-256. Sie waren von jedem mit Datenbankzugriff faelschbar und gelten als ungeprueft, nicht als integer.',
					$result['unkeyed_legacy']
				)
			);
		}
	}

	/**
	 * Say where the private key lives on this install, and what a database dump is worth.
	 *
	 * ## EXAMPLES
	 *
	 *     wp hinschg key-status
	 *
	 * @subcommand key-status
	 */
	public function key_status( array $args, array $assoc_args ): void {
		$source = Vault::private_key_source();

		WP_CLI::line( '=== Privater Schluessel ===' );
		WP_CLI::line( sprintf( 'Quelle: %s', $source['source'] ) );
		WP_CLI::line( $source['label'] );

		if ( $source['dump_is_enough'] ) {
			// Stated as a warning, not as a line of status: this is the one configuration in which a
			// stolen backup reads every report ever filed, on a channel whose whole promise is that
			// it cannot be read by whoever happens to hold a copy of the database.
			WP_CLI::warning(
				sprintf(
					'Ein vollstaendiger Datenbank-Abzug entschluesselt jede Meldung. Setzen Sie %s (empfohlen) oder %s ' .
					'in der wp-config.php und fuehren Sie danach `wp hinschg protect-key` aus.',
					Vault::MASTER_KEY_CONSTANT,
					Vault::PASSPHRASE_CONSTANT
				)
			);
			return;
		}

		WP_CLI::success( 'Ein Datenbank-Abzug allein entschluesselt keine Meldung.' );
	}

	/**
	 * Re-export the stored private key encrypted with the passphrase from wp-config.php.
	 *
	 * The key pair is kept: the reports are sealed against its public half, so a new pair would
	 * strand every report filed so far. Only the stored form changes.
	 *
	 * ## EXAMPLES
	 *
	 *     wp hinschg protect-key
	 *
	 * @subcommand protect-key
	 */
	public function protect_key( array $args, array $assoc_args ): void {
		$before = Vault::private_key_source();
		$result = \WMCyber\HinSchG\Database\Schema::protect_private_key();

		if ( ! $result['ok'] ) {
			WP_CLI::error( $result['message'] );
		}

		WP_CLI::success( $result['message'] );

		// Measured after the fact, not assumed from the return value: the point of the command is
		// that a dump stops being enough, so that is what gets reported.
		$after = Vault::private_key_source();
		WP_CLI::line( sprintf( 'Quelle vorher: %s -- nachher: %s', $before['source'], $after['source'] ) );
	}

	/**
	 * Show who may open a report on this install.
	 *
	 * ## EXAMPLES
	 *
	 *     wp hinschg access
	 */
	public function access( array $args, array $assoc_args ): void {
		$roles   = Capabilities::roles_with_access();
		$holders = Capabilities::holders();

		WP_CLI::line( '=== Wer darf Meldungen oeffnen? ===' );
		WP_CLI::line( sprintf( 'Berechtigung: %s', Capabilities::READ_CASES ) );
		WP_CLI::line( sprintf( 'Rollen:       %s', $roles ? implode( ', ', $roles ) : '(keine)' ) );
		WP_CLI::line( sprintf( 'Personen:     %d', count( $holders ) ) );

		foreach ( $holders as $user_id ) {
			$user = get_userdata( $user_id );
			WP_CLI::line( sprintf( '  #%d %s', $user_id, $user ? $user->user_login : '(unbekannt)' ) );
		}

		if ( [] === $holders ) {
			// Not a status line: nobody can open a report, the § 17 clock keeps running, and the
			// reports stay encrypted. `wp hinschg grant-access` is the way back in.
			WP_CLI::warning( 'Niemand kann Meldungen oeffnen. Die Sieben-Tage-Frist nach § 17 HinSchG laeuft trotzdem.' );
			return;
		}

		if ( in_array( 'administrator', $roles, true ) ) {
			WP_CLI::warning(
				'Die Rolle "administrator" darf Meldungen oeffnen, also jede Person, die diese Website verwaltet. ' .
				'§ 8 HinSchG haelt den Inhalt bei den mit der Meldestelle betrauten Personen. Rolle ' .
				Capabilities::ROLE . ' vergeben und danach `wp hinschg revoke-access --role=administrator`.'
			);
		}
	}

	/**
	 * Allow a role or a user to open reports.
	 *
	 * ## OPTIONS
	 *
	 * [--role=<slug>]
	 * : The role that should be able to open reports.
	 *
	 * [--user=<id-or-login>]
	 * : The user who should be able to open reports, regardless of their role.
	 *
	 * ## EXAMPLES
	 *
	 *     wp hinschg grant-access --role=wm_hinschg_meldestelle
	 *     wp hinschg grant-access --user=compliance@example.org
	 *
	 * @subcommand grant-access
	 */
	public function grant_access( array $args, array $assoc_args ): void {
		$this->apply_access( $assoc_args, false );
	}

	/**
	 * Stop a role or a user from opening reports.
	 *
	 * Refused when it would leave nobody able to open a report: the reports are encrypted, this
	 * plugin is the only way in, and § 17 HinSchG keeps running its clock either way.
	 *
	 * ## OPTIONS
	 *
	 * [--role=<slug>]
	 * : The role that should no longer be able to open reports.
	 *
	 * [--user=<id-or-login>]
	 * : The user who should no longer be able to open reports.
	 *
	 * ## EXAMPLES
	 *
	 *     wp hinschg revoke-access --role=administrator
	 *
	 * @subcommand revoke-access
	 */
	public function revoke_access( array $args, array $assoc_args ): void {
		$this->apply_access( $assoc_args, true );
	}

	/** Shared argument handling for grant-access and revoke-access. */
	private function apply_access( array $assoc_args, bool $revoke ): void {
		$role = (string) ( $assoc_args['role'] ?? '' );
		$user = (string) ( $assoc_args['user'] ?? '' );

		if ( ( '' === $role ) === ( '' === $user ) ) {
			WP_CLI::error( 'Genau eins von --role=<slug> oder --user=<id-oder-login> angeben.' );
		}

		if ( '' !== $role ) {
			$result = $revoke ? Capabilities::revoke_from_role( $role ) : Capabilities::grant_to_role( $role );
		} else {
			$found = is_numeric( $user ) ? get_userdata( (int) $user ) : get_user_by( 'login', $user );
			if ( ! $found ) {
				$found = get_user_by( 'email', $user );
			}
			if ( ! $found ) {
				WP_CLI::error( sprintf( 'Benutzer "%s" nicht gefunden.', $user ) );
			}
			$result = $revoke ? Capabilities::revoke_from_user( (int) $found->ID ) : Capabilities::grant_to_user( (int) $found->ID );
		}

		if ( ! $result['ok'] ) {
			WP_CLI::error( $result['message'] );
		}

		WP_CLI::success( $result['message'] );

		// Measured after the change, not predicted from it: whether someone still holds the
		// capability through another role is a question only WordPress can answer.
		WP_CLI::line( sprintf( 'Personen mit Zugriff: %d', count( Capabilities::holders() ) ) );
	}
}
