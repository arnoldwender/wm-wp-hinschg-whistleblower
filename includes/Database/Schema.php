<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\HinSchG\Crypto\Vault;
use WMCyber\HinSchG\Security\Capabilities;

final class Schema {
	/** Required PHP extensions for AES-256-GCM/RSA-4096 (OpenSSL) and XSalsa20-Poly1305 (Libsodium). */
	public const REQUIRED_EXTENSIONS = [ 'openssl', 'sodium' ];

	/**
	 * Verify required cryptographic PHP extensions before activation; deactivate cleanly via wp_die() when missing.
	 *
	 * @param callable(string):bool|null $probe Optional probe for unit testing.
	 */
	public static function enforce_prerequisites( ?callable $probe = null ): void {
		$check   = $probe ?? static fn( string $ext ): bool => extension_loaded( $ext );
		$missing = array_values( array_filter( self::REQUIRED_EXTENSIONS, static fn( string $ext ): bool => ! $check( $ext ) ) );
		if ( [] === $missing ) {
			return;
		}
		if ( ! function_exists( 'deactivate_plugins' ) && defined( 'ABSPATH' ) && is_file( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( function_exists( 'deactivate_plugins' ) && defined( 'WM_HINSCHG_FILE' ) ) {
			deactivate_plugins( plugin_basename( WM_HINSCHG_FILE ) );
		}
		if ( function_exists( 'wp_die' ) ) {
			wp_die(
				esc_html(
					sprintf(
						/* translators: %s: comma-separated list of missing PHP extensions */
						__( 'WM HinSchG Whistleblower Desk konnte nicht aktiviert werden, da folgende erforderliche PHP-Erweiterungen fehlen: %s.', 'wm-hinschg-whistleblower' ),
						implode( ', ', $missing )
					)
				),
				esc_html__( 'Fehlende PHP-Erweiterung', 'wm-hinschg-whistleblower' ),
				[ 'back_link' => true ]
			);
		}
	}

	public static function activate(): void {
		self::enforce_prerequisites();

		global $wpdb;

		// The role and the capability that gate the desk and the admin routes. Also applied from
		// Plugin::boot() on a version bump, because this hook does not fire on an update.
		Capabilities::install();

		$charset_collate = $wpdb->get_charset_collate();

		$table_reports  = $wpdb->prefix . 'wm_whistle_reports';
		$table_messages = $wpdb->prefix . 'wm_whistle_messages';
		$table_audit    = $wpdb->prefix . 'wm_whistle_audit_log';

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		// Reports: category, deadlines and the encrypted report; no name, e-mail or IP column.
		$sql_reports = "CREATE TABLE $table_reports (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			case_public_id varchar(32) NOT NULL,
			category varchar(64) NOT NULL DEFAULT 'general_compliance',
			encrypted_payload longtext NOT NULL,
			encrypted_key text NOT NULL,
			token_auth_hash varchar(64) NOT NULL,
			status varchar(32) NOT NULL DEFAULT 'submitted',
			ack_sla_deadline datetime NOT NULL,
			feedback_sla_deadline datetime NOT NULL,
			ack_sent_at datetime DEFAULT NULL,
			feedback_sent_at datetime DEFAULT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY uq_case_public_id (case_public_id),
			KEY idx_status (status),
			KEY idx_token_auth_hash (token_auth_hash)
		) $charset_collate;";
		dbDelta( $sql_reports );

		// Messages / Confidential Follow-up Chat
		$sql_messages = "CREATE TABLE $table_messages (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			report_id bigint(20) unsigned NOT NULL,
			sender_role varchar(20) NOT NULL DEFAULT 'whistleblower',
			encrypted_message longtext NOT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY idx_report_id (report_id)
		) $charset_collate;";
		dbDelta( $sql_messages );

		// Audit log: each entry carries an HMAC over its predecessor (Vault::log_audit_event). Tamper-evident rather than write-once.
		$sql_audit = "CREATE TABLE $table_audit (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			case_public_id varchar(32) NOT NULL,
			action varchar(64) NOT NULL,
			actor_role varchar(32) NOT NULL,
			actor_user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			previous_hash varchar(64) NOT NULL,
			current_hash varchar(64) NOT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY idx_case_id (case_public_id)
		) $charset_collate;";
		dbDelta( $sql_audit );

		// Schedule HinSchG § 17 Hourly Cron
		if ( ! wp_next_scheduled( 'wm_hinschg_hourly_sla_check' ) ) {
			wp_schedule_event( time(), 'hourly', 'wm_hinschg_hourly_sla_check' );
		}

		// Ensure Vault Key Pair exists without ever storing a plaintext PEM private key in wp_options.
		if ( ! get_option( 'wm_hinschg_public_key' ) ) {
			if ( defined( Vault::KEY_CONSTANT ) && '' !== (string) constant( Vault::KEY_CONSTANT ) ) {
				$ext_key = openssl_pkey_get_private( (string) constant( Vault::KEY_CONSTANT ), Vault::key_passphrase() ?? '' );
				if ( $ext_key ) {
					$ext_details = openssl_pkey_get_details( $ext_key );
					update_option( 'wm_hinschg_public_key', (string) ( $ext_details['key'] ?? '' ), false );
				}
				return;
			}

			$master     = Vault::master_key_bytes();
			$passphrase = Vault::key_passphrase();
			$fallback   = Vault::fallback_auth_key_bytes();

			// Zero-plaintext invariant: if no wp-config.php secret exists at all (no WM_HINSCHG_MASTER_KEY,
			// no WM_HINSCHG_KEY_PASSPHRASE, and no valid AUTH_KEY), NEVER generate a server-side private key
			// and NEVER write a PEM to wp_options or to a transient (transients hit wp_options in plaintext
			// when no Redis/Memcached object cache is active). Instead, leave the key pair unconfigured so
			// the administrator generates a Zero-Knowledge key pair locally in the browser or sets WM_HINSCHG_MASTER_KEY.
			if ( null === $master && null === $passphrase && null === $fallback ) {
				return;
			}

			$res = openssl_pkey_new( [
				'digest_alg'       => 'sha256',
				'private_key_bits' => 4096,
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
			] );

			if ( $res ) {
				$details    = openssl_pkey_get_details( $res );
				$public_key = (string) ( $details['key'] ?? '' );

				if ( null !== $master ) {
					openssl_pkey_export( $res, $raw_pem );
					$sealed = Vault::seal_private_key_sodium( $raw_pem, $master, Vault::SODIUM_PREFIX );
					update_option( Vault::KEY_OPTION, $sealed, false );
				} elseif ( null !== $passphrase ) {
					openssl_pkey_export( $res, $encrypted_pem, $passphrase );
					update_option( Vault::KEY_OPTION, $encrypted_pem, false );
				} else {
					openssl_pkey_export( $res, $raw_pem );
					$sealed = Vault::seal_private_key_sodium( $raw_pem, $fallback, Vault::SODIUM_AUTHKEY_PREFIX );
					update_option( Vault::KEY_OPTION, $sealed, false );
				}

				update_option( 'wm_hinschg_public_key', $public_key, false );
			}
		}
	}

	/**
	 * Re-seal or re-export the existing private key encrypted with WM_HINSCHG_MASTER_KEY (Libsodium) or WM_HINSCHG_KEY_PASSPHRASE.
	 *
	 * For installs that already ran: the key pair exists and the reports are sealed against its
	 * public half, so generating a new pair would strand every report filed so far. The pair is
	 * kept and only the STORED FORM changes, which is why this is a migration and not a rotation.
	 *
	 * @return array{ok:bool, message:string}
	 */
	public static function protect_private_key(): array {
		$master     = Vault::master_key_bytes();
		$passphrase = Vault::key_passphrase();

		if ( null === $master && null === $passphrase ) {
			return [
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: master key constant name, 2: passphrase constant name */
					__( 'In wp-config.php ist weder %1$s noch %2$s gesetzt. Ohne ein Geheimnis in wp-config.php kann der Schlüssel nicht verschlüsselt werden.', 'wm-hinschg-whistleblower' ),
					Vault::MASTER_KEY_CONSTANT,
					Vault::PASSPHRASE_CONSTANT
				),
			];
		}

		$stored = (string) get_option( Vault::KEY_OPTION, '' );
		if ( '' === $stored ) {
			return [
				'ok'      => false,
				'message' => __( 'In der Datenbank liegt kein privater Schlüssel. Es gibt nichts zu migrieren.', 'wm-hinschg-whistleblower' ),
			];
		}

		// Path A: WM_HINSCHG_MASTER_KEY is configured — target format is sodium_crypto_secretbox (wm-sodium-v1:).
		if ( null !== $master ) {
			if ( str_starts_with( $stored, Vault::SODIUM_PREFIX ) ) {
				$opened = Vault::open_private_key_sodium( $stored );
				if ( null === $opened || false === openssl_pkey_get_private( $opened ) ) {
					return [
						'ok'      => false,
						'message' => __( 'Der gespeicherte Schlüssel lässt sich nicht mit WM_HINSCHG_MASTER_KEY entschlüsseln. Bitte den ursprünglichen Hauptschlüssel wiederherstellen; es wurde nichts überschrieben.', 'wm-hinschg-whistleblower' ),
					];
				}
				return [
					'ok'      => true,
					'message' => __( 'Der private Schlüssel ist bereits per Libsodium (WM_HINSCHG_MASTER_KEY) verschlüsselt. Nichts zu tun.', 'wm-hinschg-whistleblower' ),
				];
			}

			$raw_pem = null;
			if ( str_starts_with( $stored, Vault::SODIUM_AUTHKEY_PREFIX ) ) {
				$raw_pem = Vault::open_private_key_sodium( $stored );
			} elseif ( false !== openssl_pkey_get_private( $stored ) ) {
				$raw_pem = $stored;
			} elseif ( null !== $passphrase ) {
				$res_with = openssl_pkey_get_private( $stored, $passphrase );
				if ( false !== $res_with ) {
					openssl_pkey_export( $res_with, $exported_plain );
					$raw_pem = $exported_plain;
				}
			}

			if ( null === $raw_pem || '' === $raw_pem || false === openssl_pkey_get_private( $raw_pem ) ) {
				return [
					'ok'      => false,
					'message' => __( 'Der gespeicherte Schlüssel lässt sich nicht öffnen. Es wurde nichts überschrieben.', 'wm-hinschg-whistleblower' ),
				];
			}

			$sealed = Vault::seal_private_key_sodium( $raw_pem, $master, Vault::SODIUM_PREFIX );
			if ( Vault::open_private_key_sodium( $sealed ) !== $raw_pem ) {
				return [
					'ok'      => false,
					'message' => __( 'Der per Libsodium versiegelte Schlüssel ließ sich nicht verifizieren. Es wurde nichts überschrieben.', 'wm-hinschg-whistleblower' ),
				];
			}

			update_option( Vault::KEY_OPTION, $sealed, false );
			return [
				'ok'      => true,
				'message' => __( 'Der private Schlüssel liegt jetzt per Libsodium (WM_HINSCHG_MASTER_KEY) verschlüsselt in der Datenbank. Ein Datenbank-Abzug allein entschlüsselt keine Meldung mehr.', 'wm-hinschg-whistleblower' ),
			];
		}

		// Path B: WM_HINSCHG_KEY_PASSPHRASE is configured (OpenSSL encrypted PEM).
		$without = openssl_pkey_get_private( $stored );
		if ( false === $without ) {
			$with = openssl_pkey_get_private( $stored, $passphrase );
			if ( false === $with ) {
				return [
					'ok'      => false,
					'message' => __( 'Der gespeicherte Schlüssel lässt sich weder ohne noch mit der konfigurierten Passphrase öffnen. Er wurde mit einer anderen Passphrase verschlüsselt — bitte die alte wiederherstellen, sonst ist keine Meldung mehr lesbar.', 'wm-hinschg-whistleblower' ),
				];
			}
			return [
				'ok'      => true,
				'message' => __( 'Der private Schlüssel ist bereits mit der konfigurierten Passphrase verschlüsselt. Nichts zu tun.', 'wm-hinschg-whistleblower' ),
			];
		}

		$encrypted = '';
		if ( ! openssl_pkey_export( $without, $encrypted, $passphrase ) || '' === $encrypted ) {
			return [
				'ok'      => false,
				'message' => __( 'Der Schlüssel konnte nicht verschlüsselt exportiert werden. Der gespeicherte Schlüssel bleibt unverändert.', 'wm-hinschg-whistleblower' ),
			];
		}

		// Verified BEFORE the old copy is overwritten. Writing first and checking after is how a
		// migration turns every existing report into ciphertext nobody can open.
		//
		// Defence in depth with NO test behind it, on purpose and stated rather than pretended: it
		// only fires if openssl_pkey_export() returns success and material that openssl cannot read
		// back, which no test can provoke. A mutation was written for it on 2026-09-19 and SURVIVED
		// — it was removed instead of kept as a gate that cannot fail.
		if ( false === openssl_pkey_get_private( $encrypted, $passphrase ) ) {
			return [
				'ok'      => false,
				'message' => __( 'Der verschlüsselte Schlüssel ließ sich nicht wieder öffnen. Es wurde nichts überschrieben.', 'wm-hinschg-whistleblower' ),
			];
		}

		update_option( Vault::KEY_OPTION, $encrypted );

		return [
			'ok'      => true,
			'message' => __( 'Der private Schlüssel liegt jetzt verschlüsselt in der Datenbank. Ein Datenbank-Abzug allein entschlüsselt keine Meldung mehr. Die Passphrase in wp-config.php ist ab sofort unverzichtbar: ohne sie ist keine Meldung mehr lesbar.', 'wm-hinschg-whistleblower' ),
		];
	}

	public static function deactivate(): void {
		wp_clear_scheduled_hook( 'wm_hinschg_hourly_sla_check' );
	}
}
