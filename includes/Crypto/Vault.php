<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Crypto;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Vault {
	/** Whole private key in wp-config.php: the database holds nothing that can decrypt a report. */
	public const KEY_CONSTANT = 'WM_HINSCHG_PRIVATE_KEY';

	/** Master secret in wp-config.php: seals the RSA private key in wp_options with sodium_crypto_secretbox via HKDF-SHA256. */
	public const MASTER_KEY_CONSTANT = 'WM_HINSCHG_MASTER_KEY';

	/** Passphrase in wp-config.php: the key stays in wp_options, encrypted with it. */
	public const PASSPHRASE_CONSTANT = 'WM_HINSCHG_KEY_PASSPHRASE';

	/** Dedicated audit-chain secret in wp-config.php (derived via HKDF-SHA256, independent of AUTH_KEY). */
	public const AUDIT_KEY_CONSTANT = 'WM_HINSCHG_AUDIT_KEY';

	/** MySQL advisory lock name serialising concurrent audit-chain appends. */
	public const AUDIT_LOCK_NAME = 'wm_hinschg_audit_chain';

	public const KEY_OPTION                  = 'wm_hinschg_private_key';
	public const RECOVERY_PUBLIC_KEY_OPTION  = 'wm_hinschg_recovery_public_key';
	public const UNINSTALL_DELETE_OPTION     = 'wm_hinschg_delete_data_on_uninstall';

	public const SODIUM_PREFIX         = 'wm-sodium-v1:';
	public const SODIUM_AUTHKEY_PREFIX = 'wm-sodium-authkey-v1:';

	private string $public_key;
	private string $private_key;

	public function __construct() {
		$this->public_key  = (string) get_option( 'wm_hinschg_public_key', '' );
		$this->private_key = (string) get_option( self::KEY_OPTION, '' );
		$this->maybe_migrate_legacy_key();
	}

	/**
	 * Derive a 32-byte Libsodium secretbox key from WM_HINSCHG_MASTER_KEY via HKDF-SHA256, or null when unset.
	 */
	public static function master_key_bytes(): ?string {
		if ( ! defined( self::MASTER_KEY_CONSTANT ) ) {
			return null;
		}
		$raw = trim( (string) constant( self::MASTER_KEY_CONSTANT ) );
		if ( '' === $raw ) {
			return null;
		}
		return hash_hkdf( 'sha256', $raw, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'wm-hinschg-vault-secretbox-v1' );
	}

	/**
	 * Derive a 32-byte Libsodium secretbox key from AUTH_KEY / SECURE_AUTH_KEY in wp-config.php for out-of-the-box activation.
	 */
	public static function fallback_auth_key_bytes(): ?string {
		if ( ! defined( 'AUTH_KEY' ) ) {
			return null;
		}
		$auth = trim( (string) AUTH_KEY );
		if ( '' === $auth || 'put your unique phrase here' === $auth ) {
			return null;
		}
		$secure = defined( 'SECURE_AUTH_KEY' ) ? trim( (string) SECURE_AUTH_KEY ) : '';
		return hash_hkdf( 'sha256', $auth . '|' . $secure, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'wm-hinschg-wpconfig-authkey-v1' );
	}

	/**
	 * Seal a PEM private key with sodium_crypto_secretbox (XSalsa20-Poly1305).
	 */
	public static function seal_private_key_sodium( string $pem, ?string $derived_key = null, string $prefix = self::SODIUM_PREFIX ): string {
		$box_key = $derived_key ?? ( self::SODIUM_AUTHKEY_PREFIX === $prefix ? self::fallback_auth_key_bytes() : self::master_key_bytes() );
		if ( null === $box_key || SODIUM_CRYPTO_SECRETBOX_KEYBYTES !== strlen( $box_key ) ) {
			throw new \RuntimeException( 'Missing 32-byte master key for sodium_crypto_secretbox.' );
		}
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = sodium_crypto_secretbox( $pem, $nonce, $box_key );
		return $prefix . base64_encode( $nonce . $box );
	}

	/**
	 * Open a sodium_crypto_secretbox-sealed PEM private key, returning null on missing key or authentication failure.
	 */
	public static function open_private_key_sodium( string $stored ): ?string {
		if ( str_starts_with( $stored, self::SODIUM_PREFIX ) ) {
			$box_key = self::master_key_bytes();
			$encoded = substr( $stored, strlen( self::SODIUM_PREFIX ) );
		} elseif ( str_starts_with( $stored, self::SODIUM_AUTHKEY_PREFIX ) ) {
			$box_key = self::fallback_auth_key_bytes();
			$encoded = substr( $stored, strlen( self::SODIUM_AUTHKEY_PREFIX ) );
		} else {
			return null;
		}

		if ( null === $box_key ) {
			return null;
		}

		$raw = base64_decode( $encoded, true );
		if ( ! is_string( $raw ) || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
			return null;
		}

		$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$opened = sodium_crypto_secretbox_open( $cipher, $nonce, $box_key );
		return is_string( $opened ) ? $opened : null;
	}

	/**
	 * Transparently migrate a legacy plaintext PEM in wp_options to sodium_crypto_secretbox
	 * (using WM_HINSCHG_MASTER_KEY when defined, or HKDF(AUTH_KEY|SECURE_AUTH_KEY) on upgraded installs),
	 * and transparently promote an AUTH_KEY-sealed key to WM_HINSCHG_MASTER_KEY once configured.
	 */
	private function maybe_migrate_legacy_key(): void {
		if ( defined( self::KEY_CONSTANT ) && '' !== (string) constant( self::KEY_CONSTANT ) ) {
			return;
		}
		if ( '' === $this->private_key ) {
			return;
		}
		$master = self::master_key_bytes();
		if ( null !== $master && str_starts_with( $this->private_key, self::SODIUM_AUTHKEY_PREFIX ) ) {
			$opened = self::open_private_key_sodium( $this->private_key );
			if ( null !== $opened ) {
				$sealed = self::seal_private_key_sodium( $opened, $master, self::SODIUM_PREFIX );
				if ( self::open_private_key_sodium( $sealed ) === $opened ) {
					update_option( self::KEY_OPTION, $sealed, false );
					$this->private_key = $sealed;
				}
			}
			return;
		}
		$fallback = ( null === $master && null === self::key_passphrase() ) ? self::fallback_auth_key_bytes() : null;
		$box_key  = $master ?? $fallback;
		$prefix   = null !== $master ? self::SODIUM_PREFIX : self::SODIUM_AUTHKEY_PREFIX;
		if ( null === $box_key ) {
			return;
		}
		$trimmed = ltrim( $this->private_key );
		if ( ! str_starts_with( $trimmed, '-----BEGIN ' . 'PRIVATE KEY-----' ) && ! str_starts_with( $trimmed, '-----BEGIN RSA ' . 'PRIVATE KEY-----' ) ) {
			return;
		}
		if ( false === openssl_pkey_get_private( $this->private_key ) ) {
			return;
		}
		$sealed = self::seal_private_key_sodium( $this->private_key, $box_key, $prefix );
		if ( self::open_private_key_sodium( $sealed ) !== $this->private_key ) {
			return;
		}
		update_option( self::KEY_OPTION, $sealed, false );
		$this->private_key = $sealed;
	}

	/**
	 * Where the private key comes from on this install, and what a database dump is worth.
	 *
	 * @return array{source:string, dump_is_enough:bool, label:string}
	 */
	public static function private_key_source(): array {
		if ( defined( self::KEY_CONSTANT ) && '' !== (string) constant( self::KEY_CONSTANT ) ) {
			return [
				'source'         => 'wp-config',
				'dump_is_enough' => false,
				'label'          => __( 'Der private Schlüssel steht in wp-config.php. Ein Datenbank-Abzug allein entschlüsselt keine Meldung.', 'wm-hinschg-whistleblower' ),
			];
		}

		$stored = (string) get_option( self::KEY_OPTION, '' );

		if ( str_starts_with( $stored, self::SODIUM_PREFIX ) || null !== self::master_key_bytes() ) {
			return [
				'source'         => 'database-sodium',
				'dump_is_enough' => false,
				'label'          => __( 'Der private Schlüssel liegt per Libsodium (XSalsa20-Poly1305) verschlüsselt in der Datenbank; der Hauptschlüssel (WM_HINSCHG_MASTER_KEY) steht in wp-config.php. Ein Datenbank-Abzug allein entschlüsselt keine Meldung.', 'wm-hinschg-whistleblower' ),
			];
		}

		if ( defined( self::PASSPHRASE_CONSTANT ) && '' !== (string) constant( self::PASSPHRASE_CONSTANT ) ) {
			return [
				'source'         => 'database-encrypted',
				'dump_is_enough' => false,
				'label'          => __( 'Der private Schlüssel liegt verschlüsselt in der Datenbank; die Passphrase steht in wp-config.php. Ein Datenbank-Abzug allein entschlüsselt keine Meldung.', 'wm-hinschg-whistleblower' ),
			];
		}

		if ( str_starts_with( $stored, self::SODIUM_AUTHKEY_PREFIX ) ) {
			return [
				'source'         => 'database-authkey-sodium',
				'dump_is_enough' => false,
				'label'          => __( 'Der private Schlüssel liegt per Libsodium verschlüsselt in der Datenbank (abgeleitet aus AUTH_KEY in wp-config.php). Ein Datenbank-Abzug allein entschlüsselt keine Meldung; für unabhängige Schlüsselrotation empfiehlt sich WM_HINSCHG_MASTER_KEY.', 'wm-hinschg-whistleblower' ),
			];
		}

		if ( '' === $stored && '' !== (string) get_option( 'wm_hinschg_public_key', '' ) ) {
			return [
				'source'         => 'offline-custody',
				'dump_is_enough' => false,
				'label'          => __( 'In der Datenbank liegt nur der öffentliche Schlüssel (Offline-Verwahrung). Neue Meldungen werden versiegelt; zum Lesen nutzen Sie die lokale Browser-Entschlüsselung in der Fallansicht oder hinterlegen WM_HINSCHG_PRIVATE_KEY in der wp-config.php.', 'wm-hinschg-whistleblower' ),
			];
		}

		if ( '' === $stored && '' === (string) get_option( 'wm_hinschg_public_key', '' ) ) {
			return [
				'source'         => 'unconfigured-zero-knowledge',
				'dump_is_enough' => false,
				'label'          => __( 'Es ist noch kein Schlüsselpaar hinterlegt. Erzeugen Sie im Reiter „Schlüsselverwahrung“ ein lokales Browser-Schlüsselpaar (Offline-Verwahrung) oder hinterlegen Sie WM_HINSCHG_MASTER_KEY in der wp-config.php.', 'wm-hinschg-whistleblower' ),
			];
		}

		return [
			'source'         => 'database-plain',
			'dump_is_enough' => true,
			'label'          => __( 'Der private Schlüssel liegt unverschlüsselt in der Datenbank, neben den Meldungen. Wer einen vollständigen Datenbank-Abzug hat, kann jede Meldung entschlüsseln.', 'wm-hinschg-whistleblower' ),
		];
	}

	/**
	 * Validate an SPKI RSA public key PEM (>= 2048 bits) and refuse any private key material.
	 *
	 * @param string $public_pem           Candidate PEM string.
	 * @param string $private_rejected_msg Error message when private key headers are detected.
	 * @return array{ok:bool, key:string, message:string}
	 */
	private static function validate_rsa_public_key( string $public_pem, string $private_rejected_msg ): array {
		if ( str_contains( $public_pem, 'PRIVATE KEY' ) ) {
			return [
				'ok'      => false,
				'key'     => '',
				'message' => $private_rejected_msg,
			];
		}

		$res = @openssl_pkey_get_public( $public_pem ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $res ) {
			return [
				'ok'      => false,
				'key'     => '',
				'message' => __( 'Der übermittelte Text ist kein gültiger öffentlicher RSA-Schlüssel im PEM-Format.', 'wm-hinschg-whistleblower' ),
			];
		}

		$details = openssl_pkey_get_details( $res );
		if ( ! is_array( $details ) || OPENSSL_KEYTYPE_RSA !== ( $details['type'] ?? -1 ) || (int) ( $details['bits'] ?? 0 ) < 2048 || empty( $details['key'] ) ) {
			return [
				'ok'      => false,
				'key'     => '',
				'message' => __( 'Der öffentliche Schlüssel muss ein RSA-Schlüssel mit mindestens 2048 Bit (empfohlen: 4096 Bit) sein.', 'wm-hinschg-whistleblower' ),
			];
		}

		return [
			'ok'      => true,
			'key'     => (string) $details['key'],
			'message' => '',
		];
	}

	/**
	 * Install a client-generated RSA public key (Zero-Knowledge / Offline Custody) and remove any stored private key.
	 *
	 * @param string $public_pem      SPKI RSA public key PEM generated in the administrator's browser.
	 * @param bool   $confirm_replace Required when reports already exist in wm_whistle_reports.
	 * @return array{ok:bool, message:string}
	 */
	public static function install_zero_knowledge_public_key( string $public_pem, bool $confirm_replace = false ): array {
		$validated = self::validate_rsa_public_key(
			$public_pem,
			__( 'Sicherheitsabbruch: Es wurde ein privater Schlüssel übermittelt. In der Offline-Verwahrung darf ausschließlich der öffentliche Schlüssel (BEGIN PUBLIC KEY) gespeichert werden.', 'wm-hinschg-whistleblower' )
		);
		if ( ! $validated['ok'] ) {
			return [
				'ok'      => false,
				'message' => $validated['message'],
			];
		}

		global $wpdb;
		if ( isset( $wpdb ) && is_object( $wpdb ) && isset( $wpdb->prefix ) ) {
			$table_reports = $wpdb->prefix . 'wm_whistle_reports';
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$existing = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_reports} WHERE id >= %d", 0 ) );
			if ( $existing > 0 && ! $confirm_replace ) {
				return [
					'ok'      => false,
					'message' => __( 'Es sind bereits verschlüsselte Vorgänge vorhanden. Bitte bestätigen Sie den Schlüsselwechsel ausdrücklich, da bestehende Meldungen weiterhin den bisherigen privaten Schlüssel benötigen.', 'wm-hinschg-whistleblower' ),
				];
			}
		}

		update_option( 'wm_hinschg_public_key', $validated['key'], false );
		if ( function_exists( 'delete_option' ) ) {
			delete_option( self::KEY_OPTION );
		} else {
			update_option( self::KEY_OPTION, '', false );
		}

		return [
			'ok'      => true,
			'message' => __( 'Öffentlicher RSA-Schlüssel gespeichert und serverseitiger Privatschlüssel entfernt (Offline-Verwahrung aktiv).', 'wm-hinschg-whistleblower' ),
		];
	}

	/**
	 * Install or clear the optional secondary RSA public key for a 2nd Meldestelle officer or Ombudsperson (§ 8 Abs. 1, § 15 HinSchG).
	 *
	 * @param string $public_pem SPKI RSA public key PEM (>= 2048 bits), or empty string to remove the recovery key.
	 * @return array{ok:bool, message:string}
	 */
	public static function install_recovery_public_key( string $public_pem ): array {
		$trimmed = trim( $public_pem );
		if ( '' === $trimmed ) {
			if ( function_exists( 'delete_option' ) ) {
				delete_option( self::RECOVERY_PUBLIC_KEY_OPTION );
			} else {
				update_option( self::RECOVERY_PUBLIC_KEY_OPTION, '', false );
			}
			return [
				'ok'      => true,
				'message' => __( 'Notfall- und Vertretungsschlüssel entfernt.', 'wm-hinschg-whistleblower' ),
			];
		}

		$validated = self::validate_rsa_public_key(
			$trimmed,
			__( 'Sicherheitsabbruch: Es wurde ein privater Schlüssel übermittelt. Als Notfall- und Vertretungsschlüssel darf ausschließlich der öffentliche Schlüssel (BEGIN PUBLIC KEY) gespeichert werden.', 'wm-hinschg-whistleblower' )
		);
		if ( ! $validated['ok'] ) {
			return [
				'ok'      => false,
				'message' => $validated['message'],
			];
		}

		update_option( self::RECOVERY_PUBLIC_KEY_OPTION, $validated['key'], false );

		return [
			'ok'      => true,
			'message' => __( 'Öffentlicher Notfall- und Vertretungsschlüssel (2. betraute Person / Ombudsperson) gespeichert.', 'wm-hinschg-whistleblower' ),
		];
	}

	/** The passphrase the key is exported with, or null when the install configured none. */
	public static function key_passphrase(): ?string {
		if ( defined( self::PASSPHRASE_CONSTANT ) ) {
			$value = (string) constant( self::PASSPHRASE_CONSTANT );
			if ( '' !== $value ) {
				return $value;
			}
		}
		return null;
	}

	/**
	 * The private key material, from wherever this install keeps it.
	 *
	 * wp-config.php wins over the database on purpose: an operator who moved the key out expects the
	 * old copy to stop mattering, and silently preferring a stale option would make the move look
	 * done while changing nothing.
	 */
	private function private_key_pem(): string {
		if ( defined( self::KEY_CONSTANT ) ) {
			$pem = (string) constant( self::KEY_CONSTANT );
			if ( '' !== $pem ) {
				return $pem;
			}
		}
		if ( str_starts_with( $this->private_key, self::SODIUM_PREFIX ) || str_starts_with( $this->private_key, self::SODIUM_AUTHKEY_PREFIX ) ) {
			return self::open_private_key_sodium( $this->private_key ) ?? '';
		}
		return $this->private_key;
	}

	/**
	 * Encrypt report payload with AES-256-GCM and seal the symmetric key with RSA-4096
	 * (plus optional secondary recovery RSA key for a 2nd Meldestelle officer / Ombudsperson).
	 *
	 * @param array<string, mixed> $payload
	 * @return array{payload: string, key: string, tag: string, iv: string, recovery_key?: string}
	 */
	public function encrypt_envelope( array $payload ): array {
		$plaintext = wp_json_encode( $payload, JSON_THROW_ON_ERROR );
		$aes_key   = random_bytes( 32 );
		$iv        = random_bytes( 12 ); // 96-bit IV for AES-GCM
		$tag       = '';

		$ciphertext = openssl_encrypt(
			$plaintext,
			'aes-256-gcm',
			$aes_key,
			OPENSSL_RAW_DATA,
			$iv,
			$tag
		);

		if ( $ciphertext === false ) {
			throw new \RuntimeException( 'Failed to encrypt report payload with AES-256-GCM.' );
		}

		// Encrypt symmetric AES key with RSA-4096 Public Key
		$encrypted_key = '';
		$res = openssl_pkey_get_public( $this->public_key );
		if ( ! $res ) {
			throw new \RuntimeException( 'Invalid RSA public key in Vault.' );
		}

		openssl_public_encrypt( $aes_key, $encrypted_key, $res, OPENSSL_PKCS1_OAEP_PADDING );

		$envelope = [
			'payload' => base64_encode( $ciphertext ),
			'key'     => base64_encode( $encrypted_key ),
			'tag'     => base64_encode( $tag ),
			'iv'      => base64_encode( $iv ),
		];

		$recovery_pem = trim( (string) get_option( self::RECOVERY_PUBLIC_KEY_OPTION, '' ) );
		if ( '' !== $recovery_pem ) {
			$recovery_res = @openssl_pkey_get_public( $recovery_pem ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false !== $recovery_res ) {
				$encrypted_recovery_key = '';
				if ( openssl_public_encrypt( $aes_key, $encrypted_recovery_key, $recovery_res, OPENSSL_PKCS1_OAEP_PADDING ) && '' !== $encrypted_recovery_key ) {
					$envelope['recovery_key'] = base64_encode( $encrypted_recovery_key );
				}
			}
		}

		return $envelope;
	}

	/**
	 * Serialise envelope key metadata for wm_whistle_reports.encrypted_key, preserving recovery_key when present.
	 *
	 * @param array{key: string, tag: string, iv: string, recovery_key?: string} $envelope
	 */
	public static function encode_key_meta( array $envelope ): string {
		$meta = [
			'key' => (string) ( $envelope['key'] ?? '' ),
			'tag' => (string) ( $envelope['tag'] ?? '' ),
			'iv'  => (string) ( $envelope['iv'] ?? '' ),
		];
		if ( ! empty( $envelope['recovery_key'] ) ) {
			$meta['recovery_key'] = (string) $envelope['recovery_key'];
		}
		return (string) wp_json_encode( $meta, JSON_THROW_ON_ERROR );
	}

	/**
	 * Decrypt envelope using RSA private key and AES-256-GCM.
	 *
	 * @param string $payload_b64
	 * @param string $key_b64
	 * @param string $tag_b64
	 * @param string $iv_b64
	 * @return array<string, mixed>
	 */
	public function decrypt_envelope( string $payload_b64, string $key_b64, string $tag_b64, string $iv_b64 ): array {
		$encrypted_key = base64_decode( $key_b64, true );
		$ciphertext    = base64_decode( $payload_b64, true );
		$tag           = base64_decode( $tag_b64, true );
		$iv            = base64_decode( $iv_b64, true );

		// The passphrase is passed whenever the install has one: openssl_pkey_get_private() ignores
		// it for an unencrypted key, so one call covers both the migrated and the not-yet-migrated
		// state without asking which one this is.
		$passphrase = self::key_passphrase();
		$pem        = $this->private_key_pem();
		$res        = null === $passphrase
			? openssl_pkey_get_private( $pem )
			: openssl_pkey_get_private( $pem, $passphrase );

		if ( ! $res ) {
			// Naming the source turns "it does not work" into one of two different problems: a key
			// that is not there, or a passphrase that does not open the key that is.
			$source = self::private_key_source();
			throw new \RuntimeException(
				// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- internal source identifier from private_key_source().
				sprintf( 'Private key unavailable or invalid (source: %s).', $source['source'] )
			);
		}

		$aes_key = '';
		openssl_private_decrypt( $encrypted_key, $aes_key, $res, OPENSSL_PKCS1_OAEP_PADDING );

		$decrypted = openssl_decrypt(
			$ciphertext,
			'aes-256-gcm',
			$aes_key,
			OPENSSL_RAW_DATA,
			$iv,
			$tag
		);

		if ( $decrypted === false ) {
			throw new \RuntimeException( 'Decryption failed: Integrity violation or invalid key.' );
		}

		return (array) json_decode( $decrypted, true );
	}

	/**
	 * Generate the access token handed to the reporting person once (64 hex chars, CSPRNG).
	 */
	public function generate_access_token(): string {
		return bin2hex( random_bytes( 32 ) );
	}

	/**
	 * Hash the access token for storage: HMAC-SHA256 keyed with wp_salt( 'auth' ). A move to a server with other salts
	 * invalidates every token (no Argon2id is involved; the comment said so until 2026-09-15).
	 */
	public function hash_token( string $token ): string {
		$salt = (string) wp_salt( 'auth' );
		return hash_hmac( 'sha256', $token, $salt );
	}

	/**
	 * Derive the server secret used to seal compliance officer replies for the reporting person's token view
	 * (in offline-custody mode the server has no RSA private key to reopen officer replies for /report/status).
	 */
	private static function reporter_box_secret(): string {
		$master = self::master_key_bytes();
		if ( null !== $master ) {
			return $master;
		}
		$auth = defined( 'AUTH_KEY' ) ? trim( (string) AUTH_KEY ) : '';
		if ( 'put your unique phrase here' === $auth ) {
			$auth = '';
		}
		$salt     = function_exists( 'wp_salt' ) ? trim( (string) wp_salt( 'secure_auth' ) ) : '';
		$material = '' !== $auth ? ( $auth . '|' . $salt ) : $salt;
		if ( '' === $material ) {
			throw new \RuntimeException( 'Missing secret material for reporter_box.' );
		}
		return hash_hkdf( 'sha256', $material, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'wm-hinschg-reporter-box-master-v1' );
	}

	/**
	 * Seal a compliance officer message symmetrically for the holder of $token_auth_hash (XSalsa20-Poly1305).
	 *
	 * @return array{nonce: string, box: string}
	 */
	private static function seal_for_reporter( string $text, string $token_auth_hash ): array {
		$key     = hash_hkdf( 'sha256', self::reporter_box_secret(), SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'wm-hinschg-reporter-reply-v1:' . $token_auth_hash );
		$nonce   = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$payload = (string) wp_json_encode( [ 'message' => $text ], JSON_THROW_ON_ERROR );
		$cipher  = sodium_crypto_secretbox( $payload, $nonce, $key );

		return [
			'nonce' => base64_encode( $nonce ),
			'box'   => base64_encode( $cipher ),
		];
	}

	/**
	 * Open the reporter_box on a compliance officer message for the verified token holder.
	 *
	 * @throws \RuntimeException When reporter_box is missing, tampered, or the token hash does not match.
	 * @return array{message: string, sealed: bool}
	 */
	public static function open_message_for_reporter( string $stored, string $token_auth_hash ): array {
		if ( '' === $token_auth_hash ) {
			throw new \RuntimeException( 'Missing token hash for reporter_box.' );
		}
		$decoded = json_decode( $stored, true );
		if (
			! is_array( $decoded )
			|| ! isset( $decoded['reporter_box'] )
			|| ! is_array( $decoded['reporter_box'] )
			|| ! isset( $decoded['reporter_box']['nonce'], $decoded['reporter_box']['box'] )
		) {
			throw new \RuntimeException( 'Reporter box unavailable.' );
		}

		$nonce = base64_decode( (string) $decoded['reporter_box']['nonce'], true );
		$box   = base64_decode( (string) $decoded['reporter_box']['box'], true );
		if (
			! is_string( $nonce )
			|| SODIUM_CRYPTO_SECRETBOX_NONCEBYTES !== strlen( $nonce )
			|| ! is_string( $box )
			|| strlen( $box ) <= SODIUM_CRYPTO_SECRETBOX_MACBYTES
		) {
			throw new \RuntimeException( 'Reporter box malformed.' );
		}

		$key   = hash_hkdf( 'sha256', self::reporter_box_secret(), SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'wm-hinschg-reporter-reply-v1:' . $token_auth_hash );
		$plain = sodium_crypto_secretbox_open( $box, $nonce, $key );
		if ( false === $plain ) {
			throw new \RuntimeException( 'Reporter box authentication failed.' );
		}

		$inner = json_decode( $plain, true );
		if ( ! is_array( $inner ) || ! array_key_exists( 'message', $inner ) ) {
			throw new \RuntimeException( 'Reporter box payload invalid.' );
		}

		return [
			'message' => (string) $inner['message'],
			'sealed'  => true,
		];
	}

	/**
	 * Seal one follow-up message with the same envelope as the report.
	 *
	 * Until 2026-09-14 wm_whistle_messages.encrypted_message held plain text: the whistleblower's
	 * replies, the officer's acknowledgment and the officer's answers sat beside an encrypted
	 * report, readable by anyone with a database dump, under a column named "encrypted" (fleet
	 * audit 2026-09-13 §6.2 #28). The stored form is the JSON envelope (payload/key/tag/iv), with
	 * a fresh AES key and IV per message; open_message() tells it apart from the rows written
	 * before.
	 *
	 * Whistleblower-authored messages remain 100% asymmetric RSA-OAEP Zero-Knowledge and NEVER carry
	 * reporter_box; only compliance_officer replies with a non-empty token_auth_hash attach it so
	 * the reporting person can still read replies when the server operates in offline-custody mode.
	 *
	 * @return string JSON envelope for the encrypted_message column.
	 */
	public function seal_message( string $text, string $sender_role, string $token_auth_hash = '' ): string {
		$envelope = $this->encrypt_envelope(
			[
				'message'     => $text,
				'sender_role' => $sender_role,
			]
		);

		if ( 'compliance_officer' === $sender_role && '' !== $token_auth_hash ) {
			$envelope['reporter_box'] = self::seal_for_reporter( $text, $token_auth_hash );
		}

		return (string) wp_json_encode( $envelope, JSON_THROW_ON_ERROR );
	}

	/**
	 * Open a stored message: a sealed envelope is decrypted, a legacy plain text row passes
	 * through flagged.
	 *
	 * @throws \RuntimeException When an envelope does not decrypt (wrong key or tampered).
	 * @return array{message: string, sealed: bool}
	 */
	public function open_message( string $stored ): array {
		$decoded = json_decode( $stored, true );
		if ( ! is_array( $decoded ) || ! isset( $decoded['payload'], $decoded['key'], $decoded['tag'], $decoded['iv'] ) ) {
			return [
				'message' => $stored,
				'sealed'  => false,
			];
		}

		$plain = $this->decrypt_envelope(
			(string) $decoded['payload'],
			(string) $decoded['key'],
			(string) $decoded['tag'],
			(string) $decoded['iv']
		);

		return [
			'message' => (string) ( $plain['message'] ?? '' ),
			'sealed'  => true,
		];
	}

	/** Predecessor of the first chained audit entry. */
	public const AUDIT_GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

	/** Mirrors the chain tip outside the log table so tail deletion is detectable. */
	public const AUDIT_TIP_OPTION = 'wm_whistle_audit_tip';

	/**
	 * Where the audit chain key comes from on this install.
	 *
	 * @return string 'wp-config-dedicated', 'wp-config', or 'database'.
	 */
	public static function audit_key_source(): string {
		if ( defined( self::AUDIT_KEY_CONSTANT ) && '' !== trim( (string) constant( self::AUDIT_KEY_CONSTANT ) ) ) {
			return 'wp-config-dedicated';
		}
		return defined( 'AUTH_KEY' ) && '' !== (string) AUTH_KEY ? 'wp-config' : 'database';
	}

	/**
	 * Legacy AUTH_KEY / auth-salt HMAC for dual-verifying entries written before WM_HINSCHG_AUDIT_KEY was configured.
	 */
	private static function legacy_audit_hash( string $payload ): string {
		$key = ( defined( 'AUTH_KEY' ) && '' !== (string) AUTH_KEY ) ? (string) AUTH_KEY : (string) wp_salt( 'auth' );
		return hash_hmac( 'sha256', $payload, $key );
	}

	/**
	 * Canonical serialisation of an audit entry.
	 *
	 * One function, used by both the writer and the verifier. They used to carry two separate
	 * copies of the same sprintf() — one here, one in the WP-CLI command — which is how a
	 * security-critical formula drifts without anything failing.
	 *
	 * @param string $case_public_id Case reference.
	 * @param string $action         Action key.
	 * @param string $actor_role     Role of the actor.
	 * @param int    $user_id        Acting user.
	 * @param string $prev_hash      Predecessor hash.
	 * @param string $created_at     Timestamp as stored.
	 * @return string
	 */
	public static function audit_payload( string $case_public_id, string $action, string $actor_role, int $user_id, string $prev_hash, string $created_at ): string {
		return sprintf( '%s|%s|%s|%d|%s|%s', $case_public_id, $action, $actor_role, $user_id, $prev_hash, $created_at );
	}

	/**
	 * Chain hash for an audit entry.
	 *
	 * Keyed, and that is the whole change. It used to be a plain hash( 'sha256', ... ) over values
	 * that are ALL stored in the row, so rewriting an entry and recomputing every hash after it
	 * needed no secret at all. Measured on a clean install: change an entry's action from
	 * "case_assigned" to "case_dismissed", re-sign the tail, and `wp hinschg verify-chain` still
	 * reported the log intact — on a system whose documentation promises non-repudiation for
	 * whistleblower reports.
	 *
	 * The key lives in wp-config.php, so database access alone can no longer mint a link.
	 *
	 * @param string $payload Canonical payload.
	 * @return string Hex HMAC.
	 */
	public static function audit_hash( string $payload ): string {
		if ( defined( self::AUDIT_KEY_CONSTANT ) && '' !== trim( (string) constant( self::AUDIT_KEY_CONSTANT ) ) ) {
			$derived = hash_hkdf( 'sha256', trim( (string) constant( self::AUDIT_KEY_CONSTANT ) ), 32, 'wm-hinschg-audit-chain-v1' );
			return hash_hmac( 'sha256', $payload, $derived );
		}
		return self::legacy_audit_hash( $payload );
	}

	/**
	 * Append an audit log entry linked to its predecessor under a MySQL advisory lock.
	 *
	 * @param string $case_public_id Case reference.
	 * @param string $action         Action key.
	 * @param string $actor_role     Role of the actor.
	 * @param int    $user_id        Acting user.
	 * @return string The entry hash.
	 */
	public function log_audit_event( string $case_public_id, string $action, string $actor_role, int $user_id = 0 ): string {
		global $wpdb;
		$table_audit = $wpdb->prefix . 'wm_whistle_audit_log';

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$locked = null;
		for ( $attempt = 0; $attempt < 6; ++$attempt ) {
			$locked = $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', self::AUDIT_LOCK_NAME, 0 ) );
			if ( '1' === (string) $locked || 1 === $locked ) {
				break;
			}
			if ( null === $locked || '0' !== (string) $locked ) {
				break;
			}
			if ( $attempt < 5 ) {
				usleep( random_int( 15000, 45000 ) );
			}
		}
		if ( '1' !== (string) $locked && 1 !== $locked ) {
			throw new \RuntimeException( 'Could not acquire audit chain lock.' );
		}

		try {
			$last_entry = $wpdb->get_row(
				$wpdb->prepare( "SELECT current_hash FROM {$table_audit} ORDER BY id DESC LIMIT %d", 1 ),
				ARRAY_A
			);
			$prev_hash = $last_entry['current_hash'] ?? self::AUDIT_GENESIS;

			$now          = current_time( 'mysql', true );
			$current_hash = self::audit_hash(
				self::audit_payload( $case_public_id, $action, $actor_role, $user_id, $prev_hash, $now )
			);

			$wpdb->insert(
				$table_audit,
				[
					'case_public_id' => $case_public_id,
					'action'         => $action,
					'actor_role'     => $actor_role,
					'actor_user_id'  => $user_id,
					'previous_hash'  => $prev_hash,
					'current_hash'   => $current_hash,
					'created_at'     => $now,
				],
				[ '%s', '%s', '%s', '%d', '%s', '%s', '%s' ]
			);

			$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_audit" );
			// Outside the log table on purpose, and HMAC-signed so an attacker with SQL write access
			// cannot truncate the tail AND rewrite wm_whistle_audit_tip without the wp-config.php key.
			update_option(
				self::AUDIT_TIP_OPTION,
				[
					'hash'  => $current_hash,
					'count' => $count,
					'sig'   => self::audit_hash( 'tip|' . $current_hash . '|' . $count ),
				],
				false
			);
		} finally {
			$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::AUDIT_LOCK_NAME ) );
		}
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		return $current_hash;
	}

	/**
	 * Walk the audit chain and report the first entry that does not verify.
	 *
	 * Entries written before the key was introduced carry a plain SHA-256 over the same payload.
	 * They are recognised and counted as unkeyed rather than reported as tampering — they were
	 * forgeable by anyone with database access, and calling them intact would repeat the claim
	 * this change removes.
	 *
	 * @return array{valid:bool, checked:int, unkeyed_legacy:int, broken_at_id:?int, error:?string, key_source:string}
	 */
	public static function verify_audit_chain(): array {
		global $wpdb;
		$table_audit = $wpdb->prefix . 'wm_whistle_audit_log';

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$table_audit} WHERE id >= %d ORDER BY id ASC", 0 ),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		$result = [
			'valid'          => true,
			'checked'        => 0,
			'unkeyed_legacy' => 0,
			'broken_at_id'   => null,
			'error'          => null,
			'key_source'     => self::audit_key_source(),
		];

		$tip = get_option( self::AUDIT_TIP_OPTION, null );

		if ( empty( $rows ) ) {
			if ( is_array( $tip ) && (int) ( $tip['count'] ?? 0 ) > 0 ) {
				$result['valid'] = false;
				$result['error'] = sprintf(
					/* translators: %d: previously recorded entry count */
					__( 'Das Protokoll ist leer, obwohl zuletzt %d Einträge verzeichnet waren.', 'wm-hinschg-whistleblower' ),
					(int) $tip['count']
				);
			}
			return $result;
		}

		$expected_prev  = self::AUDIT_GENESIS;
		$seen_keyed     = false;
		$seen_dedicated = false;

		foreach ( $rows as $row ) {
			$id = (int) $row['id'];

			if ( ! hash_equals( $expected_prev, (string) $row['previous_hash'] ) ) {
				$result['valid']        = false;
				$result['broken_at_id'] = $id;
				$result['error']        = sprintf(
					/* translators: %d: audit entry id */
					__( 'Kettenbruch bei Eintrag #%d: ein Eintrag wurde gelöscht, eingeschleust oder umsortiert.', 'wm-hinschg-whistleblower' ),
					$id
				);
				return $result;
			}

			$payload = self::audit_payload(
				(string) $row['case_public_id'],
				(string) $row['action'],
				(string) $row['actor_role'],
				(int) $row['actor_user_id'],
				(string) $row['previous_hash'],
				(string) $row['created_at']
			);

			if ( hash_equals( self::audit_hash( $payload ), (string) $row['current_hash'] ) ) {
				$seen_keyed = true;
				if ( 'wp-config-dedicated' === $result['key_source'] ) {
					$seen_dedicated = true;
				}
				++$result['checked'];
			} elseif ( 'wp-config-dedicated' === $result['key_source'] && ! $seen_dedicated && hash_equals( self::legacy_audit_hash( $payload ), (string) $row['current_hash'] ) ) {
				// Pre-WM_HINSCHG_AUDIT_KEY entry signed with AUTH_KEY before dedicated key rotation.
				// Tolerated only before the first dedicated-key entry so AUTH_KEY cannot forge new links afterwards.
				$seen_keyed = true;
				++$result['checked'];
			} elseif ( ! $seen_keyed && hash_equals( hash( 'sha256', $payload ), (string) $row['current_hash'] ) ) {
				// Pre-key entry: consistent with its own contents, but forgeable — not intact.
				// Tolerated only at the HEAD of the chain. An unkeyed row after a keyed one is not
				// a leftover, and since each entry binds its predecessor's hash, downgrading any
				// entry forces downgrading everything after it — so a partial downgrade always
				// lands here, and a full one is caught by the all-unkeyed check below.
				++$result['unkeyed_legacy'];
			} else {
				$result['valid']        = false;
				$result['broken_at_id'] = $id;
				$result['error']        = sprintf(
					// An HMAC mismatch cannot tell an edited entry from a different key: a site moved to a server with another AUTH_KEY
					// fails here at entry #1 (measured after a site migration, 2026-09-15). The message says both.
					/* translators: %d: audit entry id */
					__( 'Eintrag #%d passt nicht zu seiner Signatur: Er wurde nachträglich verändert, oder das Protokoll wurde mit einem anderen AUTH_KEY geschrieben (etwa vor einem Umzug der Website).', 'wm-hinschg-whistleblower' ),
					$id
				);
				return $result;
			}

			$expected_prev = (string) $row['current_hash'];
		}

		if ( is_array( $tip ) && isset( $tip['hash'] ) && ! hash_equals( (string) $tip['hash'], $expected_prev ) ) {
			$result['valid'] = false;
			$result['error'] = __( 'Das Ende des Protokolls passt nicht zum zuletzt verzeichneten Eintrag. Die neuesten Einträge wurden entfernt.', 'wm-hinschg-whistleblower' );
			return $result;
		}

		if ( is_array( $tip ) && isset( $tip['sig'], $tip['hash'], $tip['count'] ) ) {
			$tip_payload = 'tip|' . (string) $tip['hash'] . '|' . (int) $tip['count'];
			$tip_ok      = hash_equals( self::audit_hash( $tip_payload ), (string) $tip['sig'] )
				|| ( 'wp-config-dedicated' === $result['key_source'] && ! $seen_dedicated && hash_equals( self::legacy_audit_hash( $tip_payload ), (string) $tip['sig'] ) );
			if ( ! $tip_ok ) {
				$result['valid'] = false;
				$result['error'] = __( 'Die Signatur des verzeichneten Kettenendes ist ungültig. Das Protokollende wurde manipuliert.', 'wm-hinschg-whistleblower' );
				return $result;
			}
		}

		// The other half of the downgrade defence: if an attacker removes keyed_from_id, every row
		// would fall into the legacy branch above. A log that contains no keyed entry at all has
		// not been verified against anything an attacker could not compute, and saying otherwise
		// is the claim this whole change exists to remove.
		if ( 0 === $result['checked'] && $result['unkeyed_legacy'] > 0 ) {
			$result['valid'] = false;
			$result['error'] = __( 'Kein einziger Eintrag trägt eine geschlüsselte Signatur. Das Protokoll stammt entweder vollständig aus der Zeit vor dem Schlüssel oder wurde auf das alte, fälschbare Format zurückgestuft. In beiden Fällen ist es nicht überprüfbar.', 'wm-hinschg-whistleblower' );
		}

		return $result;
	}

	public function get_public_key(): string {
		return $this->public_key;
	}
}
