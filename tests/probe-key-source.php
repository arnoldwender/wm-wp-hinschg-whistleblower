<?php
/**
 * Probe for Vault::private_key_source() and Schema::protect_private_key(), one mode per process.
 *
 * Why a separate process: the three outcomes depend on PHP constants, and a constant cannot be
 * undefined or redefined. Testing them in one run would mean testing whichever one happened to be
 * defined first and calling the other two covered. The suite runs this file three times and reads
 * the JSON it prints.
 *
 * Usage: php tests/probe-key-source.php <plain|passphrase|wp-config|migrate|migrate-twice|migrate-wrong-passphrase>
 *
 * @package WMCyber\HinSchG
 */

declare(strict_types=1);

$mode = (string) ( $argv[1] ?? '' );

// --- the constants, before anything reads them -------------------------------------------------
$passphrase = 'probe-passphrase-not-a-secret';
if ( in_array( $mode, [ 'passphrase', 'migrate', 'migrate-twice', 'migrate-wrong-passphrase' ], true ) ) {
	define( 'WM_HINSCHG_KEY_PASSPHRASE', $passphrase );
}
if ( in_array( $mode, [ 'master-key', 'master-key-tampered' ], true ) ) {
	define( 'WM_HINSCHG_MASTER_KEY', 'probe-master-key-32-bytes-secret-2026' );
}
if ( 'activate-authkey' === $mode || 'multisite-init' === $mode ) {
	define( 'AUTH_KEY', 'probe-wp-config-auth-key-distinct-from-placeholder' );
	define( 'SECURE_AUTH_KEY', 'probe-wp-config-secure-auth-key-distinct' );
}
if ( 'audit-key-dual' === $mode ) {
	define( 'AUTH_KEY', 'probe-legacy-auth-key-before-rotation' );
	define( 'WM_HINSCHG_AUDIT_KEY', 'probe-dedicated-audit-key-after-rotation-2026' );
}

// --- the smallest WordPress that makes the two classes run -------------------------------------
$tmp_root = null;
if ( str_starts_with( $mode, 'activate-' ) || 'multisite-init' === $mode ) {
	$tmp_root = sys_get_temp_dir() . '/wm-hinschg-probe-' . getmypid();
	@mkdir( $tmp_root . '/wp-admin/includes', 0700, true );
	file_put_contents( $tmp_root . '/wp-admin/includes/upgrade.php', "<?php\n" );
	file_put_contents( $tmp_root . '/wp-admin/includes/plugin.php', "<?php\n" );
	define( 'ABSPATH', $tmp_root . '/' );
} else {
	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}
$GLOBALS['probe_options']         = [];
$GLOBALS['probe_current_blog_id'] = 1;
$GLOBALS['probe_blog_options']    = [];

function get_option( string $name, $default = false ) {
	if ( isset( $GLOBALS['probe_multisite_scoped'] ) ) {
		return $GLOBALS['probe_blog_options'][ $GLOBALS['probe_current_blog_id'] ][ $name ] ?? $default;
	}
	return $GLOBALS['probe_options'][ $name ] ?? $default;
}
function update_option( string $name, $value, $autoload = null ): bool {
	if ( isset( $GLOBALS['probe_multisite_scoped'] ) ) {
		$GLOBALS['probe_blog_options'][ $GLOBALS['probe_current_blog_id'] ][ $name ] = $value;
		return true;
	}
	$GLOBALS['probe_options'][ $name ] = $value;
	return true;
}
function delete_option( string $name ): bool {
	if ( isset( $GLOBALS['probe_multisite_scoped'] ) ) {
		unset( $GLOBALS['probe_blog_options'][ $GLOBALS['probe_current_blog_id'] ][ $name ] );
		return true;
	}
	unset( $GLOBALS['probe_options'][ $name ] );
	return true;
}
function __( string $text, string $domain = '' ): string {
	return $text;
}
function esc_html__( string $text, string $domain = '' ): string {
	return $text;
}
function wp_json_encode( $data, int $flags = 0, int $depth = 512 ) {
	return json_encode( $data, $flags, $depth );
}
function current_time( string $type, $gmt = 0 ) {
	return gmdate( 'Y-m-d H:i:s' );
}
function wp_salt( string $scheme = 'auth' ): string {
	return 'probe-salt-not-a-secret';
}
$GLOBALS['probe_transients'] = [];
function set_transient( string $name, $value, int $expiration = 0 ): bool {
	$GLOBALS['probe_transients'][ $name ] = $value;
	return true;
}
function get_transient( string $name ) {
	return $GLOBALS['probe_transients'][ $name ] ?? false;
}

require_once dirname( __DIR__ ) . '/includes/Crypto/Vault.php';

use WMCyber\HinSchG\Crypto\Vault;

if ( 'zero-knowledge-custody' === $mode ) {
	$zk_res     = openssl_pkey_new( [ 'digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ] );
	$zk_details = openssl_pkey_get_details( $zk_res );
	openssl_pkey_export( $zk_res, $zk_priv_pem );
	$zk_pub_pem = (string) ( $zk_details['key'] ?? '' );

	$GLOBALS['probe_options']['wm_hinschg_private_key'] = $zk_priv_pem;
	$refused_priv = Vault::install_zero_knowledge_public_key( $zk_pub_pem . "\n" . $zk_priv_pem );
	$installed    = Vault::install_zero_knowledge_public_key( $zk_pub_pem );
	$vault        = new Vault();
	$env          = $vault->encrypt_envelope( [ 'description' => 'ZK-Offline-Test' ] );
	$dec_plain    = '';
	$aes_key      = '';
	openssl_private_decrypt( (string) base64_decode( $env['key'], true ), $aes_key, $zk_res, OPENSSL_PKCS1_OAEP_PADDING );
	$raw_dec = openssl_decrypt( (string) base64_decode( $env['payload'], true ), 'aes-256-gcm', $aes_key, OPENSSL_RAW_DATA, (string) base64_decode( $env['iv'], true ), (string) base64_decode( $env['tag'], true ) );
	if ( is_string( $raw_dec ) ) {
		$dec_plain = (string) ( json_decode( $raw_dec, true )['description'] ?? '' );
	}

	echo json_encode(
		[
			'mode'             => $mode,
			'refused_private'  => false === $refused_priv['ok'],
			'installed_ok'     => true === $installed['ok'],
			'private_removed'  => ! isset( $GLOBALS['probe_options']['wm_hinschg_private_key'] ),
			'source'           => Vault::private_key_source(),
			'can_seal'         => isset( $env['payload'], $env['key'], $env['tag'], $env['iv'] ),
			'offline_decrypts' => 'ZK-Offline-Test' === $dec_plain,
		],
		JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
	), "\n";
	exit( 0 );
}

if ( 'audit-key-dual' === $mode ) {
	if ( ! defined( 'ARRAY_A' ) ) {
		define( 'ARRAY_A', 'ARRAY_A' );
	}
	$GLOBALS['audit_rows'] = [];
	$GLOBALS['wpdb']       = new class {
		public string $prefix = 'wp_';
		public function prepare( string $q, ...$a ): string {
			foreach ( $a as $v ) {
				$q = preg_replace( '/%[sd]/', is_int( $v ) ? (string) $v : "'" . addslashes( (string) $v ) . "'", $q, 1 );
			}
			return $q;
		}
		public function get_var( string $q ) {
			if ( str_contains( $q, 'GET_LOCK' ) || str_contains( $q, 'RELEASE_LOCK' ) ) {
				return '1';
			}
			if ( str_contains( $q, 'COUNT(*)' ) ) {
				return count( $GLOBALS['audit_rows'] );
			}
			return null;
		}
		public function get_row( string $q, string $out = 'OBJECT' ) {
			if ( empty( $GLOBALS['audit_rows'] ) ) {
				return null;
			}
			$last = end( $GLOBALS['audit_rows'] );
			return 'ARRAY_A' === $out ? $last : (object) $last;
		}
		public function get_results( string $q, string $out = 'OBJECT' ): array {
			return array_values( $GLOBALS['audit_rows'] );
		}
		public function insert( string $t, array $data ): int {
			$id = count( $GLOBALS['audit_rows'] ) + 1;
			$GLOBALS['audit_rows'][ $id ] = array_merge( [ 'id' => $id ], $data );
			return 1;
		}
	};

	// Row #1: pre-existing row signed with legacy AUTH_KEY before WM_HINSCHG_AUDIT_KEY was added.
	$ts1     = '2026-11-18 10:00:00';
	$pay1    = Vault::audit_payload( 'CASE-LEGACY1', 'REPORT_SUBMITTED', 'ANONYMOUS_WHISTLEBLOWER', 0, Vault::AUDIT_GENESIS, $ts1 );
	$hash1   = hash_hmac( 'sha256', $pay1, (string) AUTH_KEY );
	$GLOBALS['audit_rows'][1] = [
		'id'             => 1,
		'case_public_id' => 'CASE-LEGACY1',
		'action'         => 'REPORT_SUBMITTED',
		'actor_role'     => 'ANONYMOUS_WHISTLEBLOWER',
		'actor_user_id'  => 0,
		'previous_hash'  => Vault::AUDIT_GENESIS,
		'current_hash'   => $hash1,
		'created_at'     => $ts1,
	];

	// Row #2: appended now through Vault::log_audit_event() -> signed with HKDF(WM_HINSCHG_AUDIT_KEY).
	$vault = new Vault();
	$hash2 = $vault->log_audit_event( 'CASE-DEDICATED2', 'CASE_OPENED_BY_COMPLIANCE_OFFICER', 'COMPLIANCE_OFFICER', 1 );
	$dual_check = Vault::verify_audit_chain();

	// Row #3: attacker steals AUTH_KEY (without WM_HINSCHG_AUDIT_KEY) and tries to append a forged link after Row #2!
	$ts3   = '2026-11-18 10:05:00';
	$pay3  = Vault::audit_payload( 'CASE-FORGED3', 'CASE_DISMISSED', 'COMPLIANCE_OFFICER', 1, $hash2, $ts3 );
	$hash3 = hash_hmac( 'sha256', $pay3, (string) AUTH_KEY );
	$GLOBALS['audit_rows'][3] = [
		'id'             => 3,
		'case_public_id' => 'CASE-FORGED3',
		'action'         => 'CASE_DISMISSED',
		'actor_role'     => 'COMPLIANCE_OFFICER',
		'actor_user_id'  => 1,
		'previous_hash'  => $hash2,
		'current_hash'   => $hash3,
		'created_at'     => $ts3,
	];
	$downgrade_check = Vault::verify_audit_chain();

	echo json_encode(
		[
			'mode'              => $mode,
			'key_source'        => Vault::audit_key_source(),
			'hash2_differs_auth'=> $hash2 !== hash_hmac( 'sha256', Vault::audit_payload( 'CASE-DEDICATED2', 'CASE_OPENED_BY_COMPLIANCE_OFFICER', 'COMPLIANCE_OFFICER', 1, $hash1, (string) $GLOBALS['audit_rows'][2]['created_at'] ), (string) AUTH_KEY ),
			'dual_valid'        => true === $dual_check['valid'] && 2 === $dual_check['checked'],
			'downgrade_refused' => false === $downgrade_check['valid'] && 3 === $downgrade_check['broken_at_id'],
		],
		JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
	), "\n";
	exit( 0 );
}

if ( 'multisite-init' === $mode ) {
	$GLOBALS['probe_multisite_scoped'] = true;
	$GLOBALS['probe_actions']          = [];
	$GLOBALS['probe_switches']         = [];
	$GLOBALS['probe_restores']         = 0;
	$GLOBALS['probe_db_sql']           = [];
	$GLOBALS['probe_network_active']   = false;

	function plugin_dir_path( string $file ): string { return dirname( $file ) . '/'; }
	function plugin_dir_url( string $file ): string { return 'https://example.com/wp-content/plugins/' . basename( dirname( $file ) ) . '/'; }
	function plugin_basename( string $file ): string { return 'wm-hinschg-whistleblower/' . basename( $file ); }
	function register_activation_hook( string $file, callable $cb ): void {}
	function register_deactivation_hook( string $file, callable $cb ): void {}
	function add_action( string $tag, callable $cb, int $p = 10, int $a = 1 ): void { $GLOBALS['probe_actions'][ $tag ][] = $cb; }
	function add_filter( string $tag, callable $cb, int $p = 10, int $a = 1 ): void {}
	function is_plugin_active_for_network( string $plugin ): bool { return $GLOBALS['probe_network_active']; }
	function switch_to_blog( int $blog_id ): bool {
		$GLOBALS['probe_switches'][]        = $blog_id;
		$GLOBALS['probe_current_blog_id']   = $blog_id;
		$GLOBALS['wpdb']->prefix            = 1 === $blog_id ? 'wp_' : "wp_{$blog_id}_";
		return true;
	}
	function restore_current_blog(): bool {
		++$GLOBALS['probe_restores'];
		$GLOBALS['probe_current_blog_id'] = 1;
		$GLOBALS['wpdb']->prefix          = 'wp_';
		return true;
	}
	function wp_next_scheduled( string $hook ) { return true; }
	function wp_schedule_event( int $t, string $r, string $h ) { return true; }
	function wp_clear_scheduled_hook( string $h ) { return true; }
	function get_role( string $slug ) { return null; }
	function add_role( string $slug, string $name, array $caps = [] ) { return null; }
	function dbDelta( $queries = '' ): array {
		$GLOBALS['probe_db_sql'][] = (string) $queries;
		return [];
	}
	$GLOBALS['wpdb'] = new class {
		public string $prefix = 'wp_';
		public function get_charset_collate(): string { return ''; }
	};

	try {
		require_once dirname( __DIR__ ) . '/wm-hinschg-whistleblower.php';
		$cbs = $GLOBALS['probe_actions']['wp_initialize_site'] ?? [];

		// 1. Not network-activated -> must NOT switch or activate.
		$GLOBALS['probe_network_active'] = false;
		foreach ( $cbs as $cb ) {
			$cb( (object) [ 'blog_id' => 41 ] );
		}
		$ignored_when_not_network = ( [] === $GLOBALS['probe_switches'] ) && ( [] === $GLOBALS['probe_db_sql'] );

		// 2. Network-activated -> switches to blog 42, activates on wp_42_, restores to blog 1.
		$GLOBALS['probe_network_active'] = true;
		foreach ( $cbs as $cb ) {
			$cb( (object) [ 'blog_id' => 42 ] );
		}
	} finally {
		if ( null !== $tmp_root ) {
			@unlink( $tmp_root . '/wp-admin/includes/upgrade.php' );
			@unlink( $tmp_root . '/wp-admin/includes/plugin.php' );
			@rmdir( $tmp_root . '/wp-admin/includes' );
			@rmdir( $tmp_root . '/wp-admin' );
			@rmdir( $tmp_root );
		}
	}

	$sql_joined = implode( "\n", $GLOBALS['probe_db_sql'] );
	echo json_encode(
		[
			'mode'                     => $mode,
			'hook_registered'          => count( $cbs ) > 0,
			'ignored_when_not_network' => $ignored_when_not_network,
			'switched_to_42'           => [ 42 ] === $GLOBALS['probe_switches'],
			'restored_to_1'            => 1 === $GLOBALS['probe_restores'] && 1 === $GLOBALS['probe_current_blog_id'] && 'wp_' === $GLOBALS['wpdb']->prefix,
			'blog42_tables_created'    => str_contains( $sql_joined, 'wp_42_wm_whistle_reports' )
				&& str_contains( $sql_joined, 'wp_42_wm_whistle_messages' )
				&& str_contains( $sql_joined, 'wp_42_wm_whistle_audit_log' ),
			'blog42_public_key_set'    => '' !== (string) ( $GLOBALS['probe_blog_options'][42]['wm_hinschg_public_key'] ?? '' ),
			'blog1_untouched'          => ! isset( $GLOBALS['probe_blog_options'][1]['wm_hinschg_public_key'] ),
		],
		JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
	), "\n";
	exit( 0 );
}

// Schema::activate() needs a whole WordPress; only protect_private_key() is exercised here, so the
// file is loaded and just that static is called.
if ( str_starts_with( $mode, 'migrate' ) || str_starts_with( $mode, 'activate-' ) ) {
	function wp_next_scheduled( string $hook ) { return true; }
	function wp_schedule_event( int $t, string $r, string $h ) { return true; }
	function wp_clear_scheduled_hook( string $h ) { return true; }
	require_once dirname( __DIR__ ) . '/includes/Security/Capabilities.php';
	require_once dirname( __DIR__ ) . '/includes/Database/Schema.php';
}

if ( str_starts_with( $mode, 'activate-' ) ) {
	function get_role( string $slug ) { return null; }
	function add_role( string $slug, string $name, array $caps = [] ) { return null; }
	function dbDelta( $queries = '' ): array { return []; }
	$GLOBALS['wpdb'] = new class {
		public string $prefix = 'wp_';
		public function get_charset_collate(): string { return ''; }
	};
	try {
		\WMCyber\HinSchG\Database\Schema::activate();
	} finally {
		if ( null !== $tmp_root ) {
			@unlink( $tmp_root . '/wp-admin/includes/upgrade.php' );
			@unlink( $tmp_root . '/wp-admin/includes/plugin.php' );
			@rmdir( $tmp_root . '/wp-admin/includes' );
			@rmdir( $tmp_root . '/wp-admin' );
			@rmdir( $tmp_root );
		}
	}

	$stored_priv = (string) ( $GLOBALS['probe_options']['wm_hinschg_private_key'] ?? '' );
	$vault       = new Vault();
	$can_seal    = false;
	$round_trip  = false;
	try {
		$env      = $vault->encrypt_envelope( [ 'description' => 'Aktivierungs-Test' ] );
		$can_seal = isset( $env['payload'], $env['key'], $env['tag'], $env['iv'] );
		$plain    = $vault->decrypt_envelope( $env['payload'], $env['key'], $env['tag'], $env['iv'] );
		$round_trip = ( 'Aktivierungs-Test' === ( $plain['description'] ?? '' ) );
	} catch ( \Throwable $e ) {
		$round_trip = false;
	}
	echo json_encode(
		[
			'mode'                => $mode,
			'source'              => Vault::private_key_source(),
			'has_plaintext_pem'   => str_contains( $stored_priv, 'BEGIN PRIVATE KEY' ) || str_contains( $stored_priv, 'BEGIN RSA PRIVATE KEY' ),
			'stored_prefix'       => substr( $stored_priv, 0, 22 ),
			'has_offline_once'    => is_string( get_transient( 'wm_hinschg_offline_key_once' ) ) && str_contains( (string) get_transient( 'wm_hinschg_offline_key_once' ), 'BEGIN PRIVATE KEY' ),
			'can_seal'            => $can_seal,
			'round_trip'          => $round_trip,
		],
		JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
	), "\n";
	exit( 0 );
}

// A real key pair, exported the way the mode under test would have stored it.
$res = openssl_pkey_new( [ 'digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ] );
$details = openssl_pkey_get_details( $res );

if ( 'migrate-twice' === $mode ) {
	openssl_pkey_export( $res, $stored, $passphrase );   // already encrypted
} elseif ( 'migrate-wrong-passphrase' === $mode ) {
	openssl_pkey_export( $res, $stored, 'a-different-passphrase' );
} else {
	openssl_pkey_export( $res, $stored );                 // the pre-2026-09-19 stored form
}

$GLOBALS['probe_options']['wm_hinschg_private_key'] = $stored;
$GLOBALS['probe_options']['wm_hinschg_public_key']  = $details['key'];

if ( 'wp-config' === $mode ) {
	// The whole key in wp-config.php: what sits in the database must stop mattering, so the option
	// is deliberately filled with something that is NOT a key.
	define( 'WM_HINSCHG_PRIVATE_KEY', $stored );
	$GLOBALS['probe_options']['wm_hinschg_private_key'] = 'not-a-key-at-all';
}

$out = [ 'mode' => $mode, 'source' => Vault::private_key_source() ];

if ( str_starts_with( $mode, 'migrate' ) ) {
	$out['migration'] = \WMCyber\HinSchG\Database\Schema::protect_private_key();
	$out['stored_changed'] = $GLOBALS['probe_options']['wm_hinschg_private_key'] !== $stored;
	$out['stored_opens_without_passphrase'] = false !== openssl_pkey_get_private( (string) $GLOBALS['probe_options']['wm_hinschg_private_key'] );
	$out['stored_opens_with_passphrase'] = false !== openssl_pkey_get_private( (string) $GLOBALS['probe_options']['wm_hinschg_private_key'], $passphrase );
}

// A round trip through the Vault proves the key is still usable after whatever the mode did — a
// migration that produces an unopenable key would otherwise report success.
$vault = new Vault();
if ( 'master-key' === $mode ) {
	$after_boot = (string) ( $GLOBALS['probe_options']['wm_hinschg_private_key'] ?? '' );
	$out['migrated_automatically'] = str_starts_with( $after_boot, Vault::SODIUM_PREFIX ) && ! str_contains( $after_boot, 'BEGIN PRIVATE KEY' );
	$out['source']                 = Vault::private_key_source();
}
if ( 'master-key-tampered' === $mode ) {
	$after_boot = (string) ( $GLOBALS['probe_options']['wm_hinschg_private_key'] ?? '' );
	$raw_b64    = substr( $after_boot, strlen( Vault::SODIUM_PREFIX ) );
	$raw_bytes  = (string) base64_decode( $raw_b64, true );
	$flipped    = substr( $raw_bytes, 0, -1 ) . chr( ord( substr( $raw_bytes, -1 ) ) ^ 0xFF );
	$tampered   = Vault::SODIUM_PREFIX . base64_encode( $flipped );
	$GLOBALS['probe_options']['wm_hinschg_private_key'] = $tampered;
	$out['tampered_opens_null'] = ( null === Vault::open_private_key_sodium( $tampered ) );
	$vault = new Vault();
}
try {
	$envelope = $vault->encrypt_envelope( [ 'description' => 'Probe-Meldung' ] );
	$plain    = $vault->decrypt_envelope( $envelope['payload'], $envelope['key'], $envelope['tag'], $envelope['iv'] );
	$out['round_trip'] = ( 'Probe-Meldung' === ( $plain['description'] ?? '' ) );
} catch ( \Throwable $e ) {
	$out['round_trip'] = false;
	$out['round_trip_error'] = $e->getMessage();
}

echo json_encode( $out, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES ), "\n";
