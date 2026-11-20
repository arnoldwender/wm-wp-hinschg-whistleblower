<?php
/**
 * Falsifier for the audit chain of the HinSchG case log.
 *
 * Measured on 2026-08-27, before this release: the chain hash was
 *
 *     $data_string  = sprintf( '%s|%s|%s|%d|%s|%s', $case, $action, $role, $uid, $prev, $now );
 *     $current_hash = hash( 'sha256', $data_string );
 *
 * Unkeyed, over values that are ALL stored in the row. Rewriting an entry and recomputing every
 * hash after it needed no secret whatsoever. Reproduced on a clean install: changing an entry's
 * action from "case_assigned" to "case_dismissed" and re-signing the tail left the verifier
 * reporting the log INTACT — on a whistleblower system whose docs promised "immutable, SHA-256
 * Merkle-linked audit log ensuring non-repudiation". Deleting the newest entry was invisible too.
 *
 * Mutation checks, measured rather than assumed:
 *   - make Vault::audit_hash() a plain hash( 'sha256', ... ) again → case 3b fails, and so do the
 *     pre-key cases. Case 3 does NOT fail: the tip mirror catches that one, which is why 3b
 *     exists.
 *   - remove the tip comparison → cases 3 and 4 fail.
 *
 * WARNING: truncates the audit log. Scratch installs only; it refuses to run without WM_HINSCHG_SCRATCH_INSTALL=1.
 *
 * Run: WM_HINSCHG_SCRATCH_INSTALL=1 wp eval-file wp-content/plugins/wm-hinschg-whistleblower/tests/test-audit-chain-forgery.php --allow-root
 *
 * @package WMCyber\HinSchG
 */

use WMCyber\HinSchG\Crypto\Vault;

if ( ! defined( 'ABSPATH' ) ) {
	echo "Must run inside WordPress via WP-CLI.\n";
	exit( 1 );
}

// The docblock warning did not stop a run against the local demo on 2026-09-15; a gate does.
if ( '1' !== getenv( 'WM_HINSCHG_SCRATCH_INSTALL' ) ) {
	echo "Refusing to run: this test truncates the audit log (wm_whistle_audit_log) and deletes its tip. On a scratch install: WM_HINSCHG_SCRATCH_INSTALL=1 wp eval-file ...\n";
	exit( 1 );
}

// eval-file runs the file inside a function, so `global` would not bind for the helper below.
$GLOBALS['wm_h_passed'] = 0;
$GLOBALS['wm_h_failed'] = 0;

/**
 * Assert helper.
 *
 * @param bool   $condition Condition.
 * @param string $label     Description.
 * @return void
 */
function wm_h_assert( $condition, $label ) {
	if ( $condition ) {
		++$GLOBALS['wm_h_passed'];
		echo "  [PASS] {$label}\n";
	} else {
		++$GLOBALS['wm_h_failed'];
		echo "  [FAIL] {$label}\n";
	}
}

global $wpdb;
$table = $wpdb->prefix . 'wm_whistle_audit_log';

echo "\n=== HINSCHG AUDIT CHAIN FORGERY TEST ===\n\n";

/**
 * Fresh chain with three entries.
 *
 * @return array Ids.
 */
function wm_h_fixture() {
	global $wpdb;
	$table = $wpdb->prefix . 'wm_whistle_audit_log';
	// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query( "TRUNCATE TABLE {$table}" );
	delete_option( Vault::AUDIT_TIP_OPTION );
	$vault = new Vault();
	foreach ( [ 'case_opened', 'case_assigned', 'case_closed' ] as $action ) {
		$vault->log_audit_event( 'CASE-PROBE-1', $action, 'case_officer', 3 );
	}
	return array_map( 'intval', $wpdb->get_col( "SELECT id FROM {$table} ORDER BY id ASC" ) );
	// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
}

/**
 * The attack the old design allowed: rewrite an entry and re-sign every hash after it, using
 * only what is stored in the table.
 *
 * @param int    $target_index Index of the entry to rewrite.
 * @param string $new_action   Replacement action.
 * @param bool   $keyed        Whether the attacker holds the key.
 * @return void
 */
function wm_h_rewrite_and_resign( $target_index, $new_action, $keyed ) {
	global $wpdb;
	$table = $wpdb->prefix . 'wm_whistle_audit_log';
	// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id ASC", ARRAY_A );
	$prev = Vault::AUDIT_GENESIS;

	foreach ( $rows as $idx => $row ) {
		$action  = ( $idx === $target_index ) ? $new_action : $row['action'];
		$payload = Vault::audit_payload( $row['case_public_id'], $action, $row['actor_role'], (int) $row['actor_user_id'], $prev, $row['created_at'] );
		$hash    = $keyed ? Vault::audit_hash( $payload ) : hash( 'sha256', $payload );

		$wpdb->update(
			$table,
			[ 'action' => $action, 'previous_hash' => $prev, 'current_hash' => $hash ],
			[ 'id' => (int) $row['id'] ]
		);
		$prev = $hash;
	}
	// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
}

// --- Case 1: an untouched chain verifies -----------------------------------
$ids = wm_h_fixture();
$r   = Vault::verify_audit_chain();
wm_h_assert( true === $r['valid'], 'an untouched chain verifies' );
wm_h_assert( 3 === $r['checked'], 'all three entries were checked (got ' . $r['checked'] . ')' );

// --- Case 2: editing an entry without re-signing is detected ---------------
$ids = wm_h_fixture();
$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET action = 'case_dismissed' WHERE id = %d", $ids[1] ) );
$r = Vault::verify_audit_chain();
wm_h_assert( false === $r['valid'], 'editing an entry is detected' );
wm_h_assert( (int) $ids[1] === (int) $r['broken_at_id'], 'the edited entry is the one reported' );

// --- Case 3: rewriting AND re-signing without the key no longer works ------
// This is the exact sequence that used to leave the log reporting itself intact.
$ids = wm_h_fixture();
wm_h_rewrite_and_resign( 1, 'case_dismissed', false );
$r = Vault::verify_audit_chain();
wm_h_assert( false === $r['valid'], 'rewriting and re-signing without the key is detected' );

$still = $wpdb->get_var( $wpdb->prepare( "SELECT action FROM {$table} WHERE id = %d", $ids[1] ) );
wm_h_assert( 'case_dismissed' === $still, 'the falsified record is still in place — the chain reports, it does not repair' );

// --- Case 3b: re-signing AND fixing the recorded tip ----------------------
// Measured under mutation: case 3 above is caught by the tip mirror, not by the key — swap
// audit_hash() back to an unkeyed sha256 and it still passes. But the tip lives in wp_options,
// which is the same database the attacker is already writing to, so a real attacker fixes it too.
// This case removes that crutch and leaves only the key standing.
$ids = wm_h_fixture();
wm_h_rewrite_and_resign( 1, 'case_dismissed', false );
$forged_tip = $wpdb->get_var( "SELECT current_hash FROM {$table} ORDER BY id DESC LIMIT 1" );
update_option(
	Vault::AUDIT_TIP_OPTION,
	array( 'hash' => $forged_tip, 'count' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) ),
	false
);
$r = Vault::verify_audit_chain();
wm_h_assert( false === $r['valid'], 'a full re-sign with the tip fixed up is still detected — only the key stops this' );

// --- Case 3c: downgrading only the TAIL, keeping the head keyed ------------
// The pre-key tolerance only applies at the head of the chain. Without that restriction an
// attacker downgrades from entry k onward, keeps entry k-1 keyed so the log still reports
// verified entries, fixes the tip, and every downgraded row passes as a harmless leftover.
$ids = wm_h_fixture();
$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id ASC", ARRAY_A );
$prev = (string) $rows[0]['current_hash'];   // entry #1 stays keyed and untouched

foreach ( array_slice( $rows, 1 ) as $i => $row ) {
	$action  = ( 0 === $i ) ? 'case_dismissed' : $row['action'];
	$payload = Vault::audit_payload( $row['case_public_id'], $action, $row['actor_role'], (int) $row['actor_user_id'], $prev, $row['created_at'] );
	$hash    = hash( 'sha256', $payload );   // unkeyed: the attacker has no key
	$wpdb->update( $table, array( 'action' => $action, 'previous_hash' => $prev, 'current_hash' => $hash ), array( 'id' => (int) $row['id'] ) );
	$prev = $hash;
}
update_option(
	Vault::AUDIT_TIP_OPTION,
	array( 'hash' => $prev, 'count' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) ),
	false
);
$r = Vault::verify_audit_chain();
wm_h_assert( false === $r['valid'], 'downgrading only the tail, with the head left keyed, is detected' );

// --- Case 4: deleting the newest entry is detected -------------------------
$ids = wm_h_fixture();
$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id = %d", end( $ids ) ) );
$r = Vault::verify_audit_chain();
wm_h_assert( false === $r['valid'], 'deleting the newest entry is caught by the recorded tip' );

// --- Case 5: emptying the log is detected ----------------------------------
$ids = wm_h_fixture();
$wpdb->query( "DELETE FROM {$table}" );
$r = Vault::verify_audit_chain();
wm_h_assert( false === $r['valid'], 'emptying the log is detected, not read as innocent' );

// --- Case 6: pre-key entries are reported as unkeyed, never as intact ------
$ids = wm_h_fixture();
wm_h_rewrite_and_resign( 0, 'case_opened', false );   // rebuild the whole chain the old way
delete_option( Vault::AUDIT_TIP_OPTION );
$r = Vault::verify_audit_chain();
wm_h_assert( 3 === $r['unkeyed_legacy'], 'pre-key entries are counted as unkeyed (got ' . $r['unkeyed_legacy'] . ')' );
wm_h_assert( 0 === $r['checked'], 'no pre-key entry is counted as verified' );
wm_h_assert( false === $r['valid'], 'a log with no keyed entry at all does not report itself valid' );

// --- Case 7: writer and verifier share one serialisation -------------------
// They used to carry two separate copies of the same sprintf(), one in Vault and one in the CLI.
$cli = file_get_contents( WM_HINSCHG_PATH . 'includes/CLI/HinSchGCommand.php' );
wm_h_assert( false === strpos( $cli, "sprintf( '%s|%s|%s|%d|%s|%s'" ), 'the CLI no longer carries its own copy of the payload format' );

// --- Case 8: the key is not in the database --------------------------------
wm_h_assert( 'wp-config' === Vault::audit_key_source(), 'the chain key comes from wp-config.php on this install' );

// --- Teardown -------------------------------------------------------------
$wpdb->query( "TRUNCATE TABLE {$table}" );
delete_option( Vault::AUDIT_TIP_OPTION );

echo "\n=== RESULT: {$GLOBALS['wm_h_passed']} passed, {$GLOBALS['wm_h_failed']} failed ===\n\n";
