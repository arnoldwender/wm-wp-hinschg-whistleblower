<?php
/**
 * Falsifier for the follow-up chat encryption, through the real REST stack and the real database.
 *
 * Until 2026-09-14 wm_whistle_messages.encrypted_message held plain text: the whistleblower's
 * replies and the officer's answers sat next to the envelope-encrypted report, readable by anyone
 * with a database dump (fleet audit 2026-09-13 §6.2 #28). This proves, on a live install:
 *   1. a whistleblower reply is stored as an envelope that does not contain the text;
 *   2. the officer's acknowledgment and reply are stored the same way;
 *   3. /report/status returns the plain text to the token holder, flagged sealed;
 *   4. a legacy plaintext row still shows, flagged as not sealed;
 *   5. a wrong token still gets nothing.
 *
 * WARNING: writes four entries to the append-only audit log that cannot be removed without breaking the chain, and
 * clears the rate-limit counters. Scratch installs only; it refuses to run without WM_HINSCHG_SCRATCH_INSTALL=1.
 *
 * Run: WM_HINSCHG_SCRATCH_INSTALL=1 wp eval-file wp-content/plugins/wm-hinschg-whistleblower/tests/test-chat-encryption.php --allow-root
 *
 * @package WMCyber\HinSchG
 */

if ( ! defined( 'ABSPATH' ) ) {
	echo "Must run inside WordPress via WP-CLI.\n";
	exit( 1 );
}

// The docblock warning did not stop a run against the local demo on 2026-09-15; a gate does.
if ( '1' !== getenv( 'WM_HINSCHG_SCRATCH_INSTALL' ) ) {
	echo "Refusing to run: this test writes permanent entries to the audit log. On a scratch install: WM_HINSCHG_SCRATCH_INSTALL=1 wp eval-file ...\n";
	exit( 1 );
}

$GLOBALS['wm_c_passed'] = 0;
$GLOBALS['wm_c_failed'] = 0;

function wm_c_assert( $condition, $label ) {
	if ( $condition ) {
		++$GLOBALS['wm_c_passed'];
		echo "  [PASS] {$label}\n";
	} else {
		++$GLOBALS['wm_c_failed'];
		echo "  [FAIL] {$label}\n";
	}
}

function wm_c_post( string $route, array $body ) {
	$req = new WP_REST_Request( 'POST', '/wm-hinschg/v1/' . $route );
	$req->set_header( 'Content-Type', 'application/json' );
	$req->set_body( wp_json_encode( $body ) );
	return rest_get_server()->dispatch( $req );
}

global $wpdb;
$reports  = $wpdb->prefix . 'wm_whistle_reports';
$messages = $wpdb->prefix . 'wm_whistle_messages';

echo "\n=== HINSCHG CHAT ENCRYPTION TEST ===\n\n";

// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
// The public routes are rate limited per blinded client address; a falsifier that cannot be
// re-run is not a falsifier.
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wm_hinschg_rl_%' OR option_name LIKE '_transient_timeout_wm_hinschg_rl_%'" );
wp_cache_flush();

wp_set_current_user( 0 );
$res  = wm_c_post( 'report/submit', [ 'category' => 'financial_fraud', 'description' => 'PROBE-C Doppelte Rechnungen an die Muster GmbH.' ] );
$data = (array) $res->get_data();
$case = (string) ( $data['case_public_id'] ?? '' );
$tok  = (string) ( $data['access_token'] ?? '' );
wm_c_assert( 201 === $res->get_status() && '' !== $case && 64 === strlen( $tok ), 'a report was submitted (' . $res->get_status() . ')' );
$report_id = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$reports} WHERE case_public_id = %s", $case ) );

// --- 1. whistleblower reply ---------------------------------------------------------------------
$res = wm_c_post( 'report/chat', [ 'case_public_id' => $case, 'access_token' => $tok, 'message' => 'PROBE-C Ich habe die Belege gesehen.' ] );
wm_c_assert( 201 === $res->get_status(), 'the whistleblower reply was accepted (' . $res->get_status() . ')' );
$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$messages} WHERE report_id = %d ORDER BY id DESC LIMIT 1", $report_id ), ARRAY_A );
$env = $row ? json_decode( (string) $row['encrypted_message'], true ) : null;
wm_c_assert( $row && false === strpos( (string) $row['encrypted_message'], 'Belege' ), 'the stored row does not contain the text' );
wm_c_assert( is_array( $env ) && isset( $env['payload'], $env['key'], $env['tag'], $env['iv'] ), 'the stored row is an envelope (payload/key/tag/iv)' );

// --- 2. officer ack + reply ---------------------------------------------------------------------
$admins = get_users( [ 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ] );
wp_set_current_user( (int) ( $admins[0] ?? 0 ) );
$ack = wm_c_post( 'admin/ack', [ 'case_public_id' => $case ] );
$rep = wm_c_post( 'admin/reply', [ 'case_public_id' => $case, 'message' => 'PROBE-C Wir prüfen die Rechnungen.' ] );
wm_c_assert( 200 === $ack->get_status() && 200 === $rep->get_status(), 'ack and reply were issued (' . $ack->get_status() . ', ' . $rep->get_status() . ')' );
$officer_rows = $wpdb->get_results( $wpdb->prepare( "SELECT encrypted_message FROM {$messages} WHERE report_id = %d AND sender_role = 'compliance_officer'", $report_id ), ARRAY_A );
$sealed_all   = count( $officer_rows ) === 2;
foreach ( $officer_rows as $r ) {
	$e = json_decode( (string) $r['encrypted_message'], true );
	$sealed_all = $sealed_all && is_array( $e ) && isset( $e['payload'] ) && false === strpos( (string) $r['encrypted_message'], 'Rechnungen' ) && false === strpos( (string) $r['encrypted_message'], 'Empfangs' );
}
wm_c_assert( $sealed_all, 'both officer messages are stored sealed' );

// --- 3./4. status opens them for the token holder; legacy plaintext stays readable --------------
$wpdb->insert( $messages, [ 'report_id' => $report_id, 'sender_role' => 'compliance_officer', 'encrypted_message' => 'PROBE-C Altbestand im Klartext.', 'created_at' => current_time( 'mysql', true ) ], [ '%d', '%s', '%s', '%s' ] );
wp_set_current_user( 0 );
$st   = wm_c_post( 'report/status', [ 'case_public_id' => $case, 'access_token' => $tok ] );
$msgs = (array) ( $st->get_data()['messages'] ?? [] );
$texts = array_map( static fn( $m ) => (string) ( $m['message'] ?? '' ), $msgs );
wm_c_assert( 200 === $st->get_status() && 4 === count( $msgs ), 'status returns the four messages (' . count( $msgs ) . ')' );
wm_c_assert( isset( $texts[0] ) && 'PROBE-C Ich habe die Belege gesehen.' === $texts[0] && true === ( $msgs[0]['sealed'] ?? null ), 'the whistleblower reply comes back as plain text, flagged sealed' );
wm_c_assert( isset( $texts[2] ) && 'PROBE-C Wir prüfen die Rechnungen.' === $texts[2], 'the officer reply comes back as plain text' );
wm_c_assert( isset( $texts[3] ) && 'PROBE-C Altbestand im Klartext.' === $texts[3] && false === ( $msgs[3]['sealed'] ?? null ), 'the legacy plaintext row is shown and flagged not sealed' );
wm_c_assert( ! isset( $msgs[0]['encrypted_message'] ), 'the API no longer hands out the ciphertext column' );

// --- 5. wrong token ------------------------------------------------------------------------------
$bad = wm_c_post( 'report/status', [ 'case_public_id' => $case, 'access_token' => str_repeat( '0', 64 ) ] );
wm_c_assert( 403 === $bad->get_status(), 'a wrong token gets 403 (' . $bad->get_status() . ')' );

// --- Teardown -----------------------------------------------------------------------------------
$wpdb->query( $wpdb->prepare( "DELETE FROM {$messages} WHERE report_id = %d", $report_id ) );
$wpdb->query( $wpdb->prepare( "DELETE FROM {$reports} WHERE id = %d", $report_id ) );
// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

echo "\n=== RESULT: {$GLOBALS['wm_c_passed']} passed, {$GLOBALS['wm_c_failed']} failed ===\n\n";
