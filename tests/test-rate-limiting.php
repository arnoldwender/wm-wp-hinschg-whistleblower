<?php
/**
 * Rate-limit test for the public HinSchG endpoints.
 *
 * /report/submit, /report/status and /report/chat are public because a whistleblower has no
 * account. They authorise correctly by case token, but were unmetered: /report/status could
 * be driven as an offline oracle for guessing tokens, and /report/submit accepted unlimited
 * flooding.
 *
 * Run: wp eval-file wp-content/plugins/wm-hinschg-whistleblower/tests/test-rate-limiting.php
 *
 * @package WMCyber\HinSchG
 */

use WMCyber\HinSchG\Security\RateLimiter;

$GLOBALS['wm_rl_passed'] = 0;
$GLOBALS['wm_rl_failed'] = 0;

/**
 * Assert helper.
 *
 * @param bool   $condition Condition.
 * @param string $label     Description.
 * @return void
 */
function wm_rl_assert( $condition, $label ) {
	if ( $condition ) {
		++$GLOBALS['wm_rl_passed'];
		echo "  [PASS] {$label}\n";
	} else {
		++$GLOBALS['wm_rl_failed'];
		echo "  [FAIL] {$label}\n";
	}
}

/**
 * Clear every bucket so the test starts from a known state.
 *
 * @return void
 */
function wm_rl_reset() {
	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '%wm_hinschg_rl_%'" );
	wp_cache_flush();
}

echo "\n=== HINSCHG RATE LIMIT TEST ===\n\n";
wm_rl_reset();

// --- Case 1: the bucket refuses past its budget --------------------------
echo "Case 1 — Budget wird durchgesetzt\n";
$allowed = 0;
for ( $i = 0; $i < 8; $i++ ) {
	if ( RateLimiter::consume( 'probe', 5, HOUR_IN_SECONDS ) ) {
		++$allowed;
	}
}
wm_rl_assert( 5 === $allowed, "Genau 5 von 8 Aufrufen durchgelassen (war: {$allowed})" );
wm_rl_assert( false === RateLimiter::consume( 'probe', 5, HOUR_IN_SECONDS ), 'Weiterer Aufruf wird abgewiesen' );

// --- Case 2: buckets are independent -------------------------------------
echo "\nCase 2 — Buckets sind unabhaengig\n";
wm_rl_assert( true === RateLimiter::consume( 'other', 5, HOUR_IN_SECONDS ), 'Ein anderer Bucket ist unberuehrt' );

// --- Case 3: the refusal is a 429 ----------------------------------------
echo "\nCase 3 — Form der Ablehnung\n";
$err = RateLimiter::refusal();
wm_rl_assert( is_wp_error( $err ), 'refusal() liefert einen WP_Error' );
wm_rl_assert( 429 === ( $err->get_error_data()['status'] ?? 0 ), 'HTTP-Status 429' );

// --- Case 4: the IP is never stored in the clear -------------------------
echo "\nCase 4 — Vertraulichkeit nach sec. 8 HinSchG\n";
global $wpdb;
$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$leaked = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s AND option_name LIKE %s", '%wm_hinschg_rl_%', '%' . $wpdb->esc_like( $ip ) . '%' ) );
wm_rl_assert( 0 === $leaked, 'Keine Roh-IP im Transient-Schluessel' );

// --- Case 5: the live endpoint refuses -----------------------------------
echo "\nCase 5 — Endpunkt /report/status unter Last\n";
wm_rl_reset();
$statuses = array();
for ( $i = 0; $i < 22; $i++ ) {
	$req = new WP_REST_Request( 'POST', '/wm-hinschg/v1/report/status' );
	$req->set_body_params( array( 'case_public_id' => 'CASE-DEADBEEF', 'access_token' => str_repeat( 'a', 64 ) ) );
	$req->set_header( 'content-type', 'application/json' );
	$req->set_body( wp_json_encode( array( 'case_public_id' => 'CASE-DEADBEEF', 'access_token' => str_repeat( 'a', 64 ) ) ) );
	$statuses[] = rest_do_request( $req )->get_status();
}
$rate_limited = count( array_filter( $statuses, static fn( $s ) => 429 === $s ) );
wm_rl_assert( $rate_limited > 0, "Mindestens ein 429 nach 22 Versuchen (war: {$rate_limited})" );
wm_rl_assert( 403 === $statuses[0], 'Der erste Versuch wird noch fachlich mit 403 abgewiesen' );

wm_rl_reset();

echo "\n----------------------------------------------------\n";
$p = (int) $GLOBALS['wm_rl_passed'];
$f = (int) $GLOBALS['wm_rl_failed'];
echo "Tests bestanden: {$p} / " . ( $p + $f ) . "\n";
echo ( 0 === $f && $p > 0 ) ? "VERDICT: PASS\n" : "VERDICT: FAIL\n";
echo "----------------------------------------------------\n";
