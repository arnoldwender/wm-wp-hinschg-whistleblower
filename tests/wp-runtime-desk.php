<?php
/**
 * Runtime check of the desk, the portal and the hub adapter inside a real WordPress. Read-only: it creates,
 * changes and deletes nothing.
 *
 *   wp eval-file tests/wp-runtime-desk.php --user=1
 *
 * The standalone suite renders the same screens against a mock database; this file checks them against the
 * real tables. The deadline states are recounted here in PHP from SELECT * so the check does not trust the
 * SQL it is checking. Exit 1 (WP_CLI::error) when a check fails.
 *
 * `wp eval-file` runs the file inside a method: state lives in $GLOBALS, and there is no declare() because
 * a declare after the docblock is fatal there.
 *
 * @package WMCyber\HinSchG
 */

defined( 'ABSPATH' ) || exit; // the local install serves the plugin folder over HTTP; this file is for wp eval-file only.

use WMCyber\HinSchG\Adapters\HinSchG_Spoke_Adapter;
use WMCyber\HinSchG\Admin\AdminDashboard;
use WMCyber\HinSchG\Compliance\ReportCategories;
use WMCyber\HinSchG\Core\Plugin;

$GLOBALS['wm_hinschg_rt'] = [ 'pass' => 0, 'fail' => 0 ];

function wm_hinschg_rt_check( string $name, bool $ok, string $details = '' ): void {
	$GLOBALS['wm_hinschg_rt'][ $ok ? 'pass' : 'fail' ]++;
	WP_CLI::log( ( $ok ? '[PASS] ' : '[FAIL] ' ) . $name . ( $ok || '' === $details ? '' : ': ' . $details ) );
}

function wm_hinschg_rt_render( callable $fn ): string {
	ob_start();
	$fn();
	return (string) ob_get_clean();
}

global $wpdb;
$table = $wpdb->prefix . 'wm_whistle_reports';

if ( ! class_exists( Plugin::class ) ) {
	WP_CLI::error( 'wm-hinschg-whistleblower is not loaded.' );
}
if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
	WP_CLI::error( "{$table} does not exist." );
}

// Independent recount from the rows, same rules as HinSchGSlaManager::status_counts().
$now      = current_time( 'mysql', true );
$soon     = gmdate( 'Y-m-d H:i:s', time() + 48 * 3600 );
$rows     = (array) $wpdb->get_results( "SELECT * FROM {$table}", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$expected = [ 'breached_ack' => 0, 'breached_feedback' => 0, 'impending_ack' => 0, 'open' => 0 ];
foreach ( $rows as $r ) {
	$closed = 'closed' === $r['status'];
	if ( null === $r['ack_sent_at'] && ! $closed && $r['ack_sla_deadline'] < $now ) {
		$expected['breached_ack']++;
	}
	if ( null === $r['ack_sent_at'] && ! $closed && $r['ack_sla_deadline'] <= $soon && $r['ack_sla_deadline'] > $now ) {
		$expected['impending_ack']++;
	}
	if ( null === $r['feedback_sent_at'] && ! $closed && $r['feedback_sla_deadline'] < $now ) {
		$expected['breached_feedback']++;
	}
	if ( null === $r['feedback_sent_at'] && ! $closed ) {
		$expected['open']++;
	}
}

$plugin = Plugin::instance();
$counts = $plugin->get_sla_manager()->status_counts();
WP_CLI::log( sprintf( 'rows %d | counted %s', count( $rows ), wp_json_encode( $counts ) ) );
wm_hinschg_rt_check( 'status_counts() equals the recount from the rows', $expected === $counts, wp_json_encode( $expected ) );

$desk    = new AdminDashboard( $plugin->get_vault(), $plugin->get_sla_manager() );
$overdue = $counts['breached_ack'] + $counts['breached_feedback'];
$emoji   = '/[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}]/u';

$widget = wm_hinschg_rt_render( fn() => $desk->render_dashboard_widget() );
preg_match_all( '#<div class="wm-dash-kpi-val[^"]*">(\d+)</div>\s*<div class="wm-dash-kpi-lbl">([^<]+)</div>#', $widget, $m, PREG_SET_ORDER );
$kpis = [];
foreach ( $m as $k ) {
	$kpis[ trim( $k[2] ) ] = (int) $k[1];
}
wm_hinschg_rt_check(
	'dashboard widget shows the real case, open and overdue numbers',
	[ 'Vorgänge' => count( $rows ), 'Offen' => $counts['open'], 'Überfällig' => $overdue ] === $kpis && ! preg_match( $emoji, $widget ),
	wp_json_encode( $kpis )
);

unset( $_GET['tab'] );
$page      = wm_hinschg_rt_render( fn() => $desk->render_dashboard_page() );
$row_count = preg_match_all( '#<tr>\s*<td><code>CASE-#', $page );
$marks     = substr_count( $page, '<strong>überfällig</strong>' );
$expected_marks = 0;
foreach ( array_slice( array_reverse( $rows ), 0, 50 ) as $r ) {
	$closed = 'closed' === $r['status'];
	$expected_marks += ( null === $r['ack_sent_at'] && ! $closed && $r['ack_sla_deadline'] < $now ) ? 1 : 0;
	$expected_marks += ( null === $r['feedback_sent_at'] && ! $closed && $r['feedback_sla_deadline'] < $now ) ? 1 : 0;
}
wm_hinschg_rt_check(
	'desk lists the cases with one overdue mark per passed deadline',
	min( 50, count( $rows ) ) === $row_count && $expected_marks === $marks && ! preg_match( $emoji, $page ) && ! preg_match( '/Retrasos|PROTEGIDO|CIFRADO|Configuración/u', $page ),
	"rows {$row_count}, marks {$marks}, expected {$expected_marks}"
);

$_GET['tab'] = 'shortcode';
$embed = wm_hinschg_rt_render( fn() => $desk->render_dashboard_page() );
unset( $_GET['tab'] );
preg_match_all( '/\[([a-z_]+)\]/', $embed, $sc );
$unregistered = array_values( array_filter( array_unique( $sc[1] ), fn( $tag ) => ! shortcode_exists( $tag ) ) );
wm_hinschg_rt_check( 'every shortcode the embed tab names is registered', [] !== $sc[1] && [] === $unregistered, implode( ',', $unregistered ) );

$portal = do_shortcode( '[wm_whistleblower_portal]' );
preg_match_all( '/<option value="([a-z_]+)"/', $portal, $opts );
wm_hinschg_rt_check(
	'portal renders the shared categories without certification or E2E claims',
	array_keys( ReportCategories::all() ) === $opts[1] && ! preg_match( '/\bBSI\b|(?i:zero-knowledge|ende-zu-ende|garantie)/u', $portal ) && ! preg_match( $emoji, $portal ),
	implode( ',', $opts[1] )
);

require_once ABSPATH . 'wp-admin/includes/plugin.php';
$desk->register_admin_menu();
$adapter = class_exists( HinSchG_Spoke_Adapter::class ) ? new HinSchG_Spoke_Adapter() : null;
if ( null === $adapter ) {
	WP_CLI::log( '[SKIP] hub adapter: WM Suite Hub interface not loaded' );
} else {
	parse_str( (string) wp_parse_url( (string) $adapter->get_settings_url(), PHP_URL_QUERY ), $q );
	wm_hinschg_rt_check( 'hub settings link opens a registered admin page', isset( $GLOBALS['admin_page_hooks'][ $q['page'] ?? '' ] ), (string) ( $q['page'] ?? '' ) );

	$health = $adapter->get_health_status();
	$tm     = $adapter->get_telemetry_metrics();
	$want   = $overdue > 0 ? 'DEGRADED' : 'HEALTHY';
	WP_CLI::log( 'hub health ' . $health . ' | telemetry ' . wp_json_encode( $tm ) );
	wm_hinschg_rt_check(
		'hub health and telemetry follow the counts',
		in_array( $health, [ $want, 'ERROR' ], true ) && $counts['open'] === ( $tm['open_cases'] ?? null ) && $counts['breached_ack'] === ( $tm['breached_ack_sla'] ?? null ),
		$health . ' expected ' . $want
	);
}

WP_CLI::log( sprintf( '=== RUNTIME: %d passed, %d failed ===', $GLOBALS['wm_hinschg_rt']['pass'], $GLOBALS['wm_hinschg_rt']['fail'] ) );
if ( $GLOBALS['wm_hinschg_rt']['fail'] > 0 ) {
	WP_CLI::error( 'runtime check failed' );
}
