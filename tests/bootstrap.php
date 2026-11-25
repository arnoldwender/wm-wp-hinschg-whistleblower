<?php
declare(strict_types=1);

// Lightweight WordPress Mocking Bootstrap for HinSchG Testing
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', sys_get_temp_dir() . '/wordpress/' );
}
if ( ! defined( 'WM_HINSCHG_PATH' ) ) {
	define( 'WM_HINSCHG_PATH', dirname( __DIR__ ) . '/' );
}
if ( ! defined( 'WM_HINSCHG_VERSION' ) ) {
	define( 'WM_HINSCHG_VERSION', '1.4.1' );
}

require_once dirname( __DIR__ ) . '/includes/Crypto/Vault.php';
require_once dirname( __DIR__ ) . '/includes/Compliance/HinSchGSlaManager.php';

// WordPress helper mocks
if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $options = 0, $depth = 512 ) {
		return json_encode( $data, $options, $depth );
	}
}
if ( ! function_exists( 'wp_salt' ) ) {
	function wp_salt( $scheme = 'auth' ) {
		return 'test_mock_salt_for_hinschg_testing_purposes_only';
	}
}
if ( ! function_exists( 'current_time' ) ) {
	function current_time( $type, $gmt = false ) {
		return gmdate( 'Y-m-d H:i:s' );
	}
}
if ( ! function_exists( 'get_option' ) ) {
	function get_option( $opt, $default = false ) {
		global $mock_wp_options;
		return $mock_wp_options[ $opt ] ?? $default;
	}
}
if ( ! function_exists( 'update_option' ) ) {
	function update_option( $opt, $value ) {
		global $mock_wp_options;
		$mock_wp_options[ $opt ] = $value;
		return true;
	}
}
if ( ! function_exists( 'delete_option' ) ) {
	function delete_option( $opt ) {
		global $mock_wp_options;
		unset( $mock_wp_options[ $opt ] );
		return true;
	}
}
if ( ! function_exists( '__' ) ) {
	function __( string $text, string $domain = 'default' ): string {
		return $text;
	}
}
if ( ! function_exists( 'do_action' ) ) {
	function do_action( $tag, ...$args ) {}
}
