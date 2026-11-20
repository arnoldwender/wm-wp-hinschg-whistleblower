<?php
/**
 * Plugin Name:       WM HinSchG Whistleblower Desk
 * Plugin URI:        https://arnoldwender.com/wordpress-plugins/wm-hinschg-whistleblower/
 * Description:       Internal whistleblowing channel: report form, server-side encryption of reports and messages, deadline tracking under § 17 HinSchG and a keyed audit log. It does not assess legal compliance.
 * Version:           1.4.0
 * Requires at least: 6.4
 * Requires PHP:      8.2
 * Author:            Arnold Wender
 * Author URI:        https://arnoldwender.com
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wm-hinschg-whistleblower
 * Domain Path:       /languages
 */

declare(strict_types=1);

namespace WMCyber\HinSchG;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WM_HINSCHG_VERSION', '1.4.0' );
define( 'WM_HINSCHG_FILE', __FILE__ );
define( 'WM_HINSCHG_PATH', plugin_dir_path( __FILE__ ) );
define( 'WM_HINSCHG_URL', plugin_dir_url( __FILE__ ) );

// Autoloader for Plugin Namespaces
spl_autoload_register( function ( string $class ): void {
	$prefix = 'WMCyber\\HinSchG\\';
	$base_dir = WM_HINSCHG_PATH . 'includes/';

	$len = strlen( $prefix );
	if ( strncmp( $prefix, $class, $len ) !== 0 ) {
		return;
	}

	$relative_class = substr( $class, $len );
	$file = $base_dir . str_replace( '\\', '/', $relative_class ) . '.php';

	if ( file_exists( $file ) ) {
		require_once $file;
	}
} );

// Activation & Deactivation Hooks
register_activation_hook( __FILE__, [ Database\Schema::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ Database\Schema::class, 'deactivate' ] );

// Multisite: initialize tables, roles, cron and vault key when a new site is created while network-activated.
add_action( 'wp_initialize_site', function ( $new_site ): void {
	if ( ! is_object( $new_site ) || ! isset( $new_site->blog_id ) ) {
		return;
	}
	if ( ! function_exists( 'is_plugin_active_for_network' ) && is_file( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	if ( ! function_exists( 'is_plugin_active_for_network' ) || ! is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
		return;
	}
	if ( ! function_exists( 'switch_to_blog' ) || ! function_exists( 'restore_current_blog' ) ) {
		return;
	}
	switch_to_blog( (int) $new_site->blog_id );
	try {
		Database\Schema::activate();
	} finally {
		restore_current_blog();
	}
} );

// Register as Spoke in WM Suite Hub
add_filter( 'wm_register_suite_module', function ( array $modules ): array {
	if ( ! class_exists( 'WMCyber\HinSchG\Adapters\HinSchG_Spoke_Adapter' ) && file_exists( WM_HINSCHG_PATH . 'includes/Adapters/HinSchG_Spoke_Adapter.php' ) ) {
		require_once WM_HINSCHG_PATH . 'includes/Adapters/HinSchG_Spoke_Adapter.php';
	}
	if ( class_exists( 'WMCyber\HinSchG\Adapters\HinSchG_Spoke_Adapter' ) ) {
		$modules[] = new Adapters\HinSchG_Spoke_Adapter();
	}
	return $modules;
} );

// Initialize Core Service Container
add_action( 'plugins_loaded', function (): void {
	Core\Plugin::instance()->boot();
} );

