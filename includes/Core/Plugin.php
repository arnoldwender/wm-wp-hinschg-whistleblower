<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\HinSchG\Database\Schema;
use WMCyber\HinSchG\Crypto\Vault;
use WMCyber\HinSchG\Compliance\HinSchGSlaManager;
use WMCyber\HinSchG\API\RestController;
use WMCyber\HinSchG\CLI\HinSchGCommand;
use WMCyber\HinSchG\Admin\AdminDashboard;
use WMCyber\HinSchG\Frontend\WhistlePortal;
use WMCyber\HinSchG\Security\Capabilities;

final class Plugin {
	private static ?Plugin $instance = null;
	private Vault $vault;
	private HinSchGSlaManager $sla_manager;

	private function __construct() {
		$this->vault = new Vault();
		$this->sla_manager = new HinSchGSlaManager();
	}

	public static function instance(): Plugin {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function boot(): void {
		// An update does not fire the activation hook, so an install that already runs would keep a
		// desk whose capability nobody holds. One integer comparison against an autoloaded option.
		Capabilities::maybe_upgrade();

		// Load text domain
		add_action( 'init', function (): void {
			load_plugin_textdomain(
				'wm-hinschg-whistleblower',
				false,
				dirname( plugin_basename( WM_HINSCHG_FILE ) ) . '/languages'
			);
		} );

		// Initialize REST Controller
		( new RestController( $this->vault, $this->sla_manager ) )->register_routes();

		// Initialize Admin Interface
		if ( is_admin() ) {
			( new AdminDashboard( $this->vault, $this->sla_manager ) )->init();
		}

		// Initialize Frontend Intake Portal (Zero-CDN)
		( new WhistlePortal() )->init();

		// Register WP-CLI Commands
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			HinSchGCommand::register();
		}

		// Register Cron Tasks for HinSchG § 17 SLA checks
		add_action( 'wm_hinschg_hourly_sla_check', [ $this->sla_manager, 'execute_hourly_check' ] );

		do_action( 'wm_hinschg_ready', $this );
	}

	public function get_vault(): Vault {
		return $this->vault;
	}

	public function get_sla_manager(): HinSchGSlaManager {
		return $this->sla_manager;
	}
}
