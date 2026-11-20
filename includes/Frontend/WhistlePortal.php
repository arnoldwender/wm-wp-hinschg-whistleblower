<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Frontend;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\HinSchG\Compliance\CaseStatus;
use WMCyber\HinSchG\Compliance\HinSchGSlaManager;
use WMCyber\HinSchG\Compliance\ReportCategories;
use WMCyber\HinSchG\Core\Plugin;
use WMCyber\HinSchG\Security\Capabilities;

/**
 * The public intake form: [wm_whistleblower_portal], [wm_hinschg_portal] or the block wm/hinschg-portal.
 *
 * Also registers WP 6.5+ Block Bindings (wm-hinschg/status) and the GenerateBlocks 2.x Dynamic Tag
 * ({{wm_hinschg_status}}) exposing non-confidential channel status metadata.
 */
final class WhistlePortal {
	public function init(): void {
		add_shortcode( 'wm_hinschg_portal', [ $this, 'render_shortcode' ] );
		add_shortcode( 'wm_whistleblower_portal', [ $this, 'render_shortcode' ] );
		add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_frontend_assets' ] );
		add_action( 'init', [ $this, 'register_gutenberg_block' ] );
		add_action( 'init', [ $this, 'register_block_bindings' ] );
		add_action( 'init', [ $this, 'register_generateblocks_tags' ] );
		add_filter( 'generateblocks_dynamic_tag_replacement', [ $this, 'filter_generateblocks_tag_replacement' ], 10, 3 );
	}

	public function register_gutenberg_block(): void {
		if ( ! function_exists( 'register_block_type' ) ) {
			return;
		}

		$asset_file = WM_HINSCHG_PATH . 'build/index.asset.php';
		$asset      = file_exists( $asset_file )
			? require $asset_file
			: [
				'dependencies' => [ 'wp-block-editor', 'wp-blocks', 'wp-components', 'wp-element', 'wp-i18n', 'wp-server-side-render' ],
				'version'      => WM_HINSCHG_VERSION,
			];

		if ( function_exists( 'wp_register_script' ) ) {
			wp_register_script(
				'wm-hinschg-blocks-editor',
				WM_HINSCHG_URL . 'build/index.js',
				$asset['dependencies'],
				(string) $asset['version'],
				true
			);
		}

		if ( function_exists( 'wp_set_script_translations' ) ) {
			wp_set_script_translations(
				'wm-hinschg-blocks-editor',
				'wm-hinschg-whistleblower',
				WM_HINSCHG_PATH . 'languages'
			);
		}

		register_block_type(
			WM_HINSCHG_PATH . 'blocks/portal',
			[
				'editor_script'   => 'wm-hinschg-blocks-editor',
				'render_callback' => [ $this, 'render_shortcode' ],
			]
		);
	}

	/**
	 * Register WP 6.5+ Block Bindings source wm-hinschg/status.
	 */
	public function register_block_bindings(): void {
		if ( ! function_exists( 'register_block_bindings_source' ) ) {
			return;
		}

		register_block_bindings_source(
			'wm-hinschg/status',
			[
				'label'              => __( 'HinSchG Meldestelle Status', 'wm-hinschg-whistleblower' ),
				'get_value_callback' => [ $this, 'resolve_status_binding' ],
				'uses_context'       => [ 'postId', 'postType' ],
			]
		);
	}

	/**
	 * Resolve WP 6.5+ Block Bindings value for wm-hinschg/status without exposing confidential case data.
	 *
	 * @param array<string, mixed> $source_args Binding arguments.
	 */
	public function resolve_status_binding( array $source_args ): string {
		$key = sanitize_key( (string) ( $source_args['key'] ?? 'channel_label' ) );
		return $this->compute_status_tag_value( $key );
	}

	/**
	 * Register GenerateBlocks 2.x Dynamic Tag {{wm_hinschg_status}}.
	 */
	public function register_generateblocks_tags(): void {
		if ( ! class_exists( 'GenerateBlocks_Register_Dynamic_Tag' ) ) {
			return;
		}

		new \GenerateBlocks_Register_Dynamic_Tag(
			[
				'title'    => __( 'HinSchG Meldestelle Status', 'wm-hinschg-whistleblower' ),
				'tag'      => 'wm_hinschg_status',
				'type'     => 'wm-hinschg',
				'supports' => [],
				'return'   => [ $this, 'render_generateblocks_status_tag' ],
			]
		);
	}

	/**
	 * Render callback for GenerateBlocks 2.x {{wm_hinschg_status}}.
	 *
	 * @param array<string, mixed> $options Tag options.
	 */
	public function render_generateblocks_status_tag( array $options = [] ): string {
		$key = sanitize_key( (string) ( $options['key'] ?? 'channel_label' ) );
		return esc_html( $this->compute_status_tag_value( $key ) );
	}

	/**
	 * Fallback replacement filter for GenerateBlocks dynamic tags.
	 *
	 * @param string               $replacement Existing replacement.
	 * @param array<string, mixed> $tag_details Parsed tag details.
	 * @param mixed                $instance    Block instance.
	 */
	public function filter_generateblocks_tag_replacement( string $replacement, array $tag_details = [], mixed $instance = null ): string {
		unset( $instance );
		if ( ( $tag_details['tag'] ?? '' ) !== 'wm_hinschg_status' ) {
			return $replacement;
		}

		$options = is_array( $tag_details['options'] ?? null ) ? $tag_details['options'] : [];
		return $this->render_generateblocks_status_tag( $options );
	}

	/**
	 * Compute non-confidential status string for Block Bindings and GenerateBlocks.
	 */
	private function compute_status_tag_value( string $key ): string {
		switch ( $key ) {
			case 'ack_days':
				/* translators: %d: statutory acknowledgment days */
				return sprintf( __( '%d Tage Eingangsbestätigung (§ 17 HinSchG)', 'wm-hinschg-whistleblower' ), HinSchGSlaManager::ACK_DAYS );

			case 'feedback_months':
				/* translators: %d: statutory feedback months */
				return sprintf( __( '%d Monate Rückmeldefrist (§ 17 HinSchG)', 'wm-hinschg-whistleblower' ), HinSchGSlaManager::FEEDBACK_MONTHS );

			case 'open_cases':
				if ( ! Capabilities::may_read() ) {
					return '';
				}
				return (string) Plugin::instance()->get_sla_manager()->status_counts()['open'];

			case 'channel_label':
			default:
				$has_key = '' !== Plugin::instance()->get_vault()->get_public_key();
				return $has_key
					? __( 'Interne Meldestelle aktiv', 'wm-hinschg-whistleblower' )
					: __( 'Meldestelle wird eingerichtet', 'wm-hinschg-whistleblower' );
		}
	}

	public function enqueue_frontend_assets(): void {
		wp_register_style(
			'wm-hinschg-portal-css',
			WM_HINSCHG_URL . 'assets/css/portal-zero-cdn.css',
			[],
			WM_HINSCHG_VERSION
		);

		wp_register_script(
			'wm-hinschg-portal-js',
			WM_HINSCHG_URL . 'assets/js/portal-crypto.js',
			[],
			WM_HINSCHG_VERSION,
			true
		);

		$config = [
			'restUrl'    => esc_url_raw( rest_url( 'wm-hinschg/v1/' ) ),
			'nonce'      => wp_create_nonce( 'wp_rest' ),
			// The status view showed the stored keys ("submitted", "financial_fraud") until 2026-09-15.
			'categories' => ReportCategories::all(),
			'statuses'   => CaseStatus::labels(),
		];

		if ( function_exists( 'apply_filters' ) ) {
			$config = (array) apply_filters( 'wm_hinschg_portal_config', $config );
		}

		wp_localize_script( 'wm-hinschg-portal-js', 'wmHinSchGConfig', $config );
	}

	/**
	 * Render the whistleblower intake and status portal.
	 *
	 * @param array<string, mixed>|string $atts Shortcode or Gutenberg block attributes.
	 */
	public function render_shortcode( array|string $atts = [] ): string {
		wp_enqueue_style( 'wm-hinschg-portal-css' );
		wp_enqueue_script( 'wm-hinschg-portal-js' );

		$parsed    = is_array( $atts ) ? $atts : [];
		$title     = isset( $parsed['title'] ) && '' !== trim( (string) $parsed['title'] )
			? sanitize_text_field( (string) $parsed['title'] )
			: __( 'Interne Meldestelle', 'wm-hinschg-whistleblower' );
		$show_desc = ! array_key_exists( 'showDescription', $parsed ) || (bool) $parsed['showDescription'];

		ob_start();
		?>
		<div class="wm-whistle-portal" id="wm-whistle-app">
			<div class="wm-whistle-header">
				<h2 class="wm-portal-title"><?php echo esc_html( $title ); ?></h2>
				<?php if ( $show_desc ) : ?>
					<p class="wm-portal-desc">
						<?php esc_html_e( 'Hier können Sie Hinweise auf Verstöße melden. Name und E-Mail-Adresse werden nicht abgefragt.', 'wm-hinschg-whistleblower' ); ?>
					</p>
				<?php endif; ?>
			</div>

			<div class="wm-whistle-tabs" role="tablist">
				<button class="wm-whistle-tab-btn active" id="tab-submit-btn" role="tab" aria-selected="true" aria-controls="panel-submit">
					<?php esc_html_e( 'Neuen Hinweis melden', 'wm-hinschg-whistleblower' ); ?>
				</button>
				<button class="wm-whistle-tab-btn" id="tab-status-btn" role="tab" aria-selected="false" aria-controls="panel-status">
					<?php esc_html_e( 'Vorgang abrufen', 'wm-hinschg-whistleblower' ); ?>
				</button>
			</div>

			<!-- Panel 1: report submission -->
			<div class="wm-whistle-panel active" id="panel-submit" role="tabpanel" aria-labelledby="tab-submit-btn">
				<div class="wm-whistle-notice">
					<strong><?php esc_html_e( 'Was gespeichert wird:', 'wm-hinschg-whistleblower' ); ?></strong>
					<?php esc_html_e( 'Kategorie und Sachverhalt, auf dem Server verschlüsselt. Ihre IP-Adresse wird nicht mit der Meldung gespeichert; zur Begrenzung der Anfragen hält die Website bis zu einer Stunde einen mit ihrem Geheimschlüssel gebildeten Hash (HMAC) davon vor. Ob der Webserver Zugriffe protokolliert, legt der Betreiber der Website fest, nicht dieses Formular. Nach dem Absenden erhalten Sie eine Vorgangs-ID und einen Zugangsschlüssel für Rückfragen und Rückmeldungen.', 'wm-hinschg-whistleblower' ); ?>
				</div>

				<form id="wm-whistle-submit-form" class="wm-whistle-form">
					<div class="wm-form-group">
						<label for="wm-report-category"><?php esc_html_e( 'Kategorie', 'wm-hinschg-whistleblower' ); ?></label>
						<select id="wm-report-category" name="category" required>
							<?php foreach ( ReportCategories::all() as $key => $label ) : ?>
								<option value="<?php echo esc_attr( $key ); ?>"<?php echo ReportCategories::DEFAULT === $key ? ' selected' : ''; ?>><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
					</div>

					<div class="wm-form-group">
						<label for="wm-report-description"><?php esc_html_e( 'Sachverhalt', 'wm-hinschg-whistleblower' ); ?></label>
						<textarea id="wm-report-description" name="description" rows="6" placeholder="<?php echo esc_attr__( 'Beschreiben Sie den Sachverhalt möglichst genau (Ort, Datum, beteiligte Personen) …', 'wm-hinschg-whistleblower' ); ?>" required></textarea>
					</div>

					<button type="submit" class="wm-whistle-submit-btn">
						<?php esc_html_e( 'Hinweis absenden', 'wm-hinschg-whistleblower' ); ?>
					</button>
				</form>

				<div id="wm-submit-result" class="wm-result-card" style="display:none;"></div>
			</div>

			<!-- Panel 2: status and follow-up messages via access token -->
			<div class="wm-whistle-panel" id="panel-status" role="tabpanel" aria-labelledby="tab-status-btn" style="display:none;">
				<div class="wm-whistle-notice">
					<?php esc_html_e( 'Geben Sie Vorgangs-ID und Zugangsschlüssel ein, um den Bearbeitungsstand zu sehen und der Meldestelle zu schreiben.', 'wm-hinschg-whistleblower' ); ?>
				</div>

				<form id="wm-whistle-status-form" class="wm-whistle-form">
					<div class="wm-form-group">
						<label for="wm-case-id"><?php esc_html_e( 'Vorgangs-ID', 'wm-hinschg-whistleblower' ); ?></label>
						<input type="text" id="wm-case-id" name="case_public_id" placeholder="<?php echo esc_attr__( 'z. B. CASE-A1B2C3D4', 'wm-hinschg-whistleblower' ); ?>" required />
					</div>
					<div class="wm-form-group">
						<label for="wm-access-token"><?php esc_html_e( 'Zugangsschlüssel', 'wm-hinschg-whistleblower' ); ?></label>
						<input type="password" id="wm-access-token" name="access_token" placeholder="<?php echo esc_attr__( '64 Zeichen', 'wm-hinschg-whistleblower' ); ?>" required />
					</div>
					<button type="submit" class="wm-whistle-submit-btn">
						<?php esc_html_e( 'Vorgang laden', 'wm-hinschg-whistleblower' ); ?>
					</button>
				</form>

				<div id="wm-status-result" class="wm-result-card" style="display:none;"></div>
			</div>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}
