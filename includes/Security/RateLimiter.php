<?php
/**
 * Rate limiting for the public HinSchG endpoints.
 *
 * /report/submit, /report/status and /report/chat are public by design — a whistleblower has
 * no account and this channel accepts anonymous reports (§ 16 Abs. 1 HinSchG asks that they be
 * processed, it does not require channels that enable them). Public and unmetered are different
 * things though: without a limiter, /report/status is an offline oracle for guessing case tokens
 * and /report/submit accepts unlimited flooding.
 *
 * Counters live in transients keyed by a blinded client IP. The IP is never stored raw —
 * sec. 8 HinSchG requires confidentiality of the reporting person, so the limiter must not
 * become the log that identifies them.
 *
 * @package WMCyber\HinSchG
 */

declare(strict_types=1);

namespace WMCyber\HinSchG\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Fixed-window rate limiter backed by transients.
 */
final class RateLimiter {

	/**
	 * Blind the client IP so no raw address is persisted.
	 *
	 * @return string 32 hex chars.
	 */
	private static function client_key(): string {
		$ip         = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0.0.0.0';
		$epoch_salt = wp_salt( 'auth' ) . '|' . gmdate( 'Y-m-d-H' );
		return substr( hash_hmac( 'sha256', $ip, $epoch_salt ), 0, 32 );
	}

	/**
	 * Consume one unit from a bucket.
	 *
	 * @param string $bucket   Logical bucket name, e.g. 'status'.
	 * @param int    $limit    Maximum hits per window.
	 * @param int    $window   Window length in seconds.
	 * @return bool True when the caller is within budget, false when it must be refused.
	 */
	public static function consume( string $bucket, int $limit, int $window ): bool {
		if ( function_exists( 'apply_filters' ) ) {
			$limit = max( 1, (int) apply_filters( 'wm_hinschg_rest_rate_limit', $limit, $bucket, $window ) );
		}

		$key   = 'wm_hinschg_rl_' . $bucket . '_' . self::client_key();
		$count = (int) get_transient( $key );

		if ( $count >= $limit ) {
			return false;
		}

		// set_transient refreshes the TTL on every write, which would turn a fixed window into
		// a sliding one that never expires under sustained load. Only the first write in a
		// window sets the expiry.
		if ( 0 === $count ) {
			set_transient( $key, 1, $window );
			return true;
		}

		set_transient( $key, $count + 1, self::remaining_ttl( $key, $window ) );
		return true;
	}

	/**
	 * Remaining TTL for a transient, falling back to the full window.
	 *
	 * @param string $key    Transient key.
	 * @param int    $window Window length in seconds.
	 * @return int
	 */
	private static function remaining_ttl( string $key, int $window ): int {
		$timeout = (int) get_option( '_transient_timeout_' . $key, 0 );
		$left    = $timeout - time();

		return $left > 0 ? $left : $window;
	}

	/**
	 * Standard refusal payload.
	 *
	 * @return \WP_Error
	 */
	public static function refusal(): \WP_Error {
		return new \WP_Error(
			'wm_hinschg_rate_limited',
			__( 'Zu viele Anfragen. Bitte versuchen Sie es spaeter erneut.', 'wm-hinschg-whistleblower' ),
			array( 'status' => 429 )
		);
	}
}
