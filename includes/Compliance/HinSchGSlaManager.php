<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Compliance;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HinSchGSlaManager {
	public const ACK_DAYS = 7;
	public const FEEDBACK_MONTHS = 3;

	/**
	 * Compute HinSchG § 17 legal deadlines.
	 *
	 * @return array{ack_deadline: string, feedback_deadline: string}
	 */
	public function compute_deadlines( ?\DateTimeImmutable $from = null ): array {
		$base = $from ?? new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) );

		$ack_deadline      = $base->modify( '+' . self::ACK_DAYS . ' days' );
		$feedback_deadline = $base->modify( '+' . self::FEEDBACK_MONTHS . ' months' );

		return [
			'ack_deadline'      => $ack_deadline->format( 'Y-m-d H:i:s' ),
			'feedback_deadline' => $feedback_deadline->format( 'Y-m-d H:i:s' ),
		];
	}

	/**
	 * Hourly SLA checker triggered by WP-Cron or CLI: counts, and the breach action when a deadline passed.
	 *
	 * @return array{breached_ack: int, breached_feedback: int, impending_ack: int}
	 */
	public function execute_hourly_check(): array {
		$counts = $this->status_counts();

		if ( $counts['breached_ack'] > 0 || $counts['breached_feedback'] > 0 ) {
			do_action( 'wm_hinschg_sla_breach_detected', [
				'breached_ack'      => $counts['breached_ack'],
				'breached_feedback' => $counts['breached_feedback'],
				'impending_ack'     => $counts['impending_ack'],
			] );
		}

		return [
			'breached_ack'      => $counts['breached_ack'],
			'breached_feedback' => $counts['breached_feedback'],
			'impending_ack'     => $counts['impending_ack'],
		];
	}

	/**
	 * The same counts without side effects, for screens and telemetry that are read often. The desk showed
	 * a fixed "0 Retrasos" for both deadlines until 2026-09-15, whatever the cases held.
	 *
	 * @return array{breached_ack: int, breached_feedback: int, impending_ack: int, open: int}
	 */
	public function status_counts(): array {
		global $wpdb;
		$table_reports = $wpdb->prefix . 'wm_whistle_reports';

		$now = current_time( 'mysql', true );

		// 1. Pending Acknowledgment Breaches (Ack not sent, now > ack_sla_deadline)
		$breached_ack = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM $table_reports WHERE ack_sent_at IS NULL AND ack_sla_deadline < %s AND status != 'closed'",
			$now
		) );

		// 2. Impending Acknowledgment Warnings (Within 48 hours of 7-day deadline)
		$warning_window = gmdate( 'Y-m-d H:i:s', time() + ( 48 * 3600 ) );
		$impending_ack = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM $table_reports WHERE ack_sent_at IS NULL AND ack_sla_deadline <= %s AND ack_sla_deadline > %s AND status != 'closed'",
			$warning_window,
			$now
		) );

		// 3. Feedback Deadline Breaches (Feedback not sent, now > feedback_sla_deadline)
		$breached_feedback = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM $table_reports WHERE feedback_sent_at IS NULL AND feedback_sla_deadline < %s AND status != 'closed'",
			$now
		) );

		// Everything not closed and without final feedback (REST /admin/reply sets feedback_sent_at and status investigated together).
		$open = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$table_reports} WHERE feedback_sent_at IS NULL AND status != %s",
			'closed'
		) );

		return [
			'breached_ack'      => $breached_ack,
			'breached_feedback' => $breached_feedback,
			'impending_ack'     => $impending_ack,
			'open'              => $open,
		];
	}
}
