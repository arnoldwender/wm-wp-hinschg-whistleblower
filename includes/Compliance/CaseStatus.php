<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Compliance;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Labels for the values of wm_whistle_reports.status, shared by the desk and the portal.
 *
 * The code writes submitted (portal, test report), acknowledged (REST /admin/ack) and investigated
 * (REST /admin/reply with is_final_feedback); received, in_investigation and closed come from the
 * demo cases. The portal showed the raw key ("Status: submitted") until 2026-09-15.
 */
final class CaseStatus {
	/**
	 * @return array<string,string> status => label
	 */
	public static function labels(): array {
		$received    = __( 'Eingegangen', 'wm-hinschg-whistleblower' );
		$in_progress = __( 'In Bearbeitung', 'wm-hinschg-whistleblower' );

		return [
			'submitted'        => $received,
			'received'         => $received,
			'acknowledged'     => $in_progress,
			'in_review'        => $in_progress,
			'in_investigation' => $in_progress,
			'investigated'     => __( 'Rückmeldung gegeben', 'wm-hinschg-whistleblower' ),
			'closed'           => __( 'Abgeschlossen', 'wm-hinschg-whistleblower' ),
		];
	}

	/** An unknown value is shown as stored, never as a label that suggests the case is done. */
	public static function label( string $status ): string {
		return self::labels()[ $status ] ?? $status;
	}
}
