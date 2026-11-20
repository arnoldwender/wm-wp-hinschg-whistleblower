<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Compliance;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Report categories: the keys stored in wm_whistle_reports.category and their labels.
 *
 * One list for the intake form and the desk. Until 2026-09-15 each carried its own copy, the desk's
 * test form offered keys the portal did not, and the portal labelled the list "nach HinSchG § 2",
 * which it is not: several entries (Diskriminierung, allgemeine Compliance) lie outside § 2.
 */
final class ReportCategories {
	public const DEFAULT = 'general_compliance';

	/**
	 * @return array<string,string> key => label
	 */
	public static function all(): array {
		return [
			'financial_fraud'    => __( 'Finanzbetrug, Untreue, Korruption & Bestechung', 'wm-hinschg-whistleblower' ),
			'data_protection'    => __( 'DSGVO-Verstöße & Datenschutzverletzungen', 'wm-hinschg-whistleblower' ),
			'it_security'        => __( 'IT-Sicherheit & Cyber-Vorfälle', 'wm-hinschg-whistleblower' ),
			'supply_chain'       => __( 'Lieferkette & Menschenrechte', 'wm-hinschg-whistleblower' ),
			'workplace_safety'   => __( 'Arbeitsschutz, Diskriminierung & Belästigung', 'wm-hinschg-whistleblower' ),
			'general_compliance' => __( 'Allgemeine Compliance-Verstöße', 'wm-hinschg-whistleblower' ),
		];
	}

	/** A stored key, or the default when the key is not one of ours. */
	public static function normalize( string $key ): string {
		return array_key_exists( $key, self::all() ) ? $key : self::DEFAULT;
	}

	/** Label for a stored key; an unknown key is shown as stored. */
	public static function label( string $key ): string {
		return self::all()[ $key ] ?? $key;
	}
}
