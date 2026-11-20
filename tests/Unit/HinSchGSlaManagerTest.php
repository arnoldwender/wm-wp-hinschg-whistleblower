<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WMCyber\HinSchG\Compliance\HinSchGSlaManager;

final class HinSchGSlaManagerTest extends TestCase {
	private HinSchGSlaManager $sla_manager;

	protected function setUp(): void {
		parent::setUp();
		$this->sla_manager = new HinSchGSlaManager();
	}

	public function test_compute_deadlines_7_days_and_3_months(): void {
		$base = new \DateTimeImmutable( '2026-08-01 10:00:00', new \DateTimeZone( 'UTC' ) );
		$deadlines = $this->sla_manager->compute_deadlines( $base );

		$this->assertSame( '2026-08-08 10:00:00', $deadlines['ack_deadline'] );
		$this->assertSame( '2026-11-01 10:00:00', $deadlines['feedback_deadline'] );
	}
}
