<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WMCyber\HinSchG\Crypto\Vault;

/**
 * The follow-up chat (wm_whistle_messages.encrypted_message) stored plain text until 2026-09-14:
 * the whistleblower's replies, the officer's acknowledgment and the officer's answers sat next
 * to an envelope-encrypted report in the same database, readable by anyone with a dump. The
 * column was called encrypted_message the whole time (fleet audit 2026-09-13 §6.2 #28).
 */
final class MessageSealingTest extends TestCase {
	private Vault $vault;

	protected function setUp(): void {
		parent::setUp();
		global $mock_wp_options;
		$res = openssl_pkey_new( [ 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ] );
		openssl_pkey_export( $res, $private_key );
		$mock_wp_options['wm_hinschg_private_key'] = $private_key;
		$mock_wp_options['wm_hinschg_public_key']  = openssl_pkey_get_details( $res )['key'];
		$this->vault = new Vault();
	}

	public function test_sealed_message_is_an_envelope_without_the_text(): void {
		$sealed = $this->vault->seal_message( 'Der Zeuge heißt Müller.', 'whistleblower' );
		$json   = json_decode( $sealed, true );

		$this->assertIsArray( $json );
		$this->assertArrayHasKey( 'payload', $json );
		$this->assertArrayHasKey( 'key', $json );
		$this->assertArrayHasKey( 'tag', $json );
		$this->assertArrayHasKey( 'iv', $json );
		$this->assertStringNotContainsString( 'Müller', $sealed );
		$this->assertStringNotContainsString( base64_encode( 'Der Zeuge' ), $sealed );
	}

	public function test_open_message_restores_the_text_and_reports_it_sealed(): void {
		$sealed = $this->vault->seal_message( 'Ich habe die Belege gesehen.', 'whistleblower' );
		$opened = $this->vault->open_message( $sealed );

		$this->assertSame( 'Ich habe die Belege gesehen.', $opened['message'] );
		$this->assertTrue( $opened['sealed'] );
	}

	public function test_two_seals_of_the_same_text_differ(): void {
		$a = $this->vault->seal_message( 'gleich', 'whistleblower' );
		$b = $this->vault->seal_message( 'gleich', 'whistleblower' );
		$this->assertNotSame( $a, $b, 'a fresh AES key and IV per message: equal texts must not produce equal rows' );
	}

	public function test_legacy_plaintext_rows_pass_through_flagged(): void {
		$opened = $this->vault->open_message( 'Alte Nachricht im Klartext.' );
		$this->assertSame( 'Alte Nachricht im Klartext.', $opened['message'] );
		$this->assertFalse( $opened['sealed'] );
	}

	public function test_a_tampered_envelope_does_not_open(): void {
		$sealed = $this->vault->seal_message( 'unverändert', 'compliance_officer' );
		$json   = json_decode( $sealed, true );
		$json['payload'] = base64_encode( strrev( (string) base64_decode( $json['payload'] ) ) );

		$this->expectException( \RuntimeException::class );
		$this->vault->open_message( (string) json_encode( $json ) );
	}

	public function test_whistleblower_messages_never_include_reporter_box_even_with_token_hash(): void {
		$token_hash = hash( 'sha256', 'unit-test-token' );
		$sealed     = $this->vault->seal_message( 'Vertraulicher Hinweis', 'whistleblower', $token_hash );
		$json       = json_decode( $sealed, true );

		$this->assertIsArray( $json );
		$this->assertArrayNotHasKey( 'reporter_box', $json );
	}

	public function test_officer_messages_include_reporter_box_and_open_only_with_matching_token_hash(): void {
		$token_hash = hash( 'sha256', 'unit-test-token' );
		$sealed     = $this->vault->seal_message( 'Rückfrage der Meldestelle', 'compliance_officer', $token_hash );
		$json       = json_decode( $sealed, true );

		$this->assertIsArray( $json );
		$this->assertArrayHasKey( 'reporter_box', $json );

		$opened = Vault::open_message_for_reporter( $sealed, $token_hash );
		$this->assertSame( 'Rückfrage der Meldestelle', $opened['message'] );
		$this->assertTrue( $opened['sealed'] );

		$this->expectException( \RuntimeException::class );
		Vault::open_message_for_reporter( $sealed, hash( 'sha256', 'wrong-token' ) );
	}
}
