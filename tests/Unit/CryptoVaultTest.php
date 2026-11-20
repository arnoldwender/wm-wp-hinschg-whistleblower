<?php
declare(strict_types=1);

namespace WMCyber\HinSchG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WMCyber\HinSchG\Crypto\Vault;

final class CryptoVaultTest extends TestCase {
	private Vault $vault;

	protected function setUp(): void {
		parent::setUp();

		// Generate RSA-4096 pair for testing
		$res = openssl_pkey_new( [
			'digest_alg'       => 'sha256',
			'private_key_bits' => 4096,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		] );
		openssl_pkey_export( $res, $private_key );
		$details = openssl_pkey_get_details( $res );

		update_option( 'wm_hinschg_private_key', $private_key );
		update_option( 'wm_hinschg_public_key', $details['key'] );

		$this->vault = new Vault();
	}

	public function test_envelope_encryption_and_decryption(): void {
		$original_payload = [
			'category'    => 'financial_fraud',
			'description' => 'Unregelmäßige Buchungen auf Offshore-Konten festgestellt.',
			'amount'      => 450000,
		];

		$envelope = $this->vault->encrypt_envelope( $original_payload );

		$this->assertArrayHasKey( 'payload', $envelope );
		$this->assertArrayHasKey( 'key', $envelope );
		$this->assertArrayHasKey( 'tag', $envelope );
		$this->assertArrayHasKey( 'iv', $envelope );

		$decrypted = $this->vault->decrypt_envelope(
			$envelope['payload'],
			$envelope['key'],
			$envelope['tag'],
			$envelope['iv']
		);

		$this->assertSame( $original_payload, $decrypted );
	}

	public function test_access_token_entropy_and_hashing(): void {
		$token1 = $this->vault->generate_access_token();
		$token2 = $this->vault->generate_access_token();

		$this->assertSame( 64, strlen( $token1 ) );
		$this->assertSame( 64, strlen( $token2 ) );
		$this->assertNotSame( $token1, $token2 );

		$hash1 = $this->vault->hash_token( $token1 );
		$hash2 = $this->vault->hash_token( $token1 );

		$this->assertSame( $hash1, $hash2 );
		$this->assertSame( 64, strlen( $hash1 ) );
	}

	public function test_dual_envelope_recovery_public_key_seals_and_clears(): void {
		$rec_res = openssl_pkey_new( [
			'digest_alg'       => 'sha256',
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		] );
		$rec_pub = (string) openssl_pkey_get_details( $rec_res )['key'];

		$installed = Vault::install_recovery_public_key( $rec_pub );
		$this->assertTrue( $installed['ok'] );

		$payload  = [ 'category' => 'it_security', 'description' => 'Backup key test.' ];
		$envelope = $this->vault->encrypt_envelope( $payload );

		$this->assertArrayHasKey( 'recovery_key', $envelope );
		$aes_key = '';
		$this->assertTrue(
			openssl_private_decrypt( (string) base64_decode( $envelope['recovery_key'], true ), $aes_key, $rec_res, OPENSSL_PKCS1_OAEP_PADDING )
		);
		$decrypted = openssl_decrypt(
			(string) base64_decode( $envelope['payload'], true ),
			'aes-256-gcm',
			$aes_key,
			OPENSSL_RAW_DATA,
			(string) base64_decode( $envelope['iv'], true ),
			(string) base64_decode( $envelope['tag'], true )
		);
		$this->assertSame( $payload, json_decode( (string) $decrypted, true ) );

		$cleared = Vault::install_recovery_public_key( '' );
		$this->assertTrue( $cleared['ok'] );
		$after = $this->vault->encrypt_envelope( $payload );
		$this->assertArrayNotHasKey( 'recovery_key', $after );
	}
}
