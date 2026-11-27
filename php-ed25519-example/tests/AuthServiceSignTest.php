<?php

declare(strict_types=1);

namespace App\Tests;

use App\Services\AuthService;
use App\Services\InvalidBodyException;
use App\Services\SignedData;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AuthServiceSignTest extends TestCase
{
    private AuthService $authService;

    protected function setUp(): void
    {
        $this->authService = TestKeys::newAuthService();
    }

    private static function cases(): array
    {
        $document = json_decode((string) file_get_contents(__DIR__ . '/../../testdata/payload-escaping-cases.json'), true, 512, JSON_THROW_ON_ERROR);

        return $document['cases'];
    }

    public static function acceptedPayloadCases(): Generator
    {
        foreach (self::cases() as $case) {
            if (!($case['rejected'] ?? false)) {
                yield $case['name'] => ['bodyHex' => $case['bodyHex']];
            }
        }
    }

    public static function rejectedPayloadCases(): Generator
    {
        foreach (self::cases() as $case) {
            if ($case['rejected'] ?? false) {
                yield $case['name'] => ['bodyHex' => $case['bodyHex']];
            }
        }
    }

    public function testSharedCaseFileHasMoreThan100Cases(): void
    {
        self::assertGreaterThan(100, count(self::cases()));
    }

    #[DataProvider('acceptedPayloadCases')]
    public function testAcceptedPayloadIsSigned(string $bodyHex): void
    {
        $body = (string) hex2bin($bodyHex);

        $signed = $this->authService->sign($body);

        self::assertMatchesRegularExpression('/^[\x20-\x7e]*$/D', $signed->payload, 'payload must be printable ASCII to fit in a header');
        $document = json_decode($signed->payload, false, 512, JSON_THROW_ON_ERROR);
        self::assertSame($body, $document->data);
        self::assertSignedByOperator($signed);
    }

    #[DataProvider('rejectedPayloadCases')]
    public function testRejectedPayloadThrows(string $bodyHex): void
    {
        $this->expectException(InvalidBodyException::class);

        $this->authService->sign((string) hex2bin($bodyHex));
    }

    public function testReturnsConfiguredIds(): void
    {
        $signed = $this->authService->sign('{}');

        self::assertSame(TestKeys::KEY_ID, $signed->keyId);
        self::assertSame(TestKeys::OPERATOR_ID, $signed->operatorId);
    }

    public function testNonceIsCurrentUuidV7(): void
    {
        $before = (int) floor(microtime(true) * 1000);
        $signed = $this->authService->sign('');
        $after = (int) floor(microtime(true) * 1000);

        $nonce = json_decode($signed->payload, false, 512, JSON_THROW_ON_ERROR)->nonce;
        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D', $nonce);
        $unixMilli = (int) hexdec(substr($nonce, 0, 8) . substr($nonce, 9, 4));
        self::assertGreaterThanOrEqual($before, $unixMilli);
        self::assertLessThanOrEqual($after, $unixMilli);
    }

    public function testEverySignatureUsesFreshNonce(): void
    {
        self::assertNotSame($this->authService->sign('same')->payload, $this->authService->sign('same')->payload);
    }

    private static function assertSignedByOperator(SignedData $signed): void
    {
        $publicKey = sodium_crypto_sign_publickey(TestKeys::operatorKeypair());
        self::assertTrue(TestKeys::verify($publicKey, $signed->payload, (string) base64_decode($signed->signature, true)));
    }
}
