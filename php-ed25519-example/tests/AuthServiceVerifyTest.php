<?php

declare(strict_types=1);

namespace App\Tests;

use App\Http\VerifyRequestFactory;
use App\Services\AuthService;
use Closure;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

final class AuthServiceVerifyTest extends TestCase
{
    private const string BODY = '{"amount":100}';

    private AuthService $authService;

    protected function setUp(): void
    {
        $this->authService = TestKeys::newAuthService();
    }

    private static function nonceAt(int $unixMilli): string
    {
        $hex = sprintf('%012x', $unixMilli);
        $random = bin2hex(random_bytes(8));

        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-7' . substr($random, 0, 3) . '-8' . substr($random, 3, 3) . '-' . substr($random, 4, 12);
    }

    private static function nowMillis(): int
    {
        return (int) floor(microtime(true) * 1000);
    }

    private static function signedHeaders(
        string $body = self::BODY,
        string|int|null $data = null,
        string $payloadDomain = 'five-gaming',
        string $headerDomain = 'five-gaming',
        ?string $nonce = null,
        ?int $notBefore = null,
        ?int $notAfter = null,
        ?string $root = null,
        ?string $payloadSigner = null,
        ?string $payloadOverride = null,
    ): array {
        $nonce ??= self::nonceAt(self::nowMillis());
        $notBefore ??= time() - 60;
        $notAfter ??= time() + 3600;
        $intermediate = TestKeys::randomKeypair();
        $intermediatePublicKey = base64_encode(sodium_crypto_sign_publickey($intermediate));
        $certificate = '{"not_after":' . $notAfter . ',"not_before":' . $notBefore
            . ',"public_key":"' . $intermediatePublicKey . '"}';

        $payload = $payloadOverride ?? json_encode(
            ['data' => $data ?? $body, 'domain' => $payloadDomain, 'nonce' => $nonce],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
        );

        return [
            'X-Sign-Version' => '2',
            'X-Sign-Domain' => $headerDomain,
            'X-Sign-Nonce' => $nonce,
            'X-Sign-Payload' => $payload,
            'X-Sign-Signature' => base64_encode(TestKeys::sign($payloadSigner ?? $intermediate, $payload)),
            'X-Sign-Intermediate-Public-Key' => $intermediatePublicKey,
            'X-Sign-Intermediate-Signature' => base64_encode(TestKeys::sign($root ?? TestKeys::rootKeypair(), $certificate)),
            'X-Sign-Intermediate-Not-Before' => (string) $notBefore,
            'X-Sign-Intermediate-Not-After' => (string) $notAfter,
        ];
    }

    private static function request(array $headers): ServerRequestInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/Auth/verify');
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $request;
    }

    private function verifyRequest(ServerRequestInterface $request, string $body = self::BODY): bool
    {
        return $this->authService->verify(VerifyRequestFactory::fromRequest($request), $body);
    }

    private function verify(
        string $body = self::BODY,
        string|int|null $data = null,
        string $payloadDomain = 'five-gaming',
        string $headerDomain = 'five-gaming',
        ?string $nonce = null,
        ?int $notBefore = null,
        ?int $notAfter = null,
        ?string $root = null,
        ?string $payloadSigner = null,
        ?string $payloadOverride = null,
        ?Closure $tamper = null,
    ): bool {
        $headers = self::signedHeaders(
            body: $body,
            data: $data,
            payloadDomain: $payloadDomain,
            headerDomain: $headerDomain,
            nonce: $nonce,
            notBefore: $notBefore,
            notAfter: $notAfter,
            root: $root,
            payloadSigner: $payloadSigner,
            payloadOverride: $payloadOverride,
        );
        if ($tamper !== null) {
            $headers = $tamper($headers);
        }

        return $this->verifyRequest(self::request($headers), $body);
    }

    private static function set(string $name, string $value): Closure
    {
        return static function (array $headers) use ($name, $value): array {
            $headers[$name] = $value;

            return $headers;
        };
    }

    private static function remove(string $name): Closure
    {
        return static function (array $headers) use ($name): array {
            unset($headers[$name]);

            return $headers;
        };
    }

    public function testValidRequest(): void
    {
        self::assertTrue($this->verify());
    }

    public function testUnicodeBodyWithRawUtf8Payload(): void
    {
        self::assertTrue($this->verify(body: '{"name":"Joë’s Café — €5","emoji":"🎰"}'));
    }

    public function testEmptyBody(): void
    {
        self::assertTrue($this->verify(body: ''));
    }

    public function testNonceSlightlyInFutureWithinClockSkew(): void
    {
        self::assertTrue($this->verify(nonce: self::nonceAt(self::nowMillis() + 30_000)));
    }

    public function testReplayedRequest(): void
    {
        $request = self::request(self::signedHeaders());

        self::assertTrue($this->verifyRequest($request));
        self::assertFalse($this->verifyRequest($request));
    }

    public function testTamperedBody(): void
    {
        self::assertFalse($this->verifyRequest(self::request(self::signedHeaders()), '{"amount":999}'));
    }

    public function testNoHeadersAtAll(): void
    {
        self::assertFalse($this->verifyRequest(self::request([]), ''));
    }

    public function testWrongVersion(): void
    {
        self::assertFalse($this->verify(tamper: self::set('X-Sign-Version', '1')));
    }

    public function testDuplicatedHeader(): void
    {
        $headers = self::signedHeaders();
        $request = self::request($headers)->withAddedHeader('X-Sign-Signature', $headers['X-Sign-Signature']);

        self::assertFalse($this->verifyRequest($request));
    }

    public function testMissingSignature(): void
    {
        self::assertFalse($this->verify(tamper: self::remove('X-Sign-Signature')));
    }

    public function testSignatureNotBase64(): void
    {
        self::assertFalse($this->verify(tamper: self::set('X-Sign-Signature', 'not-base64!!')));
    }

    public function testSignatureWrongLength(): void
    {
        self::assertFalse($this->verify(tamper: self::set('X-Sign-Signature', base64_encode(str_repeat("\0", 63)))));
    }

    public function testPayloadSignedByOtherKey(): void
    {
        self::assertFalse($this->verify(payloadSigner: TestKeys::randomKeypair()));
    }

    public function testCertificateSignedByOtherRoot(): void
    {
        self::assertFalse($this->verify(root: TestKeys::randomKeypair()));
    }

    public function testCertificateValidityExtendedAfterSigning(): void
    {
        self::assertFalse($this->verify(tamper: self::set('X-Sign-Intermediate-Not-After', '9999999999')));
    }

    public function testCertificateNotAfterNotANumber(): void
    {
        self::assertFalse($this->verify(tamper: self::set('X-Sign-Intermediate-Not-After', 'soon')));
    }

    public function testCertificateExpired(): void
    {
        self::assertFalse($this->verify(notAfter: time() - 1));
    }

    public function testCertificateNotYetValid(): void
    {
        self::assertFalse($this->verify(notBefore: time() + 600));
    }

    public function testMissingPayload(): void
    {
        self::assertFalse($this->verify(tamper: self::remove('X-Sign-Payload')));
    }

    public function testPayloadNotJson(): void
    {
        self::assertFalse($this->verify(payloadOverride: 'not json'));
    }

    public function testPayloadIsJsonArray(): void
    {
        self::assertFalse($this->verify(payloadOverride: '[1,2]'));
    }

    public function testDataIsNotString(): void
    {
        self::assertFalse($this->verify(data: 100));
    }

    public function testPayloadDomainMismatch(): void
    {
        self::assertFalse($this->verify(payloadDomain: 'evil'));
    }

    public function testHeaderDomainMismatch(): void
    {
        self::assertFalse($this->verify(headerDomain: 'evil'));
    }

    public function testNonceHeaderMismatch(): void
    {
        self::assertFalse($this->verify(tamper: self::set('X-Sign-Nonce', self::nonceAt(self::nowMillis()))));
    }

    public function testNonceTooOld(): void
    {
        self::assertFalse($this->verify(nonce: self::nonceAt(self::nowMillis() - 6 * 60_000)));
    }

    public function testNonceTooFarInFuture(): void
    {
        self::assertFalse($this->verify(nonce: self::nonceAt(self::nowMillis() + 2 * 60_000)));
    }

    public function testNonceTooShort(): void
    {
        self::assertFalse($this->verify(nonce: 'abc'));
    }

    public function testNonceNotHex(): void
    {
        self::assertFalse($this->verify(nonce: 'zzzzzzzz-zzzz-7zzz-8zzz-zzzzzzzzzzzz'));
    }

    private function verifyRaw(string $json, string $body = self::BODY): bool
    {
        $nonce = self::nonceAt(self::nowMillis());

        return $this->verify(body: $body, nonce: $nonce, payloadOverride: str_replace('NONCE', $nonce, $json));
    }

    public function testPayloadKeysDifferInCase(): void
    {
        self::assertFalse($this->verifyRaw('{"DATA":"{\"amount\":100}","Domain":"five-gaming","Nonce":"NONCE"}'));
    }

    public function testValidSurrogatePairInData(): void
    {
        self::assertTrue($this->verifyRaw('{"data":"🚀","domain":"five-gaming","nonce":"NONCE"}', "\u{1F680}"));
    }

    public function testLoneSurrogateInDataIsRejected(): void
    {
        self::assertFalse($this->verifyRaw('{"data":"\udcff","domain":"five-gaming","nonce":"NONCE"}', "\u{FFFD}"));
    }

    public function testLoneSurrogateInUnusedKeyIsRejected(): void
    {
        self::assertFalse($this->verifyRaw('{"data":"{\"amount\":100}","domain":"five-gaming","nonce":"NONCE","x":"\udcff"}'));
    }

    public function testInvalidUtf8ByteInPayload(): void
    {
        self::assertFalse($this->verifyRaw("{\"data\":\"\xff\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\"}", "\u{FFFD}"));
    }

    public function testPayloadStartsWithByteOrderMark(): void
    {
        self::assertFalse($this->verifyRaw("\xEF\xBB\xBF" . '{"data":"{\"amount\":100}","domain":"five-gaming","nonce":"NONCE"}'));
    }

    public function testNotBeforeWithPlusSign(): void
    {
        self::assertFalse($this->verify(tamper: static function (array $headers): array {
            $headers['X-Sign-Intermediate-Not-Before'] = '+' . $headers['X-Sign-Intermediate-Not-Before'];
            return $headers;
        }));
    }

    public function testSignatureBase64WithSpaceInside(): void
    {
        self::assertFalse($this->verify(tamper: static function (array $headers): array {
            $headers['X-Sign-Signature'] = substr($headers['X-Sign-Signature'], 0, 4) . ' ' . substr($headers['X-Sign-Signature'], 4);
            return $headers;
        }));
    }

    public function testSignatureBase64WithoutPadding(): void
    {
        self::assertFalse($this->verify(tamper: static function (array $headers): array {
            $headers['X-Sign-Signature'] = rtrim($headers['X-Sign-Signature'], '=');
            return $headers;
        }));
    }

    private function verifyNested(int $depth): bool
    {
        $arrays = $depth - 1;

        return $this->verifyRaw('{"data":"{\"amount\":100}","domain":"five-gaming","nonce":"NONCE","x":'
            . str_repeat('[', $arrays) . str_repeat(']', $arrays) . '}');
    }

    public function testPayloadNested64LevelsDeep(): void
    {
        self::assertTrue($this->verifyNested(64));
    }

    public function testPayloadNested65LevelsDeep(): void
    {
        self::assertFalse($this->verifyNested(65));
    }

    public function testBracketsInsideStringsDoNotCountAsNesting(): void
    {
        self::assertTrue($this->verify(body: str_repeat('[', 100) . '\\"' . str_repeat('{', 100)));
    }
}
