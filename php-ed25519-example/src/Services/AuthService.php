<?php

declare(strict_types=1);

namespace App\Services;

use App\Config\AppConfig;
use App\Config\InvalidConfigurationException;
use App\Support\Base64;
use JsonException;
use RuntimeException;
use stdClass;
use Symfony\Component\Uid\UuidV7;
use Throwable;

final readonly class AuthService
{
    private const EXPECTED_DOMAIN = 'five-gaming';
    private const NONCE_MAX_AGE_SECONDS = 5 * 60;
    private const CLOCK_SKEW_SECONDS = 60;
    private const MAX_PAYLOAD_DEPTH = 64;
    private const SHORT_ESCAPES = ['\\' => '\\\\', "\x08" => '\b', "\t" => '\t', "\n" => '\n', "\x0c" => '\f', "\r" => '\r'];

    private string $keyId;
    private string $operatorId;
    private string $secretKey;
    private string $rootPublicKey;

    public function __construct(AppConfig $config)
    {
        if (!function_exists('apcu_add') || !apcu_enabled()) {
            throw new InvalidConfigurationException(['APCu is required for nonce replay protection (CLI needs apc.enable_cli=1)']);
        }

        $this->keyId = $config->keyId;
        $this->operatorId = $config->operatorId;
        $this->secretKey = sodium_crypto_sign_secretkey(
            sodium_crypto_sign_seed_keypair((string) Base64::decodeCanonical($config->privateKey))
        );
        $this->rootPublicKey = (string) Base64::decodeCanonical($config->rootPublicKey);
    }

    public function sign(string $body): SignedData
    {
        if (!mb_check_encoding($body, 'UTF-8')) {
            throw new InvalidBodyException('body is not valid UTF-8');
        }

        $nonce = (string) new UuidV7();
        $payload = self::buildPayload($body, $nonce);
        $signature = sodium_crypto_sign_detached($payload, $this->secretKey);

        return new SignedData($this->keyId, $this->operatorId, $payload, base64_encode($signature));
    }

    private static function buildPayload(string $data, string $nonce): string
    {
        return '{"data":' . self::toJsonString($data)
            . ',"nonce":' . self::toJsonString($nonce) . '}';
    }

    private static function toJsonString(string $value): string
    {
        $escaped = preg_replace_callback(
            '/[\x00-\x1f"&\'+<>\\\\`\x{7f}-\x{10ffff}]/u',
            static function (array $match): string {
                $character = $match[0];
                if (isset(self::SHORT_ESCAPES[$character])) {
                    return self::SHORT_ESCAPES[$character];
                }

                $codePoint = mb_ord($character, 'UTF-8');
                if ($codePoint <= 0xFFFF) {
                    return sprintf('\u%04X', $codePoint);
                }

                $codePoint -= 0x10000;
                return sprintf('\u%04X\u%04X', 0xD800 | ($codePoint >> 10), 0xDC00 | ($codePoint & 0x3FF));
            },
            $value,
        );
        if ($escaped === null) {
            throw new RuntimeException('Failed to escape payload: ' . preg_last_error_msg());
        }

        return '"' . $escaped . '"';
    }

    public function verify(VerifyRequest $request, string $body): bool
    {
        if ($request->version !== '2') {
            return false;
        }

        $intermediatePublicKey = self::decodeFromBase64($request->intermediatePublicKey, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
        if ($intermediatePublicKey === null) {
            return false;
        }

        $intermediateSignature = self::decodeFromBase64($request->intermediateSignature, SODIUM_CRYPTO_SIGN_BYTES);
        if ($intermediateSignature === null) {
            return false;
        }

        $signature = self::decodeFromBase64($request->signature, SODIUM_CRYPTO_SIGN_BYTES);
        if ($signature === null) {
            return false;
        }

        $notBefore = self::parseInteger($request->intermediateNotBefore);
        if ($notBefore === null) {
            return false;
        }

        $notAfter = self::parseInteger($request->intermediateNotAfter);
        if ($notAfter === null) {
            return false;
        }

        $now = time();
        $certificate = '{"not_after":' . $notAfter . ',"not_before":' . $notBefore
            . ',"public_key":"' . base64_encode($intermediatePublicKey) . '"}';
        if (!self::ed25519Verify($intermediateSignature, $this->rootPublicKey, $certificate)) {
            return false;
        }

        if ($now < $notBefore || $now > $notAfter) {
            return false;
        }

        $payload = $request->payload;
        if ($payload === null || !self::ed25519Verify($signature, $intermediatePublicKey, $payload)) {
            return false;
        }

        try {
            $document = json_decode($payload, false, self::MAX_PAYLOAD_DEPTH + 1, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }

        if (!$document instanceof stdClass) {
            return false;
        }

        if (($document->domain ?? null) !== self::EXPECTED_DOMAIN) {
            return false;
        }

        $nonce = $document->nonce ?? null;
        if (!is_string($nonce) || $nonce !== $request->nonce) {
            return false;
        }

        if (($document->data ?? null) !== $body) {
            return false;
        }

        if ($request->domain !== self::EXPECTED_DOMAIN) {
            return false;
        }

        if (!self::isNonceFresh($nonce, $now)) {
            return false;
        }

        return self::tryMarkNonceUsed($nonce);
    }

    private static function isNonceFresh(string $nonce, int $now): bool
    {
        if (strlen($nonce) < 13) {
            return false;
        }

        $hexTimestamp = substr($nonce, 0, 8) . substr($nonce, 9, 4);
        if (!ctype_xdigit($hexTimestamp)) {
            return false;
        }

        $signedAt = intdiv((int) hexdec($hexTimestamp), 1000);

        if ($now - $signedAt > self::NONCE_MAX_AGE_SECONDS) {
            return false;
        }

        if ($signedAt - $now > self::CLOCK_SKEW_SECONDS) {
            return false;
        }

        return true;
    }

    private static function tryMarkNonceUsed(string $nonce): bool
    {
        return apcu_add('used-nonce:' . $nonce, true, self::NONCE_MAX_AGE_SECONDS + self::CLOCK_SKEW_SECONDS);
    }

    private static function ed25519Verify(string $signature, string $publicKey, string $data): bool
    {
        try {
            return sodium_crypto_sign_verify_detached($signature, $data, $publicKey);
        } catch (Throwable) {
            return false;
        }
    }

    private static function decodeFromBase64(?string $value, int $size): ?string
    {
        if ($value === null) {
            return null;
        }

        $bytes = Base64::decodeCanonical($value);

        return $bytes !== null && strlen($bytes) === $size ? $bytes : null;
    }

    private static function parseInteger(?string $value): ?int
    {
        if ($value === null) {
            return null;
        }

        if (preg_match('/^-?\d{1,18}$/D', $value) !== 1) {
            return null;
        }

        return (int) $value;
    }
}
