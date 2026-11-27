<?php

declare(strict_types=1);

namespace App\Config;

use App\Support\Base64;

final readonly class AppConfig
{
    public function __construct(
        public string $keyId,
        public string $operatorId,
        public string $privateKey,
        public string $rootPublicKey,
    ) {
        $errors = self::getErrors($keyId, $operatorId, $privateKey, $rootPublicKey);
        if ($errors !== []) {
            throw new InvalidConfigurationException($errors);
        }
    }

    public static function fromEnvironment(): self
    {
        return new self(
            (string) getenv('KEY_ID'),
            (string) getenv('OPERATOR_ID'),
            (string) getenv('PRIVATE_KEY'),
            (string) getenv('ROOT_PUBLIC_KEY'),
        );
    }

    public static function getErrors(string $keyId, string $operatorId, string $privateKey, string $rootPublicKey): array
    {
        return array_values(array_filter([
            self::checkNonBlank('KEY_ID', $keyId),
            self::checkNonBlank('OPERATOR_ID', $operatorId),
            self::checkKey('PRIVATE_KEY', $privateKey, SODIUM_CRYPTO_SIGN_SEEDBYTES),
            self::checkKey('ROOT_PUBLIC_KEY', $rootPublicKey, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES),
        ], static fn (?string $error): bool => $error !== null));
    }

    private static function checkNonBlank(string $name, string $value): ?string
    {
        return trim($value) === '' ? "{$name} is not set" : null;
    }

    private static function checkKey(string $name, string $value, int $length): ?string
    {
        if (trim($value) === '') {
            return "{$name} is not set";
        }

        $key = Base64::decodeCanonical($value);
        if ($key === null) {
            return "{$name} is not valid base64";
        }

        if (strlen($key) !== $length) {
            return "{$name} must be a {$length}-byte raw Ed25519 key, got " . strlen($key) . ' bytes';
        }

        return null;
    }
}
