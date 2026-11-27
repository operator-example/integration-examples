<?php

declare(strict_types=1);

namespace App\Tests;

use App\Config\AppConfig;
use App\Config\InvalidConfigurationException;
use PHPUnit\Framework\TestCase;

final class AppConfigTest extends TestCase
{
    private static function errors(
        string $keyId = 'key',
        string $operatorId = 'operator',
        ?string $privateKey = null,
        ?string $rootPublicKey = null,
    ): array {
        $validKey = base64_encode(str_repeat("\x00", 32));

        return AppConfig::getErrors($keyId, $operatorId, $privateKey ?? $validKey, $rootPublicKey ?? $validKey);
    }

    public function testValidConfigHasNoErrors(): void
    {
        self::assertSame([], self::errors());
    }

    public function testReportsEveryMissingSettingAtOnce(): void
    {
        self::assertSame([
            'KEY_ID is not set',
            'OPERATOR_ID is not set',
            'PRIVATE_KEY is not set',
            'ROOT_PUBLIC_KEY is not set',
        ], self::errors(keyId: '', operatorId: ' ', privateKey: '', rootPublicKey: ''));
    }

    public function testRejectsInvalidBase64(): void
    {
        self::assertSame(['PRIVATE_KEY is not valid base64'], self::errors(privateKey: 'not base64!!'));
    }

    public function testRejectsBase64WithoutPadding(): void
    {
        self::assertSame(['PRIVATE_KEY is not valid base64'], self::errors(privateKey: rtrim(base64_encode(str_repeat("\x00", 32)), '=')));
    }

    public function testRejectsWrongKeyLength(): void
    {
        self::assertSame(
            ['ROOT_PUBLIC_KEY must be a 32-byte raw Ed25519 key, got 31 bytes'],
            self::errors(rootPublicKey: base64_encode(str_repeat("\x00", 31))),
        );
    }

    public function testRejectsPkcs8InsteadOfRawKey(): void
    {
        self::assertSame(
            ['PRIVATE_KEY must be a 32-byte raw Ed25519 key, got 48 bytes'],
            self::errors(privateKey: base64_encode(str_repeat("\x00", 48))),
        );
    }

    public function testErrorMessageNeverContainsTheSecret(): void
    {
        $secret = base64_encode(implode('', array_map('chr', range(1, 10))));

        foreach (self::errors(privateKey: $secret) as $error) {
            self::assertStringNotContainsString($secret, $error);
        }
    }

    public function testInvalidConfigCannotBeConstructed(): void
    {
        $validKey = base64_encode(str_repeat("\x00", 32));

        try {
            new AppConfig('', 'operator', $validKey, base64_encode(str_repeat("\x00", 48)));
            self::fail('AppConfig should refuse an invalid configuration');
        } catch (InvalidConfigurationException $exception) {
            self::assertSame(
                ['KEY_ID is not set', 'ROOT_PUBLIC_KEY must be a 32-byte raw Ed25519 key, got 48 bytes'],
                $exception->errors,
            );
            self::assertStringContainsString('KEY_ID is not set', $exception->getMessage());
        }
    }

    public function testFromEnvironmentRefusesMissingSettings(): void
    {
        $names = ['KEY_ID', 'OPERATOR_ID', 'PRIVATE_KEY', 'ROOT_PUBLIC_KEY'];
        $previous = array_combine($names, array_map(getenv(...), $names));
        array_walk($names, static fn (string $name): bool => putenv($name));

        try {
            AppConfig::fromEnvironment();
            self::fail('AppConfig::fromEnvironment should refuse a missing configuration');
        } catch (InvalidConfigurationException $exception) {
            self::assertSame(array_map(static fn (string $name): string => "{$name} is not set", $names), $exception->errors);
        } finally {
            foreach ($previous as $name => $value) {
                putenv($value === false ? $name : "{$name}={$value}");
            }
        }
    }
}
