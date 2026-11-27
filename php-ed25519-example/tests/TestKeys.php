<?php

declare(strict_types=1);

namespace App\Tests;

use App\Config\AppConfig;
use App\Services\AuthService;

final class TestKeys
{
    public const KEY_ID = 'test-key';
    public const OPERATOR_ID = 'test-operator';

    public static function operatorKeypair(): string
    {
        return sodium_crypto_sign_seed_keypair(str_repeat("\x01", 32));
    }

    public static function rootKeypair(): string
    {
        return sodium_crypto_sign_seed_keypair(str_repeat("\x02", 32));
    }

    public static function config(): AppConfig
    {
        return new AppConfig(
            self::KEY_ID,
            self::OPERATOR_ID,
            base64_encode(str_repeat("\x01", 32)),
            base64_encode(sodium_crypto_sign_publickey(self::rootKeypair())),
        );
    }

    public static function newAuthService(): AuthService
    {
        return new AuthService(self::config());
    }

    public static function randomKeypair(): string
    {
        return sodium_crypto_sign_keypair();
    }

    public static function sign(string $keypair, string $data): string
    {
        return sodium_crypto_sign_detached($data, sodium_crypto_sign_secretkey($keypair));
    }

    public static function verify(string $publicKey, string $data, string $signature): bool
    {
        return sodium_crypto_sign_verify_detached($signature, $data, $publicKey);
    }
}
