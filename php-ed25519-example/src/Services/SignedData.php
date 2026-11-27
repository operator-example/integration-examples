<?php

declare(strict_types=1);

namespace App\Services;

final readonly class SignedData
{
    public function __construct(
        public string $keyId,
        public string $operatorId,
        public string $payload,
        public string $signature,
    ) {
    }
}
