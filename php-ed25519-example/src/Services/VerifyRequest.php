<?php

declare(strict_types=1);

namespace App\Services;

final readonly class VerifyRequest
{
    public function __construct(
        public ?string $version,
        public ?string $domain,
        public ?string $nonce,
        public ?string $payload,
        public ?string $signature,
        public ?string $intermediatePublicKey,
        public ?string $intermediateSignature,
        public ?string $intermediateNotBefore,
        public ?string $intermediateNotAfter,
    ) {
    }
}
