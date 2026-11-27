<?php

declare(strict_types=1);

namespace App\Http;

use App\Services\VerifyRequest;
use Psr\Http\Message\ServerRequestInterface;

final class VerifyRequestFactory
{
    public static function fromRequest(ServerRequestInterface $request): VerifyRequest
    {
        return new VerifyRequest(
            version: self::singleHeader($request, 'X-Sign-Version'),
            domain: self::singleHeader($request, 'X-Sign-Domain'),
            nonce: self::singleHeader($request, 'X-Sign-Nonce'),
            payload: self::singleHeader($request, 'X-Sign-Payload'),
            signature: self::singleHeader($request, 'X-Sign-Signature'),
            intermediatePublicKey: self::singleHeader($request, 'X-Sign-Intermediate-Public-Key'),
            intermediateSignature: self::singleHeader($request, 'X-Sign-Intermediate-Signature'),
            intermediateNotBefore: self::singleHeader($request, 'X-Sign-Intermediate-Not-Before'),
            intermediateNotAfter: self::singleHeader($request, 'X-Sign-Intermediate-Not-After'),
        );
    }

    private static function singleHeader(ServerRequestInterface $request, string $name): ?string
    {
        $values = $request->getHeader($name);

        return count($values) === 1 ? $values[0] : null;
    }
}
