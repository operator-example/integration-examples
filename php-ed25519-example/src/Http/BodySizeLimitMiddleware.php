<?php

declare(strict_types=1);

namespace App\Http;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class BodySizeLimitMiddleware implements MiddlewareInterface
{
    public const int MAX_BODY_SIZE = 8 << 20;

    public function __construct(
        private ResponseFactoryInterface $responseFactory,
        private int $maxBodySize = self::MAX_BODY_SIZE,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $body = $request->getBody();
        $size = $body->getSize() ?? strlen((string) $body);
        if ($size <= $this->maxBodySize) {
            return $handler->handle($request);
        }

        $response = $this->responseFactory->createResponse(413)->withHeader('Content-Type', 'application/json');
        $response->getBody()->write(json_encode(['error' => 'body is too large'], JSON_THROW_ON_ERROR));

        return $response;
    }
}
