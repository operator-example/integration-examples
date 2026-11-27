<?php

declare(strict_types=1);

namespace App\Tests;

use App\Http\BodySizeLimitMiddleware;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Factory\StreamFactory;

final class BodySizeLimitMiddlewareTest extends TestCase
{
    #[TestWith(['sign'])]
    #[TestWith(['verify'])]
    public function testReturnsContentTooLargeOverTheLimit(string $action): void
    {
        $response = self::process($action, (new StreamFactory())->createStream(str_repeat('a', BodySizeLimitMiddleware::MAX_BODY_SIZE + 1)));

        self::assertSame(413, $response->getStatusCode());
        self::assertSame('{"error":"body is too large"}', (string) $response->getBody());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    public function testPassesBodyAtTheLimit(): void
    {
        $response = self::process('sign', (new StreamFactory())->createStream(str_repeat('a', BodySizeLimitMiddleware::MAX_BODY_SIZE)));

        self::assertSame(204, $response->getStatusCode());
    }

    #[TestWith([BodySizeLimitMiddleware::MAX_BODY_SIZE, 204])]
    #[TestWith([BodySizeLimitMiddleware::MAX_BODY_SIZE + 1, 413])]
    public function testFallsBackToContentLengthWhenSizeIsUnknown(int $length, int $expectedStatus): void
    {
        $stream = self::createStub(StreamInterface::class);
        $stream->method('getSize')->willReturn(null);
        $stream->method('__toString')->willReturn(str_repeat('a', $length));

        self::assertSame($expectedStatus, self::process('verify', $stream)->getStatusCode());
    }

    private static function process(string $action, StreamInterface $body): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', "/Auth/{$action}")->withBody($body);
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new ResponseFactory())->createResponse(204);
            }
        };

        return (new BodySizeLimitMiddleware(new ResponseFactory()))->process($request, $handler);
    }
}
