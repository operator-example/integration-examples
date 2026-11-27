<?php

declare(strict_types=1);

namespace App\Tests;

use App\Http\JsonErrorHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Slim\Exception\HttpMethodNotAllowedException;
use Slim\Exception\HttpNotFoundException;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use Throwable;

final class JsonErrorHandlerTest extends TestCase
{
    public function testNotFound(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/nope');
        $response = self::handle(new HttpNotFoundException($request));

        self::assertSame(404, $response->getStatusCode());
        self::assertSame('{"error":"not found"}', (string) $response->getBody());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    public function testMethodNotAllowedKeepsAllowHeader(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/Auth/sign');
        $exception = (new HttpMethodNotAllowedException($request))->setAllowedMethods(['POST']);
        $response = self::handle($exception);

        self::assertSame(405, $response->getStatusCode());
        self::assertSame('{"error":"method not allowed"}', (string) $response->getBody());
        self::assertSame('POST', $response->getHeaderLine('Allow'));
    }

    public function testUnexpectedErrorHidesDetails(): void
    {
        $response = self::handle(new RuntimeException('secret internals'), logErrors: false);

        self::assertSame(500, $response->getStatusCode());
        self::assertSame('{"error":"internal server error"}', (string) $response->getBody());
    }

    private static function handle(Throwable $exception, bool $logErrors = true): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/');

        return (new JsonErrorHandler(new ResponseFactory()))($request, $exception, false, $logErrors, false);
    }
}
