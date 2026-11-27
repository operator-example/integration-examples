<?php

declare(strict_types=1);

namespace App\Tests;

use App\Controllers\AuthController;
use App\Http\BodySizeLimitMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Factory\StreamFactory;

final class AuthControllerTest extends TestCase
{
    private AuthController $controller;

    protected function setUp(): void
    {
        $this->controller = new AuthController(TestKeys::newAuthService());
    }

    public function testSignReturnsBadRequestForInvalidUtf8(): void
    {
        $response = $this->call('sign', "\xff");

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('{"error":"body is not valid UTF-8"}', (string) $response->getBody());
    }

    public function testSignAcceptsBodyAtTheLimit(): void
    {
        $response = $this->call('sign', str_repeat('a', BodySizeLimitMiddleware::MAX_BODY_SIZE));

        self::assertSame(200, $response->getStatusCode());
    }

    public function testSignReturnsFieldsInOrder(): void
    {
        $response = $this->call('sign', '{}');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(
            ['key_id', 'operator_id', 'payload', 'signature'],
            array_keys(json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR)),
        );
    }

    public function testVerifyReturnsUnauthorizedWithoutHeaders(): void
    {
        $response = $this->call('verify', '');

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('{"verified":false}', (string) $response->getBody());
    }

    private function call(string $action, string $body): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', "/Auth/{$action}")
            ->withBody((new StreamFactory())->createStream($body));

        return $this->controller->{$action}($request, (new ResponseFactory())->createResponse());
    }
}
