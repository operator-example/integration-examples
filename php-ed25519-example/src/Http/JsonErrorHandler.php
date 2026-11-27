<?php

declare(strict_types=1);

namespace App\Http;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpMethodNotAllowedException;
use Slim\Exception\HttpNotFoundException;
use Slim\Interfaces\ErrorHandlerInterface;
use Throwable;

final readonly class JsonErrorHandler implements ErrorHandlerInterface
{
    public function __construct(private ResponseFactoryInterface $responseFactory)
    {
    }

    public function __invoke(
        ServerRequestInterface $request,
        Throwable $exception,
        bool $displayErrorDetails,
        bool $logErrors,
        bool $logErrorDetails,
    ): ResponseInterface {
        [$status, $message] = match (true) {
            $exception instanceof HttpNotFoundException => [404, 'not found'],
            $exception instanceof HttpMethodNotAllowedException => [405, 'method not allowed'],
            default => [500, 'internal server error'],
        };

        if ($status === 500 && $logErrors) {
            error_log((string) $exception);
        }

        $response = $this->responseFactory->createResponse($status)->withHeader('Content-Type', 'application/json');
        if ($exception instanceof HttpMethodNotAllowedException) {
            $response = $response->withHeader('Allow', implode(', ', $exception->getAllowedMethods()));
        }

        $response->getBody()->write(json_encode(['error' => $message], JSON_THROW_ON_ERROR));

        return $response;
    }
}
