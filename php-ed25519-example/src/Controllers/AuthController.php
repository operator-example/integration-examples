<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Http\VerifyRequestFactory;
use App\Services\AuthService;
use App\Services\InvalidBodyException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class AuthController
{
    public function __construct(private AuthService $authService)
    {
    }

    public function sign(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $signed = $this->authService->sign((string) $request->getBody());
        } catch (InvalidBodyException $exception) {
            return self::json($response, ['error' => $exception->getMessage()], 400);
        }

        return self::json($response, [
            'key_id' => $signed->keyId,
            'operator_id' => $signed->operatorId,
            'payload' => $signed->payload,
            'signature' => $signed->signature,
        ], 200);
    }

    public function verify(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $verified = $this->authService->verify(VerifyRequestFactory::fromRequest($request), (string) $request->getBody());

        return self::json($response, ['verified' => $verified], $verified ? 200 : 401);
    }

    private static function json(ResponseInterface $response, array $data, int $status): ResponseInterface
    {
        $response->getBody()->write(json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
