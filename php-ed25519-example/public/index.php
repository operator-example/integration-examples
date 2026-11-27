<?php

declare(strict_types=1);

use App\Config\AppConfig;
use App\Config\InvalidConfigurationException;
use App\Controllers\AuthController;
use App\Http\BodySizeLimitMiddleware;
use App\Http\JsonErrorHandler;
use App\Services\AuthService;
use Slim\Factory\AppFactory;
use Slim\Routing\RouteCollectorProxy;

require __DIR__ . '/../vendor/autoload.php';

try {
    $authService = new AuthService(AppConfig::fromEnvironment());
} catch (InvalidConfigurationException $exception) {
    error_log($exception->getMessage());
    http_response_code(500);
    header('Content-Type: application/json');
    echo '{"error":"internal server error"}';
    return;
}

$app = AppFactory::create();
$app->addRoutingMiddleware();
$app->addErrorMiddleware(displayErrorDetails: false, logErrors: true, logErrorDetails: false)
    ->setDefaultErrorHandler(new JsonErrorHandler($app->getResponseFactory()));

$authController = new AuthController($authService);
$app->group('/Auth', function (RouteCollectorProxy $group) use ($authController): void {
    $group->post('/sign', [$authController, 'sign']);
    $group->post('/verify', [$authController, 'verify']);
})->add(new BodySizeLimitMiddleware($app->getResponseFactory()));

$app->run();
