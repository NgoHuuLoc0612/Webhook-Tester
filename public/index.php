<?php
declare(strict_types=1);

define('ROOT_PATH', dirname(__DIR__));
define('APP_START', microtime(true));

require_once ROOT_PATH . '/config/bootstrap.php';

use App\Controllers\DashboardController;
use App\Controllers\WebhookController;
use App\Controllers\ApiController;
use App\Middleware\CorsMiddleware;
use App\Middleware\RateLimitMiddleware;

CorsMiddleware::handle();

$method = $_SERVER['REQUEST_METHOD'];
$uri    = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path   = rtrim($uri, '/') ?: '/';

// Webhook capture — any HTTP method, strict token format
if (preg_match('#^/webhook/([a-zA-Z0-9_-]{8,64})$#', $path, $m)) {
    RateLimitMiddleware::handle($m[1]);
    (new WebhookController())->capture($m[1]);
    exit;
}

// Route table [method => [pattern => [controller, action]]]
$routes = [
    'GET' => [
        '/'                                    => [DashboardController::class, 'index'],
        '/api/endpoints'                       => [ApiController::class, 'listEndpoints'],
        '/api/endpoints/stats'                 => [ApiController::class, 'globalStats'],
        '/api/endpoints/{id}/stats'            => [ApiController::class, 'endpointStats'],
        '/api/endpoints/{id}/rules'            => [ApiController::class, 'listRules'],
        '/api/endpoints/{id}/security'         => [ApiController::class, 'securityEvents'],
        '/api/requests/{id}'                   => [ApiController::class, 'getRequest'],
        '/api/requests/{id}/replay/history'    => [ApiController::class, 'getReplayHistory'],
        '/api/export/{id}'                     => [ApiController::class, 'export'],
        '/api/stream'                          => [ApiController::class, 'stream'],
        '/api/security/stats'                  => [ApiController::class, 'globalSecurityStats'],
        '/api/keys'                            => [ApiController::class, 'listApiKeys'],
    ],
    'POST' => [
        '/api/endpoints'                       => [ApiController::class, 'createEndpoint'],
        '/api/endpoints/{id}/clear'            => [ApiController::class, 'clearEndpoint'],
        '/api/endpoints/{id}/pause'            => [ApiController::class, 'togglePause'],
        '/api/endpoints/{id}/regenerate'       => [ApiController::class, 'regenerateToken'],
        '/api/endpoints/{id}/verify-signature' => [ApiController::class, 'verifySignature'],
        '/api/endpoints/{id}/rules'            => [ApiController::class, 'createRule'],
        '/api/requests/{id}/note'              => [ApiController::class, 'addNote'],
        '/api/requests/{id}/tags'              => [ApiController::class, 'updateTags'],
        '/api/requests/{id}/star'              => [ApiController::class, 'starRequest'],
        '/api/requests/{id}/replay'            => [ApiController::class, 'replayRequest'],
        '/api/keys'                            => [ApiController::class, 'createApiKey'],
    ],
    'PUT' => [
        '/api/endpoints/{id}'                  => [ApiController::class, 'updateEndpoint'],
    ],
    'DELETE' => [
        '/api/endpoints/{id}'                  => [ApiController::class, 'deleteEndpoint'],
        '/api/requests/{id}'                   => [ApiController::class, 'deleteRequest'],
        '/api/rules/{id}'                      => [ApiController::class, 'deleteRule'],
        '/api/keys/{id}'                       => [ApiController::class, 'deleteApiKey'],
    ],
];

$matched = false;
foreach ($routes[$method] ?? [] as $pattern => $handler) {
    $regex = '#^' . preg_replace('/\{[^}]+\}/', '([a-zA-Z0-9_-]+)', $pattern) . '$#';
    if (preg_match($regex, $path, $params)) {
        array_shift($params);
        $matched = true;
        [$class, $action] = $handler;
        call_user_func_array([new $class(), $action], $params);
        break;
    }
}

if (!$matched) {
    http_response_code(404);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Route not found', 'path' => $path, 'method' => $method]);
}
