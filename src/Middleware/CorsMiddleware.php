<?php
declare(strict_types=1);

namespace App\Middleware;

class CorsMiddleware
{
    public static function handle(): void
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '*';

        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Accept, X-Api-Key, X-Token, X-Hub-Signature, X-Hub-Signature-256, X-Signature');
        header('Access-Control-Expose-Headers: X-Request-Id, X-Duration, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-App-Version');
        header('Access-Control-Max-Age: 86400');
        header('Vary: Origin');

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(204);
            exit;
        }
    }
}
