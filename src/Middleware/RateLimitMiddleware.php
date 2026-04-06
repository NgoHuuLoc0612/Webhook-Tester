<?php
declare(strict_types=1);

namespace App\Middleware;

use App\Services\DatabaseService;
use App\Services\SecurityService;

class RateLimitMiddleware
{
    public static function handle(string $token): void
    {
        $db     = DatabaseService::getInstance();
        $window = (int)(time() / RATE_LIMIT_WINDOW);

        $db->execute("
            INSERT INTO rate_limits (token, window_start, count)
            VALUES (:token, :window, 1)
            ON CONFLICT(token, window_start) DO UPDATE SET count = count + 1
        ", [':token' => $token, ':window' => $window]);

        $row   = $db->queryOne("SELECT count FROM rate_limits WHERE token=? AND window_start=?", [$token, $window]);
        $count = (int)($row['count'] ?? 0);

        // Clean stale windows
        $db->execute("DELETE FROM rate_limits WHERE window_start < ?", [$window - 10]);

        header('X-RateLimit-Limit: '     . RATE_LIMIT_MAX);
        header('X-RateLimit-Remaining: ' . max(0, RATE_LIMIT_MAX - $count));
        header('X-RateLimit-Reset: '     . (($window + 1) * RATE_LIMIT_WINDOW));

        if ($count > RATE_LIMIT_MAX) {
            // Log security event
            $ep = $db->queryOne("SELECT id FROM endpoints WHERE token=?", [$token]);
            if ($ep) {
                $sec = new SecurityService();
                $sec->logEvent($ep['id'], 'rate_limit', $_SERVER['REMOTE_ADDR'] ?? '', [
                    'count'  => $count,
                    'window' => $window,
                    'limit'  => RATE_LIMIT_MAX,
                ]);
            }

            http_response_code(429);
            header('Content-Type: application/json');
            header('Retry-After: ' . RATE_LIMIT_WINDOW);
            echo json_encode([
                'error'       => 'Rate limit exceeded',
                'limit'       => RATE_LIMIT_MAX,
                'retry_after' => RATE_LIMIT_WINDOW,
            ]);
            exit;
        }
    }
}
