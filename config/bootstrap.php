<?php
declare(strict_types=1);

spl_autoload_register(function (string $class): void {
    $prefix = 'App\\';
    $base   = ROOT_PATH . '/src/';
    if (strncmp($prefix, $class, strlen($prefix)) !== 0) return;
    $relative = substr($class, strlen($prefix));
    $file = $base . str_replace('\\', '/', $relative) . '.php';
    if (file_exists($file)) require $file;
});

set_error_handler(function ($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

set_exception_handler(function (Throwable $e) {
    $isApi = str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/api')
          || str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/webhook');
    if ($isApi) {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['error' => $e->getMessage(), 'file' => basename($e->getFile()), 'line' => $e->getLine()]);
    } else {
        http_response_code(500);
        echo '<pre style="font:12px monospace;padding:20px;color:red">' . htmlspecialchars($e->getMessage()) . "\n" . $e->getTraceAsString() . '</pre>';
    }
    exit;
});

define('DB_PATH',      ROOT_PATH . '/database/webhook_tester.sqlite');
define('STORAGE_PATH', ROOT_PATH . '/storage');
define('MAX_BODY_SIZE', 1024 * 1024 * 16);         // 16MB
define('MAX_REQUESTS_PER_ENDPOINT', 1000);
define('SSE_HEARTBEAT_INTERVAL', 12);
define('RATE_LIMIT_WINDOW', 60);
define('RATE_LIMIT_MAX', 500);
define('APP_VERSION', '3.0.0');

$proto = (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) ? $_SERVER['HTTP_X_FORWARDED_PROTO'] : (isset($_SERVER['HTTPS']) ? 'https' : 'http'));
define('BASE_URL', $proto . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost'));

foreach ([
    ROOT_PATH . '/storage/logs',
    ROOT_PATH . '/storage/requests',
    ROOT_PATH . '/database',
] as $dir) {
    if (!is_dir($dir)) mkdir($dir, 0755, true);
}

require_once ROOT_PATH . '/database/schema.php';
