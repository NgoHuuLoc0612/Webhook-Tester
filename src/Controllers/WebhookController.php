<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Services\WebhookService;
use App\Services\SecurityService;

class WebhookController
{
    private WebhookService $service;
    private SecurityService $security;

    public function __construct()
    {
        $this->service  = new WebhookService();
        $this->security = new SecurityService();
    }

    public function capture(string $token): void
    {
        $t0 = microtime(true);

        $endpoint = $this->service->getEndpointByToken($token);
        if (!$endpoint) {
            http_response_code(404);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Endpoint not found']);
            return;
        }

        // Collect request metadata
        $method      = $_SERVER['REQUEST_METHOD'];
        $fullUrl     = BASE_URL . $_SERVER['REQUEST_URI'];
        $path        = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $queryString = $_SERVER['QUERY_STRING'] ?? '';
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        $ip          = $this->resolveIp();
        $userAgent   = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Read body (hard-limited)
        $body = '';
        if (!in_array($method, ['GET', 'HEAD', 'OPTIONS'])) {
            $body = (string)file_get_contents('php://input', false, null, 0, MAX_BODY_SIZE);
        }

        $headers = $this->collectHeaders();

        // Security check BEFORE delay
        $sec = $this->security->evaluate($endpoint, [
            'ip'      => $ip,
            'method'  => $method,
            'headers' => $headers,
            'body'    => $body,
        ]);

        // Paused: store and reject
        if ($endpoint['is_paused']) {
            http_response_code(503);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Endpoint paused', 'token' => $token]);
            return;
        }

        // Expired
        if ($endpoint['is_expired'] || $endpoint['is_capped']) {
            http_response_code(410);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Endpoint no longer accepting requests']);
            return;
        }

        // Apply response delay (even for blocked — delay before rejection)
        if ($endpoint['response_delay_ms'] > 0) {
            usleep($endpoint['response_delay_ms'] * 1000);
        }

        $dur = round((microtime(true) - $t0) * 1000, 3);

        // Forward mode: proxy to another URL
        $responseStatus = $endpoint['response_status'];
        if ($sec['allowed'] && $endpoint['response_mode'] === 'forward' && !empty($endpoint['forward_url'])) {
            [$responseStatus] = $this->forwardRequest($endpoint['forward_url'], $method, $headers, $body);
        }

        // Store request (always — even blocked ones for audit)
        $this->service->captureRequest($endpoint['id'], [
            'method'          => $method,
            'url'             => $fullUrl,
            'path'            => $path,
            'query_string'    => $queryString,
            'headers'         => $headers,
            'body'            => $body,
            'content_type'    => $contentType,
            'ip'              => $ip,
            'user_agent'      => $userAgent,
            'duration_ms'     => $dur,
            'response_status' => $responseStatus,
        ]);

        // Respond
        if (!$sec['allowed']) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Forbidden', 'reason' => $sec['reason']]);
            return;
        }

        // Custom response headers
        foreach ($endpoint['response_headers'] as $name => $value) {
            if (is_string($name) && is_string($value)) header("$name: $value");
        }

        // Standard response headers
        header('X-Webhook-Request-Id: ' . uniqid('whr_', true));
        header('X-Webhook-Token: ' . substr($token, 0, 8) . '...');
        header('X-Processing-Time: ' . $dur . 'ms');

        http_response_code($responseStatus ?: 200);

        if (!empty($endpoint['response_body'])) {
            $body_out = $endpoint['response_body'];
            $t = trim($body_out);
            if (!isset($endpoint['response_headers']['Content-Type'])) {
                header('Content-Type: ' . (($t && ($t[0] === '{' || $t[0] === '[')) ? 'application/json' : 'text/plain'));
            }
            echo $body_out;
        } else {
            header('Content-Type: application/json');
            echo json_encode(['received' => true, 'timestamp' => gmdate('c'), 'method' => $method]);
        }
    }

    private function forwardRequest(string $url, string $method, array $headers, string $body): array
    {
        $ch = curl_init($url);
        $hdrs = array_map(fn($k, $v) => "$k: $v", array_keys($headers), array_values($headers));
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => $hdrs,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$code ?: 502];
    }

    private function collectHeaders(): array
    {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (!str_starts_with($key, 'HTTP_')) continue;
            if (in_array($key, ['HTTP_HOST','HTTP_CONNECTION'])) continue;
            $name = ucwords(strtolower(str_replace('_', '-', substr($key, 5))), '-');
            $headers[$name] = $value;
        }
        if (!empty($_SERVER['CONTENT_TYPE']))   $headers['Content-Type']   = $_SERVER['CONTENT_TYPE'];
        if (!empty($_SERVER['CONTENT_LENGTH'])) $headers['Content-Length'] = $_SERVER['CONTENT_LENGTH'];
        return $headers;
    }

    private function resolveIp(): string
    {
        foreach (['HTTP_CF_CONNECTING_IP','HTTP_X_REAL_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'] as $k) {
            if (!empty($_SERVER[$k])) {
                $ip = trim(explode(',', $_SERVER[$k])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
            }
        }
        return '0.0.0.0';
    }
}
