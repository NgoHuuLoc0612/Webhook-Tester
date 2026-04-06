<?php
declare(strict_types=1);

namespace App\Services;

class SecurityService
{
    private DatabaseService $db;

    public function __construct()
    {
        $this->db = DatabaseService::getInstance();
    }

    /**
     * Full security pipeline. Returns ['allowed'=>bool, 'reason'=>string, 'threat_score'=>int]
     */
    public function evaluate(array $endpoint, array $request): array
    {
        $ip      = $request['ip'] ?? '';
        $method  = $request['method'] ?? 'GET';
        $headers = $request['headers'] ?? [];
        $body    = $request['body'] ?? '';
        $score   = 0;
        $reason  = '';

        // 1. Endpoint expired
        if ($endpoint['expires_at'] && strtotime($endpoint['expires_at']) < time()) {
            $this->logEvent($endpoint['id'], 'expired', $ip, ['expires_at' => $endpoint['expires_at']]);
            return ['allowed' => false, 'reason' => 'endpoint_expired', 'threat_score' => 0];
        }

        // 2. Max request cap
        if ($endpoint['max_requests'] > 0 && $endpoint['request_count'] >= $endpoint['max_requests']) {
            $this->logEvent($endpoint['id'], 'max_requests', $ip, []);
            return ['allowed' => false, 'reason' => 'max_requests_reached', 'threat_score' => 0];
        }

        // 3. Blocked IPs (CIDR + exact)
        // blocked_ips may already be decoded array (from formatEndpoint) or still a JSON string
        $blockedRaw = $endpoint['blocked_ips'] ?? [];
        $blocked = is_array($blockedRaw) ? $blockedRaw : (json_decode($blockedRaw, true) ?: []);
        foreach ($blocked as $cidr) {
            if ($this->ipMatches($ip, $cidr)) {
                $this->logEvent($endpoint['id'], 'blocked_ip', $ip, ['rule' => $cidr]);
                return ['allowed' => false, 'reason' => 'ip_blocked', 'threat_score' => 100];
            }
        }

        // 4. Allowed IPs whitelist
        $allowedRaw = $endpoint['allowed_ips'] ?? [];
        $allowed = is_array($allowedRaw) ? $allowedRaw : (json_decode($allowedRaw, true) ?: []);
        if (!empty($allowed)) {
            $pass = false;
            foreach ($allowed as $cidr) {
                if ($this->ipMatches($ip, $cidr)) { $pass = true; break; }
            }
            if (!$pass) {
                $this->logEvent($endpoint['id'], 'ip_not_whitelisted', $ip, []);
                return ['allowed' => false, 'reason' => 'ip_not_whitelisted', 'threat_score' => 50];
            }
        }

        // 5. Method filter
        $methodsRaw = $endpoint['allowed_methods'] ?? [];
        $allowedMethods = is_array($methodsRaw) ? $methodsRaw : (json_decode($methodsRaw, true) ?: []);
        if (!empty($allowedMethods) && !in_array(strtoupper($method), array_map('strtoupper', $allowedMethods))) {
            $this->logEvent($endpoint['id'], 'method_not_allowed', $ip, ['method' => $method]);
            return ['allowed' => false, 'reason' => 'method_not_allowed', 'threat_score' => 10];
        }

        // 6. Auth check
        if ($endpoint['require_auth']) {
            $authResult = $this->checkAuth($endpoint, $headers);
            if (!$authResult) {
                $this->logEvent($endpoint['id'], 'auth_failed', $ip, ['auth_type' => $endpoint['auth_type']]);
                return ['allowed' => false, 'reason' => 'authentication_failed', 'threat_score' => 60];
            }
        }

        // 7. Signature verification
        $sigValid = -1;
        if ($endpoint['require_signature'] && !empty($endpoint['secret_key'])) {
            $sigValid = $this->verifySignature($endpoint, $headers, $body) ? 1 : 0;
            if ($sigValid === 0) {
                $this->logEvent($endpoint['id'], 'bad_signature', $ip, ['header' => $endpoint['signature_header']]);
                return ['allowed' => false, 'reason' => 'signature_invalid', 'threat_score' => 90];
            }
        }

        // 8. Threat scoring (heuristic)
        $score += $this->calculateThreatScore($ip, $headers, $body, $method);

        return [
            'allowed'        => true,
            'reason'         => '',
            'threat_score'   => $score,
            'signature_valid' => $sigValid,
        ];
    }

    public function verifySignature(array $endpoint, array $headers, string $body): bool
    {
        $headerName = $endpoint['signature_header'] ?? 'X-Hub-Signature-256';
        $secret     = $endpoint['secret_key'] ?? '';
        $algo       = $endpoint['signature_algo'] ?? 'sha256';

        // Normalize header name to how we store it
        $sigValue = null;
        foreach ($headers as $k => $v) {
            if (strtolower($k) === strtolower($headerName)) { $sigValue = $v; break; }
        }
        if ($sigValue === null) return false;

        $expected = hash_hmac($algo, $body, $secret);
        // Support both raw hex and "algo=hex" format
        $incoming = preg_replace('/^[a-z0-9]+=/', '', $sigValue);
        return hash_equals($expected, $incoming);
    }

    private function checkAuth(array $endpoint, array $headers): bool
    {
        $type  = $endpoint['auth_type'] ?? 'bearer';
        $value = $endpoint['auth_value'] ?? '';

        switch ($type) {
            case 'bearer':
                $auth = $headers['Authorization'] ?? $headers['authorization'] ?? '';
                return hash_equals('Bearer ' . $value, $auth);
            case 'api-key':
                $key = $headers['X-Api-Key'] ?? $headers['x-api-key'] ?? $headers['Api-Key'] ?? '';
                return hash_equals($value, $key);
            case 'basic':
                $auth     = $headers['Authorization'] ?? '';
                $decoded  = base64_decode(str_replace('Basic ', '', $auth));
                return hash_equals($value, $decoded);
        }
        return true;
    }

    private function calculateThreatScore(string $ip, array $headers, string $body, string $method): int
    {
        $score = 0;

        // SQL injection patterns in body
        if (preg_match('/(\bunion\b.*\bselect\b|\bor\b\s+\d+=\d+|drop\s+table|xp_cmdshell)/i', $body)) $score += 40;

        // XSS patterns
        if (preg_match('/<script[\s>]|javascript:|on\w+\s*=/i', $body)) $score += 30;

        // Path traversal
        if (preg_match('/\.\.[\/\\\\]/', $body)) $score += 25;

        // Suspicious user agents
        $ua = $headers['User-Agent'] ?? '';
        if (preg_match('/sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|burpsuite/i', $ua)) $score += 50;

        // No user agent at all
        if (empty($ua)) $score += 5;

        // Unusual method
        if (in_array($method, ['TRACE', 'CONNECT', 'TRACK'])) $score += 20;

        // Very large payloads from unusual methods
        if (in_array($method, ['GET', 'HEAD']) && strlen($body) > 1024) $score += 10;

        return min($score, 100);
    }

    private function ipMatches(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) return $ip === $cidr;
        [$subnet, $mask] = explode('/', $cidr);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
        $ip_long  = ip2long($ip);
        $sub_long = ip2long($subnet);
        $mask_long = -1 << (32 - (int)$mask);
        return ($ip_long & $mask_long) === ($sub_long & $mask_long);
    }

    public function logEvent(string $endpointId, string $type, string $ip, array $details): void
    {
        $this->db->execute("
            INSERT INTO security_events (id, endpoint_id, event_type, ip, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ", [
            $this->uuid(), $endpointId, $type, $ip,
            json_encode($details), gmdate('Y-m-d\TH:i:s\Z'),
        ]);

        if (in_array($type, ['blocked_ip', 'bad_signature', 'auth_failed', 'method_not_allowed', 'ip_not_whitelisted', 'rate_limit'])) {
            $this->db->execute(
                "UPDATE endpoints SET blocked_count = blocked_count + 1 WHERE id = ?",
                [$endpointId]
            );
        }
    }

    public function getSecurityEvents(string $endpointId, int $limit = 50): array
    {
        return $this->db->query("
            SELECT * FROM security_events WHERE endpoint_id = ?
            ORDER BY created_at DESC LIMIT ?
        ", [$endpointId, $limit]);
    }

    public function getGlobalSecurityStats(): array
    {
        $byType = $this->db->query("
            SELECT event_type, COUNT(*) as count
            FROM security_events
            WHERE created_at >= datetime('now', '-24 hours')
            GROUP BY event_type ORDER BY count DESC
        ");

        $topAttackers = $this->db->query("
            SELECT ip, COUNT(*) as count
            FROM security_events
            WHERE created_at >= datetime('now', '-24 hours') AND ip != ''
            GROUP BY ip ORDER BY count DESC LIMIT 10
        ");

        $timeline = $this->db->query("
            SELECT strftime('%H', created_at) as hour, COUNT(*) as count
            FROM security_events
            WHERE created_at >= datetime('now', '-24 hours')
            GROUP BY hour ORDER BY hour
        ");

        $total24h  = $this->db->queryOne("SELECT COUNT(*) as c FROM security_events WHERE created_at >= datetime('now','-24 hours')")['c'] ?? 0;
        $total7d   = $this->db->queryOne("SELECT COUNT(*) as c FROM security_events WHERE created_at >= datetime('now','-7 days')")['c'] ?? 0;

        return compact('byType', 'topAttackers', 'timeline', 'total24h', 'total7d');
    }

    // API Key management
    public function createApiKey(string $name, array $permissions = ['read', 'write']): array
    {
        $raw    = 'wht_' . bin2hex(random_bytes(24));
        $prefix = substr($raw, 0, 12);
        $hash   = hash('sha256', $raw);
        $id     = $this->uuid();
        $now    = gmdate('Y-m-d\TH:i:s\Z');

        $this->db->execute("
            INSERT INTO api_keys (id, name, key_hash, key_prefix, permissions, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ", [$id, $name, $hash, $prefix, json_encode($permissions), $now]);

        return ['id' => $id, 'key' => $raw, 'prefix' => $prefix, 'name' => $name, 'created_at' => $now];
    }

    public function listApiKeys(): array
    {
        return $this->db->query("SELECT id, name, key_prefix, permissions, created_at, last_used_at, expires_at, is_active FROM api_keys ORDER BY created_at DESC");
    }

    public function deleteApiKey(string $id): bool
    {
        return $this->db->execute("DELETE FROM api_keys WHERE id = ?", [$id]) > 0;
    }

    public function validateApiKey(string $rawKey): ?array
    {
        $hash = hash('sha256', $rawKey);
        $key  = $this->db->queryOne("SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1", [$hash]);
        if (!$key) return null;
        if ($key['expires_at'] && strtotime($key['expires_at']) < time()) return null;
        $this->db->execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", [gmdate('Y-m-d\TH:i:s\Z'), $key['id']]);
        return $key;
    }

    private function uuid(): string
    {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff)|0x4000, mt_rand(0, 0x3fff)|0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }
}
