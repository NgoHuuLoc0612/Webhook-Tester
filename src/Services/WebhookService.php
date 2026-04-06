<?php
declare(strict_types=1);

namespace App\Services;

class WebhookService
{
    private DatabaseService $db;
    private SecurityService $security;

    public function __construct()
    {
        $this->db       = DatabaseService::getInstance();
        $this->security = new SecurityService();
    }

    // ─── Endpoints ────────────────────────────────────────────────────────────

    public function createEndpoint(array $data): array
    {
        $id    = $this->uuid();
        $token = bin2hex(random_bytes(16));
        $now   = $this->now();

        $this->db->execute("
            INSERT INTO endpoints (
                id, token, name, description, color,
                response_status, response_body, response_headers, response_delay_ms,
                response_mode, forward_url,
                secret_key, allowed_ips, blocked_ips,
                require_signature, signature_header, signature_algo,
                allowed_methods, require_auth, auth_type, auth_value,
                filter_rules, expires_at, max_requests,
                created_at, updated_at
            ) VALUES (
                :id, :token, :name, :desc, :color,
                :status, :body, :headers, :delay,
                :mode, :fwd,
                :secret, :aips, :bips,
                :sig, :sighdr, :sigalgo,
                :methods, :auth, :authtype, :authval,
                :rules, :expires, :maxreq,
                :now, :now
            )
        ", [
            ':id'      => $id,
            ':token'   => $token,
            ':name'    => substr($data['name'] ?? 'Endpoint ' . strtoupper(substr($token,0,6)), 0, 120),
            ':desc'    => substr($data['description'] ?? '', 0, 500),
            ':color'   => $this->sanitizeColor($data['color'] ?? '#6366f1'),
            ':status'  => (int)($data['response_status'] ?? 200),
            ':body'    => $data['response_body'] ?? '',
            ':headers' => json_encode(is_array($data['response_headers'] ?? null) ? $data['response_headers'] : []),
            ':delay'   => max(0, min(30000, (int)($data['response_delay_ms'] ?? 0))),
            ':mode'    => in_array($data['response_mode'] ?? 'static', ['static','forward']) ? $data['response_mode'] : 'static',
            ':fwd'     => filter_var($data['forward_url'] ?? '', FILTER_VALIDATE_URL) ? $data['forward_url'] : '',
            ':secret'  => $data['secret_key'] ?? '',
            ':aips'    => json_encode(is_array($data['allowed_ips'] ?? null) ? $data['allowed_ips'] : []),
            ':bips'    => json_encode(is_array($data['blocked_ips'] ?? null) ? $data['blocked_ips'] : []),
            ':sig'     => (int)($data['require_signature'] ?? 0),
            ':sighdr'  => $data['signature_header'] ?? 'X-Hub-Signature-256',
            ':sigalgo' => in_array($data['signature_algo'] ?? 'sha256', ['sha256','sha1','sha512']) ? $data['signature_algo'] : 'sha256',
            ':methods' => json_encode(is_array($data['allowed_methods'] ?? null) ? $data['allowed_methods'] : []),
            ':auth'    => (int)($data['require_auth'] ?? 0),
            ':authtype'=> in_array($data['auth_type'] ?? 'bearer', ['bearer','api-key','basic']) ? $data['auth_type'] : 'bearer',
            ':authval' => $data['auth_value'] ?? '',
            ':rules'   => json_encode(is_array($data['filter_rules'] ?? null) ? $data['filter_rules'] : []),
            ':expires' => !empty($data['expires_at']) ? $data['expires_at'] : null,
            ':maxreq'  => max(0, (int)($data['max_requests'] ?? 0)),
            ':now'     => $now,
        ]);

        return $this->getEndpoint($id);
    }

    public function getEndpoint(string $id): ?array
    {
        $row = $this->db->queryOne("SELECT * FROM endpoints WHERE id = ?", [$id]);
        return $row ? $this->formatEndpoint($row) : null;
    }

    public function getEndpointByToken(string $token): ?array
    {
        $row = $this->db->queryOne("SELECT * FROM endpoints WHERE token = ?", [$token]);
        return $row ? $this->formatEndpoint($row) : null;
    }

    public function listEndpoints(): array
    {
        $rows = $this->db->query("SELECT * FROM endpoints ORDER BY created_at DESC");
        return array_map([$this, 'formatEndpoint'], $rows);
    }

    public function updateEndpoint(string $id, array $data): ?array
    {
        $fields = [];
        $params = [];
        $map = [
            'name'              => 'string',
            'description'       => 'string',
            'color'             => 'color',
            'response_status'   => 'int',
            'response_body'     => 'string',
            'response_headers'  => 'json',
            'response_delay_ms' => 'int',
            'response_mode'     => 'string',
            'forward_url'       => 'string',
            'secret_key'        => 'string',
            'allowed_ips'       => 'json',
            'blocked_ips'       => 'json',
            'require_signature' => 'int',
            'signature_header'  => 'string',
            'signature_algo'    => 'string',
            'allowed_methods'   => 'json',
            'require_auth'      => 'int',
            'auth_type'         => 'string',
            'auth_value'        => 'string',
            'filter_rules'      => 'json',
            'expires_at'        => 'string',
            'max_requests'      => 'int',
        ];
        foreach ($map as $field => $type) {
            if (!array_key_exists($field, $data)) continue;
            $val = match ($type) {
                'int'   => (int)$data[$field],
                'color' => $this->sanitizeColor((string)$data[$field]),
                'json'  => json_encode(is_array($data[$field]) ? $data[$field] : []),
                default => (string)$data[$field],
            };
            $fields[] = "$field = :$field";
            $params[":$field"] = $val;
        }
        if (empty($fields)) return $this->getEndpoint($id);
        $fields[] = 'updated_at = :updated_at';
        $params[':updated_at'] = $this->now();
        $params[':id'] = $id;
        $this->db->execute("UPDATE endpoints SET " . implode(', ', $fields) . " WHERE id = :id", $params);
        return $this->getEndpoint($id);
    }

    public function deleteEndpoint(string $id): bool
    {
        return $this->db->execute("DELETE FROM endpoints WHERE id = ?", [$id]) > 0;
    }

    public function togglePause(string $id): ?array
    {
        $this->db->execute("UPDATE endpoints SET is_paused = 1 - is_paused, updated_at = ? WHERE id = ?", [$this->now(), $id]);
        return $this->getEndpoint($id);
    }

    public function clearEndpoint(string $id): int
    {
        $count = $this->db->execute("DELETE FROM requests WHERE endpoint_id = ?", [$id]);
        $this->db->execute("UPDATE endpoints SET request_count=0, byte_count=0, blocked_count=0, error_count=0, last_hit_at=NULL, updated_at=? WHERE id=?", [$this->now(), $id]);
        return $count;
    }

    // ─── Request Capture ──────────────────────────────────────────────────────

    public function captureRequest(string $endpointId, array $reqData): array
    {
        $endpoint = $this->getEndpoint($endpointId);
        $id       = $this->uuid();
        $now      = $this->now();
        $body     = $reqData['body'] ?? '';
        $bodySize = strlen($body);

        // Security evaluation
        $sec = $this->security->evaluate($endpoint, $reqData);

        $this->db->transaction(function ($db) use ($id, $endpointId, $reqData, $body, $bodySize, $now, $sec) {
            $db->execute("
                INSERT INTO requests
                    (id, endpoint_id, method, url, path, query_string, headers, body,
                     body_size, content_type, ip, user_agent, duration_ms, created_at,
                     is_blocked, block_reason, signature_valid, threat_score, response_status)
                VALUES
                    (:id, :eid, :method, :url, :path, :qs, :headers, :body,
                     :bsize, :ct, :ip, :ua, :dur, :now,
                     :blocked, :breason, :sigvalid, :threat, :respstatus)
            ", [
                ':id'        => $id,
                ':eid'       => $endpointId,
                ':method'    => $reqData['method'],
                ':url'       => $reqData['url'],
                ':path'      => $reqData['path'],
                ':qs'        => $reqData['query_string'] ?? '',
                ':headers'   => json_encode($reqData['headers'] ?? []),
                ':body'      => $body,
                ':bsize'     => $bodySize,
                ':ct'        => $reqData['content_type'] ?? '',
                ':ip'        => $reqData['ip'] ?? '',
                ':ua'        => $reqData['user_agent'] ?? '',
                ':dur'       => $reqData['duration_ms'] ?? 0,
                ':now'       => $now,
                ':blocked'   => $sec['allowed'] ? 0 : 1,
                ':breason'   => $sec['reason'] ?? '',
                ':sigvalid'  => $sec['signature_valid'] ?? -1,
                ':threat'    => $sec['threat_score'] ?? 0,
                ':respstatus'=> $reqData['response_status'] ?? 0,
            ]);

            if ($sec['allowed']) {
                $db->execute("
                    UPDATE endpoints
                    SET request_count = request_count + 1,
                        byte_count    = byte_count + :bytes,
                        last_hit_at   = :now,
                        updated_at    = :now
                    WHERE id = :id
                ", [':bytes' => $bodySize, ':now' => $now, ':id' => $endpointId]);
            }

            // Purge oldest beyond cap
            $db->execute("
                DELETE FROM requests WHERE endpoint_id = :eid AND id NOT IN (
                    SELECT id FROM requests WHERE endpoint_id = :eid
                    ORDER BY created_at DESC LIMIT " . MAX_REQUESTS_PER_ENDPOINT . "
                )
            ", [':eid' => $endpointId]);
        });

        return $this->getRequest($id);
    }

    public function getRequest(string $id): ?array
    {
        $row = $this->db->queryOne("SELECT * FROM requests WHERE id = ?", [$id]);
        return $row ? $this->formatRequest($row) : null;
    }

    public function listRequests(string $endpointId, array $filters = []): array
    {
        $where  = ['r.endpoint_id = :eid'];
        $params = [':eid' => $endpointId];

        if (!empty($filters['method'])) {
            $where[] = 'r.method = :method';
            $params[':method'] = strtoupper($filters['method']);
        }
        if (isset($filters['search']) && $filters['search'] !== '') {
            $where[] = "(r.body LIKE :search OR r.path LIKE :search OR r.ip LIKE :search OR r.note LIKE :search)";
            $params[':search'] = '%' . $filters['search'] . '%';
        }
        if (!empty($filters['starred']))  $where[] = 'r.is_starred = 1';
        if (!empty($filters['blocked']))  $where[] = 'r.is_blocked = 1';
        if (!empty($filters['threats']))  $where[] = 'r.threat_score > 0';
        if (!empty($filters['from'])) {
            $where[] = 'r.created_at >= :from';
            $params[':from'] = $filters['from'];
        }
        if (!empty($filters['tag'])) {
            $where[] = "r.tags LIKE :tag";
            $params[':tag'] = '%"' . $filters['tag'] . '"%';
        }

        $limit  = min(500, (int)($filters['limit'] ?? 200));
        $offset = max(0, (int)($filters['offset'] ?? 0));
        $sort   = in_array($filters['sort'] ?? '', ['created_at', 'duration_ms', 'body_size', 'threat_score']) ? $filters['sort'] : 'created_at';
        $dir    = ($filters['dir'] ?? 'desc') === 'asc' ? 'ASC' : 'DESC';

        $sql = "SELECT * FROM requests r WHERE " . implode(' AND ', $where)
             . " ORDER BY r.$sort $dir LIMIT $limit OFFSET $offset";

        $rows = $this->db->query($sql, $params);
        return array_map([$this, 'formatRequest'], $rows);
    }

    public function deleteRequest(string $id): bool
    {
        return $this->db->execute("DELETE FROM requests WHERE id = ?", [$id]) > 0;
    }

    public function addNote(string $id, string $note): ?array
    {
        $this->db->execute("UPDATE requests SET note = ? WHERE id = ?", [substr($note, 0, 2000), $id]);
        return $this->getRequest($id);
    }

    public function toggleStar(string $id): ?array
    {
        $this->db->execute("UPDATE requests SET is_starred = 1 - is_starred WHERE id = ?", [$id]);
        return $this->getRequest($id);
    }

    public function updateTags(string $id, array $tags): ?array
    {
        $clean = array_values(array_unique(array_map('strval', array_slice($tags, 0, 10))));
        $this->db->execute("UPDATE requests SET tags = ? WHERE id = ?", [json_encode($clean), $id]);
        return $this->getRequest($id);
    }

    // ─── Replay ───────────────────────────────────────────────────────────────

    public function replayRequest(string $requestId, string $targetUrl = ''): array
    {
        $req = $this->getRequest($requestId);
        if (!$req) return ['success' => false, 'error' => 'Request not found'];

        $url = $targetUrl ?: $req['url'];
        $t0  = microtime(true);

        $ch = curl_init($url);
        $curlHeaders = [];
        foreach ($req['headers'] as $k => $v) {
            if (in_array(strtolower($k), ['host','content-length','transfer-encoding'])) continue;
            $curlHeaders[] = "$k: $v";
        }
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => $req['method'],
            CURLOPT_POSTFIELDS     => $req['body'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 20,
            CURLOPT_HTTPHEADER     => $curlHeaders,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);
        $resp   = curl_exec($ch);
        $code   = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error  = curl_error($ch);
        $dur    = round((microtime(true) - $t0) * 1000, 2);
        curl_close($ch);

        $replayId = $this->uuid();
        $now      = $this->now();
        $this->db->execute("
            INSERT INTO replay_history (id, request_id, endpoint_id, target_url, method, status_code, duration_ms, error, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        ", [$replayId, $requestId, $req['endpoint_id'], $url, $req['method'], $code, $dur, $error, $now]);

        return [
            'success'    => !$error && $code > 0,
            'replay_id'  => $replayId,
            'status_code'=> $code,
            'duration_ms'=> $dur,
            'error'      => $error ?: null,
            'target_url' => $url,
            'response_preview' => $resp ? substr($resp, 0, 500) : null,
        ];
    }

    public function getReplayHistory(string $requestId): array
    {
        return $this->db->query("SELECT * FROM replay_history WHERE request_id = ? ORDER BY created_at DESC", [$requestId]);
    }

    // ─── Rules ────────────────────────────────────────────────────────────────

    public function createRule(string $endpointId, array $data): array
    {
        $id  = $this->uuid();
        $now = $this->now();
        $this->db->execute("
            INSERT INTO webhook_rules (id, endpoint_id, name, type, condition_json, action_json, is_active, priority, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        ", [
            $id, $endpointId,
            substr($data['name'] ?? 'Rule', 0, 100),
            in_array($data['type'] ?? 'filter', ['filter','alert','transform']) ? $data['type'] : 'filter',
            json_encode($data['condition'] ?? []),
            json_encode($data['action'] ?? []),
            (int)($data['is_active'] ?? 1),
            (int)($data['priority'] ?? 0),
            $now,
        ]);
        return $this->db->queryOne("SELECT * FROM webhook_rules WHERE id = ?", [$id]);
    }

    public function listRules(string $endpointId): array
    {
        return $this->db->query("SELECT * FROM webhook_rules WHERE endpoint_id = ? ORDER BY priority ASC, created_at ASC", [$endpointId]);
    }

    public function deleteRule(string $id): bool
    {
        return $this->db->execute("DELETE FROM webhook_rules WHERE id = ?", [$id]) > 0;
    }

    // ─── Analytics ────────────────────────────────────────────────────────────

    public function getGlobalStats(): array
    {
        $endpoints  = (int)($this->db->queryOne("SELECT COUNT(*) as c FROM endpoints")['c'] ?? 0);
        $requests   = (int)($this->db->queryOne("SELECT COUNT(*) as c FROM requests")['c'] ?? 0);
        $blocked    = (int)($this->db->queryOne("SELECT COUNT(*) as c FROM requests WHERE is_blocked=1")['c'] ?? 0);
        $bytes      = (int)($this->db->queryOne("SELECT COALESCE(SUM(byte_count),0) as b FROM endpoints")['b'] ?? 0);
        $avgDur     = (float)($this->db->queryOne("SELECT ROUND(AVG(duration_ms),2) as a FROM requests WHERE duration_ms>0")['a'] ?? 0);
        $threats    = (int)($this->db->queryOne("SELECT COUNT(*) as c FROM requests WHERE threat_score>0")['c'] ?? 0);

        $methodDist = $this->db->query("SELECT method, COUNT(*) as count FROM requests WHERE is_blocked=0 GROUP BY method ORDER BY count DESC");
        $last24h    = $this->db->query("SELECT strftime('%H',created_at) as hour, COUNT(*) as count FROM requests WHERE created_at >= datetime('now','-24 hours') GROUP BY hour ORDER BY hour");
        $last7days  = $this->db->query("SELECT date(created_at) as day, COUNT(*) as total, SUM(is_blocked) as blocked FROM requests WHERE created_at >= date('now','-7 days') GROUP BY day ORDER BY day");
        $contentTypes = $this->db->query("SELECT content_type, COUNT(*) as count FROM requests WHERE content_type!='' AND is_blocked=0 GROUP BY content_type ORDER BY count DESC LIMIT 8");
        $topEndpoints = $this->db->query("SELECT id, name, color, request_count, blocked_count, byte_count, last_hit_at FROM endpoints ORDER BY request_count DESC LIMIT 8");
        $recentSec  = $this->db->query("SELECT event_type, COUNT(*) as count FROM security_events WHERE created_at >= datetime('now','-24 hours') GROUP BY event_type ORDER BY count DESC");

        // Requests per minute (last 60 minutes)
        $rpm = $this->db->query("
            SELECT strftime('%Y-%m-%dT%H:%M',created_at) as minute, COUNT(*) as count
            FROM requests WHERE created_at >= datetime('now','-60 minutes')
            GROUP BY minute ORDER BY minute
        ");

        // Avg duration trend
        $durTrend = $this->db->query("
            SELECT date(created_at) as day, ROUND(AVG(duration_ms),2) as avg_ms
            FROM requests WHERE created_at >= date('now','-7 days') AND duration_ms>0
            GROUP BY day ORDER BY day
        ");

        // Body size distribution
        $sizeDist = $this->db->query("
            SELECT
                CASE
                    WHEN body_size=0 THEN 'Empty'
                    WHEN body_size<1024 THEN '<1 KB'
                    WHEN body_size<10240 THEN '1-10 KB'
                    WHEN body_size<102400 THEN '10-100 KB'
                    ELSE '>100 KB'
                END as range, COUNT(*) as count
            FROM requests GROUP BY range ORDER BY count DESC
        ");

        return [
            'totals' => [
                'endpoints'      => $endpoints,
                'requests'       => $requests,
                'blocked'        => $blocked,
                'bytes'          => $bytes,
                'avg_duration_ms'=> $avgDur,
                'threats'        => $threats,
                'block_rate'     => $requests > 0 ? round($blocked / $requests * 100, 1) : 0,
            ],
            'method_distribution'  => $methodDist,
            'requests_last_24h'    => $last24h,
            'requests_last_7_days' => $last7days,
            'content_types'        => $contentTypes,
            'top_endpoints'        => $topEndpoints,
            'recent_security'      => $recentSec,
            'requests_per_minute'  => $rpm,
            'duration_trend'       => $durTrend,
            'size_distribution'    => $sizeDist,
        ];
    }

    public function getEndpointStats(string $id): array
    {
        $methods  = $this->db->query("SELECT method, COUNT(*) as count FROM requests WHERE endpoint_id=? GROUP BY method", [$id]);
        $timeline = $this->db->query("
            SELECT strftime('%Y-%m-%dT%H:%M',created_at) as minute, COUNT(*) as count, SUM(is_blocked) as blocked
            FROM requests WHERE endpoint_id=? AND created_at >= datetime('now','-2 hours')
            GROUP BY minute ORDER BY minute
        ", [$id]);
        $sizes    = $this->db->query("
            SELECT CASE WHEN body_size=0 THEN 'Empty' WHEN body_size<1024 THEN '<1KB' WHEN body_size<10240 THEN '1-10KB' WHEN body_size<102400 THEN '10-100KB' ELSE '>100KB' END as range, COUNT(*) as count
            FROM requests WHERE endpoint_id=? GROUP BY range
        ", [$id]);
        $dur      = $this->db->queryOne("SELECT ROUND(AVG(duration_ms),2) as avg, MIN(duration_ms) as min, MAX(duration_ms) as max, ROUND(AVG(CASE WHEN threat_score>0 THEN threat_score END),1) as avg_threat FROM requests WHERE endpoint_id=? AND duration_ms>0", [$id]);
        $threatDist = $this->db->query("
            SELECT CASE WHEN threat_score=0 THEN 'Clean' WHEN threat_score<25 THEN 'Low' WHEN threat_score<50 THEN 'Medium' WHEN threat_score<75 THEN 'High' ELSE 'Critical' END as level, COUNT(*) as count
            FROM requests WHERE endpoint_id=? GROUP BY level
        ", [$id]);
        $topIps   = $this->db->query("SELECT ip, COUNT(*) as count FROM requests WHERE endpoint_id=? AND ip!='' GROUP BY ip ORDER BY count DESC LIMIT 10", [$id]);
        $hourly   = $this->db->query("SELECT strftime('%H',created_at) as hour, COUNT(*) as count FROM requests WHERE endpoint_id=? AND created_at >= datetime('now','-7 days') GROUP BY hour ORDER BY hour", [$id]);

        return compact('methods','timeline','sizes','dur','threatDist','topIps','hourly');
    }

    // ─── Formatters ───────────────────────────────────────────────────────────

    private function formatEndpoint(array $row): array
    {
        foreach (['response_headers','allowed_ips','blocked_ips','allowed_methods','filter_rules'] as $f) {
            $row[$f] = json_decode($row[$f] ?? '[]', true) ?? [];
        }
        foreach (['is_paused','require_signature','require_auth','request_count','blocked_count','byte_count','error_count','max_requests','response_status','response_delay_ms'] as $f) {
            $row[$f] = (int)($row[$f] ?? 0);
        }
        $row['webhook_url']  = BASE_URL . '/webhook/' . $row['token'];
        $row['is_expired']   = !empty($row['expires_at']) && strtotime($row['expires_at']) < time();
        $row['is_capped']    = $row['max_requests'] > 0 && $row['request_count'] >= $row['max_requests'];
        return $row;
    }

    private function formatRequest(array $row): array
    {
        $row['headers']   = json_decode($row['headers'] ?? '{}', true) ?? [];
        $row['tags']      = json_decode($row['tags'] ?? '[]', true) ?? [];
        $row['body_size'] = (int)$row['body_size'];
        $row['is_starred']= (bool)$row['is_starred'];
        $row['is_blocked']= (bool)$row['is_blocked'];
        $row['duration_ms']= (float)$row['duration_ms'];
        $row['threat_score']= (int)$row['threat_score'];
        $row['signature_valid'] = (int)$row['signature_valid'];

        $ct = strtolower($row['content_type'] ?? '');
        $row['body_format'] = 'text';
        $row['body_parsed'] = null;

        if (str_contains($ct, 'json') || $this->looksJson($row['body'] ?? '')) {
            $parsed = json_decode($row['body'], true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $row['body_parsed'] = $parsed;
                $row['body_format'] = 'json';
            }
        } elseif (str_contains($ct, 'xml')) {
            $row['body_format'] = 'xml';
        } elseif (str_contains($ct, 'form')) {
            parse_str($row['body'] ?? '', $parsed);
            $row['body_parsed'] = $parsed;
            $row['body_format'] = 'form';
        } elseif (str_contains($ct, 'msgpack') || str_contains($ct, 'protobuf')) {
            $row['body_format'] = 'binary';
        }

        return $row;
    }

    private function looksJson(string $s): bool
    {
        $s = ltrim($s);
        return strlen($s) > 0 && ($s[0] === '{' || $s[0] === '[');
    }

    private function sanitizeColor(string $c): string
    {
        return preg_match('/^#[0-9a-f]{6}$/i', $c) ? $c : '#6366f1';
    }

    private function now(): string { return gmdate('Y-m-d\TH:i:s\Z'); }

    private function uuid(): string
    {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0,0xffff), mt_rand(0,0xffff), mt_rand(0,0xffff),
            mt_rand(0,0x0fff)|0x4000, mt_rand(0,0x3fff)|0x8000,
            mt_rand(0,0xffff), mt_rand(0,0xffff), mt_rand(0,0xffff)
        );
    }
}
