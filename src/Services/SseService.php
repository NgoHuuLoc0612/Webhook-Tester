<?php
declare(strict_types=1);

namespace App\Services;

class SseService
{
    private string $lastId;
    private int    $pollMs = 350_000; // 350ms

    public function __construct()
    {
        $this->lastId = $_SERVER['HTTP_LAST_EVENT_ID'] ?? '0';
    }

    public function stream(string $endpointId): void
    {
        $this->initSse();
        $db     = DatabaseService::getInstance();
        $lastId = $this->lastId;
        $pingAt = time();

        $this->send('connected', json_encode([
            'endpoint_id' => $endpointId,
            'timestamp'   => gmdate('c'),
            'server'      => gethostname(),
        ]));

        while (!connection_aborted()) {
            $rows = $db->query("
                SELECT r.*, e.name AS endpoint_name, e.color AS endpoint_color, e.token
                FROM requests r
                JOIN endpoints e ON e.id = r.endpoint_id
                WHERE r.endpoint_id = :eid AND r.id > :last
                ORDER BY r.created_at ASC
                LIMIT 30
            ", [':eid' => $endpointId, ':last' => $lastId]);

            foreach ($rows as $row) {
                $row['headers']    = json_decode($row['headers'] ?? '{}', true) ?? [];
                $row['tags']       = json_decode($row['tags'] ?? '[]', true) ?? [];
                $row['is_starred'] = (bool)$row['is_starred'];
                $row['is_blocked'] = (bool)$row['is_blocked'];
                $row['threat_score'] = (int)$row['threat_score'];
                $this->send('request', json_encode($row), $row['id']);
                $lastId = $row['id'];
            }

            if (time() - $pingAt >= SSE_HEARTBEAT_INTERVAL) {
                $this->ping();
                $pingAt = time();

                // Send live stats update
                $stats = $db->queryOne("
                    SELECT COUNT(*) as total, SUM(is_blocked) as blocked
                    FROM requests WHERE endpoint_id = ? AND created_at >= datetime('now','-5 minutes')
                ", [$endpointId]);
                if ($stats) {
                    $this->send('stats', json_encode($stats));
                }
            }

            usleep($this->pollMs);
        }
    }

    public function streamAll(): void
    {
        $this->initSse();
        $db     = DatabaseService::getInstance();
        $lastId = $this->lastId;
        $pingAt = time();

        $this->send('connected', json_encode([
            'type'      => 'global',
            'timestamp' => gmdate('c'),
        ]));

        while (!connection_aborted()) {
            $rows = $db->query("
                SELECT r.*, e.name AS endpoint_name, e.color AS endpoint_color, e.token
                FROM requests r
                JOIN endpoints e ON e.id = r.endpoint_id
                WHERE r.id > :last
                ORDER BY r.created_at ASC
                LIMIT 30
            ", [':last' => $lastId]);

            foreach ($rows as $row) {
                $row['headers']    = json_decode($row['headers'] ?? '{}', true) ?? [];
                $row['tags']       = json_decode($row['tags'] ?? '[]', true) ?? [];
                $row['is_starred'] = (bool)$row['is_starred'];
                $row['is_blocked'] = (bool)$row['is_blocked'];
                $row['threat_score'] = (int)$row['threat_score'];
                $this->send('request', json_encode($row), $row['id']);
                $lastId = $row['id'];
            }

            if (time() - $pingAt >= SSE_HEARTBEAT_INTERVAL) {
                $this->ping();
                $pingAt = time();

                // Global live stats
                $stats = $db->queryOne("
                    SELECT
                        COUNT(*) as total_5m,
                        SUM(is_blocked) as blocked_5m,
                        SUM(CASE WHEN threat_score > 0 THEN 1 ELSE 0 END) as threats_5m
                    FROM requests WHERE created_at >= datetime('now','-5 minutes')
                ");
                if ($stats) $this->send('global_stats', json_encode($stats));
            }

            usleep($this->pollMs);
        }
    }

    private function initSse(): void
    {
        while (ob_get_level()) ob_end_clean();
        set_time_limit(0);
        ignore_user_abort(true);

        header('Content-Type: text/event-stream; charset=utf-8');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('X-Accel-Buffering: no');
        header('Connection: keep-alive');
        header('Transfer-Encoding: identity');
    }

    private function send(string $event, string $data, string $id = ''): void
    {
        if ($id)    echo "id: $id\n";
        echo "event: $event\n";
        echo "data: $data\n\n";
        if (ob_get_level()) ob_flush();
        flush();
    }

    private function ping(): void
    {
        echo ": keepalive " . time() . "\n\n";
        if (ob_get_level()) ob_flush();
        flush();
    }
}
