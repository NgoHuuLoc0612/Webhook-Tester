<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Services\WebhookService;
use App\Services\SecurityService;
use App\Services\SseService;

class ApiController
{
    private WebhookService  $service;
    private SecurityService $security;

    public function __construct()
    {
        $this->service  = new WebhookService();
        $this->security = new SecurityService();
        header('Content-Type: application/json');
        header('X-App-Version: ' . APP_VERSION);
    }

    // ─── Endpoints ────────────────────────────────────────────────────────────

    public function listEndpoints(): void
    {
        $endpoints = $this->service->listEndpoints();
        $this->json(['data' => $endpoints, 'count' => count($endpoints)]);
    }

    public function createEndpoint(): void
    {
        $data = $this->body();
        if (empty($data['name'])) { $this->fail('Name is required', 422); return; }
        $ep = $this->service->createEndpoint($data);
        $this->json(['data' => $ep], 201);
    }

    public function updateEndpoint(string $id): void
    {
        $ep = $this->service->updateEndpoint($id, $this->body());
        $ep ? $this->json(['data' => $ep]) : $this->notFound();
    }

    public function deleteEndpoint(string $id): void
    {
        $this->service->deleteEndpoint($id) ? $this->json(['success' => true]) : $this->notFound();
    }

    public function togglePause(string $id): void
    {
        $ep = $this->service->togglePause($id);
        $ep ? $this->json(['data' => $ep]) : $this->notFound();
    }

    public function clearEndpoint(string $id): void
    {
        $n = $this->service->clearEndpoint($id);
        $this->json(['success' => true, 'deleted' => $n]);
    }

    public function regenerateToken(string $id): void
    {
        $ep = $this->service->getEndpoint($id);
        if (!$ep) { $this->notFound(); return; }
        $token = bin2hex(random_bytes(16));
        $this->service->updateEndpoint($id, ['token_regen' => $token]); // handled separately
        // Direct DB update for token
        \App\Services\DatabaseService::getInstance()->execute(
            "UPDATE endpoints SET token=?, updated_at=? WHERE id=?",
            [$token, gmdate('Y-m-d\TH:i:s\Z'), $id]
        );
        $this->json(['data' => $this->service->getEndpoint($id)]);
    }

    // ─── Requests ─────────────────────────────────────────────────────────────

    public function getRequest(string $id): void
    {
        // Try as request UUID first
        $req = $this->service->getRequest($id);
        if ($req) {
            $stats    = $this->service->getEndpointStats($req['endpoint_id']);
            $requests = $this->service->listRequests($req['endpoint_id'], ['limit' => 200]);
            $replays  = $this->service->getReplayHistory($id);
            $this->json(['data' => $req, 'stats' => $stats, 'requests' => $requests, 'replay_history' => $replays]);
            return;
        }

        // Try as endpoint ID
        $ep = $this->service->getEndpoint($id);
        if (!$ep) { $this->notFound(); return; }

        $filters = [
            'method'  => $_GET['method'] ?? '',
            'search'  => $_GET['search'] ?? '',
            'starred' => !empty($_GET['starred']),
            'blocked' => !empty($_GET['blocked']),
            'threats' => !empty($_GET['threats']),
            'tag'     => $_GET['tag'] ?? '',
            'sort'    => $_GET['sort'] ?? 'created_at',
            'dir'     => $_GET['dir'] ?? 'desc',
            'limit'   => (int)($_GET['limit'] ?? 200),
            'offset'  => (int)($_GET['offset'] ?? 0),
        ];

        $requests = $this->service->listRequests($id, $filters);
        $stats    = $this->service->getEndpointStats($id);
        $this->json(['data' => $ep, 'requests' => $requests, 'stats' => $stats]);
    }

    public function deleteRequest(string $id): void
    {
        $this->service->deleteRequest($id) ? $this->json(['success' => true]) : $this->notFound();
    }

    public function starRequest(string $id): void
    {
        $req = $this->service->toggleStar($id);
        $req ? $this->json(['data' => $req]) : $this->notFound();
    }

    public function addNote(string $id): void
    {
        $b = $this->body();
        $req = $this->service->addNote($id, $b['note'] ?? '');
        $req ? $this->json(['data' => $req]) : $this->notFound();
    }

    public function updateTags(string $id): void
    {
        $b = $this->body();
        $req = $this->service->updateTags($id, $b['tags'] ?? []);
        $req ? $this->json(['data' => $req]) : $this->notFound();
    }

    public function replayRequest(string $id): void
    {
        $b      = $this->body();
        $result = $this->service->replayRequest($id, $b['target_url'] ?? '');
        $this->json($result);
    }

    public function getReplayHistory(string $id): void
    {
        $this->json(['data' => $this->service->getReplayHistory($id)]);
    }

    // ─── Stats & Analytics ────────────────────────────────────────────────────

    public function globalStats(): void
    {
        $stats = $this->service->getGlobalStats();
        $sec   = $this->security->getGlobalSecurityStats();
        $this->json(['data' => array_merge($stats, ['security' => $sec])]);
    }

    public function endpointStats(string $id): void
    {
        $ep = $this->service->getEndpoint($id);
        if (!$ep) { $this->notFound(); return; }
        $stats  = $this->service->getEndpointStats($id);
        $events = $this->security->getSecurityEvents($id, 30);
        $this->json(['data' => array_merge($stats, ['security_events' => $events, 'endpoint' => $ep])]);
    }

    // ─── Security ─────────────────────────────────────────────────────────────

    public function securityEvents(string $endpointId): void
    {
        $limit  = min(200, (int)($_GET['limit'] ?? 50));
        $events = $this->security->getSecurityEvents($endpointId, $limit);
        $this->json(['data' => $events]);
    }

    public function globalSecurityStats(): void
    {
        $this->json(['data' => $this->security->getGlobalSecurityStats()]);
    }

    public function verifySignature(string $endpointId): void
    {
        $ep = $this->service->getEndpoint($endpointId);
        if (!$ep) { $this->notFound(); return; }
        $b       = $this->body();
        $headers = $b['headers'] ?? [];
        $body    = $b['body'] ?? '';
        $valid   = $this->security->verifySignature($ep, $headers, $body);
        $this->json(['valid' => $valid, 'algo' => $ep['signature_algo'], 'header' => $ep['signature_header']]);
    }

    // ─── API Keys ─────────────────────────────────────────────────────────────

    public function listApiKeys(): void
    {
        $this->json(['data' => $this->security->listApiKeys()]);
    }

    public function createApiKey(): void
    {
        $b      = $this->body();
        $result = $this->security->createApiKey($b['name'] ?? 'API Key', $b['permissions'] ?? ['read','write']);
        $this->json(['data' => $result], 201);
    }

    public function deleteApiKey(string $id): void
    {
        $this->security->deleteApiKey($id) ? $this->json(['success' => true]) : $this->notFound();
    }

    // ─── Rules ────────────────────────────────────────────────────────────────

    public function listRules(string $endpointId): void
    {
        $this->json(['data' => $this->service->listRules($endpointId)]);
    }

    public function createRule(string $endpointId): void
    {
        $rule = $this->service->createRule($endpointId, $this->body());
        $this->json(['data' => $rule], 201);
    }

    public function deleteRule(string $id): void
    {
        $this->service->deleteRule($id) ? $this->json(['success' => true]) : $this->notFound();
    }

    // ─── SSE Stream ───────────────────────────────────────────────────────────

    public function stream(): void
    {
        $endpointId = $_GET['endpoint_id'] ?? null;
        $sse = new SseService();
        if ($endpointId) {
            if (!$this->service->getEndpoint($endpointId)) { $this->notFound(); return; }
            $sse->stream($endpointId);
        } else {
            $sse->streamAll();
        }
    }

    // ─── Export ───────────────────────────────────────────────────────────────

    public function export(string $id): void
    {
        $fmt = $_GET['format'] ?? 'json';
        $req = $this->service->getRequest($id);
        if (!$req) { $this->notFound(); return; }

        match ($fmt) {
            'curl'   => $this->exportText($this->toCurl($req)),
            'httpie' => $this->exportText($this->toHttpie($req)),
            'python' => $this->exportText($this->toPython($req), 'text/x-python'),
            'node'   => $this->exportText($this->toNode($req), 'text/javascript'),
            'php'    => $this->exportText($this->toPhp($req), 'text/x-php'),
            'go'     => $this->exportText($this->toGo($req), 'text/x-go'),
            default  => $this->exportJson($req, $id),
        };
    }

    // ─── Code Generators ──────────────────────────────────────────────────────

    private function toCurl(array $r): string
    {
        $parts = ["curl -X {$r['method']} \\\n  '{$r['url']}'"];
        foreach ($r['headers'] as $k => $v) $parts[] = "  -H '$k: " . addslashes($v) . "'";
        if ($r['body']) $parts[] = "  --data-raw '" . addslashes(substr($r['body'], 0, 2000)) . "'";
        return implode(" \\\n", $parts);
    }

    private function toHttpie(array $r): string
    {
        $m = strtolower($r['method']);
        $s = "http $m '{$r['url']}'";
        foreach ($r['headers'] as $k => $v) $s .= " \\\n  '$k: $v'";
        if ($r['body']) $s .= " \\\n  <<< '" . addslashes(substr($r['body'], 0, 1000)) . "'";
        return $s;
    }

    private function toPython(array $r): string
    {
        $h = json_encode($r['headers'], JSON_PRETTY_PRINT);
        $b = json_encode($r['body']);
        $m = strtolower($r['method']);
        return "import requests\n\nurl = \"{$r['url']}\"\nheaders = $h\nbody = $b\n\nresponse = requests.$m(url, headers=headers, data=body)\nprint(response.status_code, response.text)\n";
    }

    private function toNode(array $r): string
    {
        $h = json_encode($r['headers'], JSON_PRETTY_PRINT);
        $b = json_encode($r['body']);
        return "const response = await fetch(\"{$r['url']}\", {\n  method: \"{$r['method']}\",\n  headers: $h,\n  body: $b,\n});\nconst data = await response.json();\nconsole.log(response.status, data);\n";
    }

    private function toPhp(array $r): string
    {
        $h = var_export($r['headers'], true);
        $b = var_export($r['body'], true);
        return "<?php\n\$ch = curl_init('{$r['url']}');\n\$headers = $h;\ncurl_setopt_array(\$ch, [\n  CURLOPT_CUSTOMREQUEST => '{$r['method']}',\n  CURLOPT_POSTFIELDS => $b,\n  CURLOPT_RETURNTRANSFER => true,\n  CURLOPT_HTTPHEADER => array_map(fn(\$k,\$v)=>\"\$k: \$v\", array_keys(\$headers), \$headers),\n]);\n\$result = curl_exec(\$ch);\n\$code = curl_getinfo(\$ch, CURLINFO_HTTP_CODE);\ncurl_close(\$ch);\necho \$code . ' ' . \$result;\n";
    }

    private function toGo(array $r): string
    {
        $b = addslashes($r['body'] ?? '');
        $hlines = implode("\n", array_map(fn($k,$v)=>"\treq.Header.Set(\"$k\", \"" . addslashes($v) . "\")", array_keys($r['headers']), array_values($r['headers'])));
        return "package main\n\nimport (\n\t\"bytes\"\n\t\"fmt\"\n\t\"net/http\"\n)\n\nfunc main() {\n\tclient := &http.Client{}\n\tbody := bytes.NewBufferString(\"$b\")\n\treq, _ := http.NewRequest(\"{$r['method']}\", \"{$r['url']}\", body)\n$hlines\n\tresp, _ := client.Do(req)\n\tfmt.Println(resp.Status)\n}\n";
    }

    private function exportText(string $content, string $ct = 'text/plain'): void
    {
        header('Content-Type: ' . $ct);
        echo $content;
    }

    private function exportJson(array $req, string $id): void
    {
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="request-' . $id . '.json"');
        echo json_encode($req, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private function body(): array
    {
        $raw = file_get_contents('php://input');
        return json_decode($raw, true) ?? [];
    }

    private function json(array $data, int $status = 200): void
    {
        http_response_code($status);
        echo json_encode(array_merge($data, ['_ms' => round((microtime(true) - APP_START) * 1000, 2)]), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private function notFound(): void { http_response_code(404); echo json_encode(['error' => 'Not found']); }
    private function fail(string $msg, int $code = 400): void { http_response_code($code); echo json_encode(['error' => $msg]); }
}
