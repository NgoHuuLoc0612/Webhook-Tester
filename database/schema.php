<?php
declare(strict_types=1);

use App\Services\DatabaseService;

$db = DatabaseService::getInstance();

$db->exec('PRAGMA journal_mode=WAL');
$db->exec('PRAGMA foreign_keys=ON');
$db->exec('PRAGMA synchronous=NORMAL');
$db->exec('PRAGMA cache_size=20000');
$db->exec('PRAGMA temp_store=MEMORY');
$db->exec('PRAGMA mmap_size=268435456');

$db->exec("
CREATE TABLE IF NOT EXISTS endpoints (
    id                   TEXT PRIMARY KEY,
    token                TEXT UNIQUE NOT NULL,
    name                 TEXT NOT NULL DEFAULT 'Unnamed Endpoint',
    description          TEXT DEFAULT '',
    color                TEXT DEFAULT '#6366f1',
    is_paused            INTEGER DEFAULT 0,
    response_status      INTEGER DEFAULT 200,
    response_body        TEXT DEFAULT '',
    response_headers     TEXT DEFAULT '{}',
    response_delay_ms    INTEGER DEFAULT 0,
    response_mode        TEXT DEFAULT 'static',
    forward_url          TEXT DEFAULT '',
    secret_key           TEXT DEFAULT '',
    allowed_ips          TEXT DEFAULT '[]',
    blocked_ips          TEXT DEFAULT '[]',
    require_signature    INTEGER DEFAULT 0,
    signature_header     TEXT DEFAULT 'X-Hub-Signature-256',
    signature_algo       TEXT DEFAULT 'sha256',
    allowed_methods      TEXT DEFAULT '[]',
    require_auth         INTEGER DEFAULT 0,
    auth_type            TEXT DEFAULT 'bearer',
    auth_value           TEXT DEFAULT '',
    filter_rules         TEXT DEFAULT '[]',
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    last_hit_at          TEXT,
    request_count        INTEGER DEFAULT 0,
    blocked_count        INTEGER DEFAULT 0,
    byte_count           INTEGER DEFAULT 0,
    error_count          INTEGER DEFAULT 0,
    expires_at           TEXT DEFAULT NULL,
    max_requests         INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS requests (
    id               TEXT PRIMARY KEY,
    endpoint_id      TEXT NOT NULL,
    method           TEXT NOT NULL,
    url              TEXT NOT NULL,
    path             TEXT NOT NULL,
    query_string     TEXT DEFAULT '',
    headers          TEXT DEFAULT '{}',
    body             TEXT DEFAULT '',
    body_size        INTEGER DEFAULT 0,
    content_type     TEXT DEFAULT '',
    ip               TEXT DEFAULT '',
    user_agent       TEXT DEFAULT '',
    duration_ms      REAL DEFAULT 0,
    created_at       TEXT NOT NULL,
    note             TEXT DEFAULT '',
    is_starred       INTEGER DEFAULT 0,
    tags             TEXT DEFAULT '[]',
    is_blocked       INTEGER DEFAULT 0,
    block_reason     TEXT DEFAULT '',
    signature_valid  INTEGER DEFAULT -1,
    threat_score     INTEGER DEFAULT 0,
    response_status  INTEGER DEFAULT 0,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limits (
    token        TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count        INTEGER DEFAULT 0,
    PRIMARY KEY (token, window_start)
);

CREATE TABLE IF NOT EXISTS security_events (
    id           TEXT PRIMARY KEY,
    endpoint_id  TEXT,
    event_type   TEXT NOT NULL,
    ip           TEXT DEFAULT '',
    details      TEXT DEFAULT '{}',
    created_at   TEXT NOT NULL,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webhook_rules (
    id          TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    condition_json TEXT DEFAULT '{}',
    action_json    TEXT DEFAULT '{}',
    is_active   INTEGER DEFAULT 1,
    priority    INTEGER DEFAULT 0,
    hit_count   INTEGER DEFAULT 0,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS replay_history (
    id           TEXT PRIMARY KEY,
    request_id   TEXT NOT NULL,
    endpoint_id  TEXT NOT NULL,
    target_url   TEXT NOT NULL,
    method       TEXT NOT NULL,
    status_code  INTEGER DEFAULT 0,
    duration_ms  REAL DEFAULT 0,
    error        TEXT DEFAULT '',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    key_hash     TEXT UNIQUE NOT NULL,
    key_prefix   TEXT NOT NULL,
    permissions  TEXT DEFAULT '[\"read\",\"write\"]',
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    expires_at   TEXT,
    is_active    INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_requests_endpoint_id ON requests(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_requests_created_at  ON requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_requests_method      ON requests(method);
CREATE INDEX IF NOT EXISTS idx_requests_ip          ON requests(ip);
CREATE INDEX IF NOT EXISTS idx_requests_starred     ON requests(is_starred);
CREATE INDEX IF NOT EXISTS idx_requests_blocked     ON requests(is_blocked);
CREATE INDEX IF NOT EXISTS idx_requests_threat      ON requests(threat_score);
CREATE INDEX IF NOT EXISTS idx_security_ep_time     ON security_events(endpoint_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_type        ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window   ON rate_limits(token, window_start);
CREATE INDEX IF NOT EXISTS idx_rules_endpoint       ON webhook_rules(endpoint_id, priority);
CREATE INDEX IF NOT EXISTS idx_replay_request       ON replay_history(request_id);
");
