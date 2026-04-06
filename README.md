# WebhookTester Enterprise v3.0

## Project Structure

```
webhook-tester/
├── public/                          ← Document root (Laragon points HERE)
│   ├── index.php                    ← Front controller + router (22 routes)
│   ├── app.html                     ← SPA shell (5 views)
│   ├── .htaccess                    ← Rewrite + security headers + WAF rules
│   └── assets/
│       ├── app.css                  ← Dark industrial UI (~700 lines)
│       └── app.js                   ← Enterprise SPA engine (~900 lines)
│
├── src/
│   ├── Controllers/
│   │   ├── DashboardController.php  ← Serves SPA HTML
│   │   ├── WebhookController.php    ← Full webhook capture pipeline
│   │   └── ApiController.php        ← Complete REST API (20+ endpoints)
│   ├── Services/
│   │   ├── DatabaseService.php      ← PDO/SQLite singleton (WAL, mmap)
│   │   ├── WebhookService.php       ← Business logic + analytics queries
│   │   ├── SecurityService.php      ← Full security pipeline + API keys
│   │   └── SseService.php           ← SSE streaming (per-endpoint + global)
│   └── Middleware/
│       ├── CorsMiddleware.php       ← Full CORS with Vary header
│       └── RateLimitMiddleware.php  ← Sliding window rate limiter
│
├── config/
│   └── bootstrap.php                ← Autoloader, error handling, constants
│
├── database/
│   ├── schema.php                   ← 8-table SQLite schema (auto-migrates)
│   └── webhook_tester.sqlite        ← Created automatically on first boot
│
└── storage/
    └── logs/                        ← Application logs
```

---

## Laragon Setup

### 1. Place project
```
C:\laragon\www\webhook-tester\
```

### 2. Virtual host
Laragon auto-creates: `http://webhook-tester.test`

Point document root to: `C:\laragon\www\webhook-tester\public`

### 3. Manual vhost (if needed)
```apache
<VirtualHost *:80>
    ServerName webhook-tester.test
    DocumentRoot "C:/laragon/www/webhook-tester/public"
    <Directory "C:/laragon/www/webhook-tester/public">
        AllowOverride All
        Require all granted
        DirectoryIndex index.php
    </Directory>
</VirtualHost>
```

### 4. PHP Requirements
- PHP 8.1+
- Extensions: `pdo_sqlite`, `curl`, `json`, `hash`, `openssl`
- All included in Laragon by default ✅

---

## Full Feature Set

### 🎯 Core Capture
| Feature | Detail |
|---------|--------|
| All HTTP methods | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE |
| Body capture | Up to 16MB, auto-parsed |
| Body formats | JSON (syntax highlighted), form-data, XML, binary |
| IP resolution | CF-Connecting-IP → X-Real-IP → X-Forwarded-For → REMOTE_ADDR |
| Realtime SSE | Per-endpoint + global stream, auto-reconnect |
| Request cap | 1000/endpoint (auto-purges oldest), configurable |

### 🛡 Security Engine (NEW)
| Feature | Detail |
|---------|--------|
| HMAC Signature | SHA-256/SHA-1/SHA-512 verification |
| IP Whitelisting | Exact IP + CIDR notation (e.g. 10.0.0.0/8) |
| IP Blacklisting | Block individual IPs or CIDR ranges |
| Method filtering | Whitelist allowed HTTP methods per endpoint |
| Auth enforcement | Bearer token, API Key header, Basic auth |
| Threat scoring | Heuristic analysis (SQLi, XSS, path traversal, bad UAs) |
| Rate limiting | 500 req/min sliding window per token |
| Security events | Full audit log of all blocked/suspicious activity |
| WAF rules | .htaccess-level XSS/GLOBALS attack blocking |

### 📊 Visualization (6 charts)
| Chart | Type | Data |
|-------|------|------|
| Requests/Hour | Bar | 24-hour hourly distribution |
| Method Distribution | Doughnut | HTTP method breakdown |
| 7-Day Traffic | Stacked bar | Requests + blocked overlay |
| Content Types | Horizontal bar | MIME type breakdown |
| Payload Sizes | Polar area | Body size buckets |
| Duration Trend | Line | Avg response time per day |
| Security Events | Doughnut | Event type breakdown |
| Security Timeline | Line | Events per hour (24h) |
| Live Activity | Bar (rolling) | Real-time 60s activity window |

### ⚡ Realtime Features
- SSE global feed + per-endpoint streams
- Live RPM counter (rolling 60-second window)
- Live threat/blocked counters
- Rolling 60-second activity bar chart
- Request list auto-prepends on new capture
- Endpoint sidebar counter increments live
- Auto-reconnect on connection drop

### 🔁 Request Operations
- **Replay** — re-fire to original or custom URL
- **Replay history** — full log with status/duration
- **Notes** — attach text notes per request
- **Tags** — multi-tag with add/remove
- **Star** — bookmark important requests
- **Delete** — individual request removal
- **Export** — 7 formats

### 📤 Code Export (7 formats)
`cURL` · `HTTPie` · `Python requests` · `Node.js fetch` · `PHP cURL` · `Go net/http` · `Raw JSON`

### 🔧 Endpoint Configuration
- Custom response status (200–503)
- Custom response body (JSON/text)
- Custom response headers
- Response delay (0–30,000ms)
- Response mode: Static | Forward (proxy)
- HMAC secret + algorithm
- IP allow/block lists
- Method whitelist
- Auth requirement (Bearer/API-Key/Basic)
- Max request cap
- Expiry timestamp
- Token regeneration

### 🔑 API Keys
- Create named API keys with permissions (read/write/admin)
- Key shown only once at creation
- SHA-256 hash stored (never raw key)
- Last-used tracking
- Expiry support

---

## REST API Reference

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/endpoints` | List all endpoints |
| POST | `/api/endpoints` | Create endpoint |
| PUT | `/api/endpoints/{id}` | Update endpoint |
| DELETE | `/api/endpoints/{id}` | Delete endpoint |
| GET | `/api/endpoints/stats` | Global stats + charts data |
| GET | `/api/endpoints/{id}/stats` | Per-endpoint analytics |
| POST | `/api/endpoints/{id}/pause` | Toggle pause |
| POST | `/api/endpoints/{id}/clear` | Clear all requests |
| POST | `/api/endpoints/{id}/regenerate` | New token |
| GET | `/api/endpoints/{id}/rules` | List rules |
| POST | `/api/endpoints/{id}/rules` | Create rule |
| GET | `/api/endpoints/{id}/security` | Security events |
| POST | `/api/endpoints/{id}/verify-signature` | Test HMAC sig |

### Requests
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/requests/{id}` | Get request or endpoint's requests |
| DELETE | `/api/requests/{id}` | Delete request |
| POST | `/api/requests/{id}/star` | Toggle star |
| POST | `/api/requests/{id}/note` | Update note |
| POST | `/api/requests/{id}/tags` | Update tags |
| POST | `/api/requests/{id}/replay` | Replay request |
| GET | `/api/requests/{id}/replay/history` | Replay history |
| GET | `/api/export/{id}?format=` | Export code |

### Security & Keys
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/security/stats` | Global security stats |
| GET | `/api/keys` | List API keys |
| POST | `/api/keys` | Create API key |
| DELETE | `/api/keys/{id}` | Delete API key |

### SSE Stream
| Path | Description |
|------|-------------|
| `GET /api/stream` | Global stream (all endpoints) |
| `GET /api/stream?endpoint_id=` | Per-endpoint stream |

### Webhook Capture
```
ANY /webhook/{token}
```
Captures all HTTP methods. Returns JSON by default or custom response.

---

## Keyboard Shortcuts
| Key | Action |
|-----|--------|
| `Ctrl+K` / `⌘K` | Focus endpoint search |
| `Esc` | Close modal |
| `N` | New endpoint (when not in input) |

---

## Database Schema (8 tables)
`endpoints` · `requests` · `rate_limits` · `security_events` · `webhook_rules` · `replay_history` · `api_keys` · (indexes)

SQLite with WAL mode, mmap 256MB, auto-created on first boot.
