# Dispa - Traffic Interception & Forwarding Proxy (User Manual)

Dispa is a high-performance proxy written in Rust. It intercepts traffic for specified domains, logs traffic, and forwards requests to multiple upstream targets with load balancing and health checks. It exposes Prometheus metrics and provides operational tooling.

- High-performance async architecture (Tokio + Hyper)
- Domain interception with exact and wildcard patterns
- Multiple load balancing strategies: round-robin, weighted, random, least-connections
- Active health checks and automatic failover
- File/DB traffic logging with rotation
- Prometheus metrics + Grafana ready
- Configuration via TOML with hot reload

## System Requirements

- OS: Linux, macOS, Windows
- Memory: 256MB+ recommended
- Disk: 100MB+ free
- Default ports: 8080 (proxy), 8081 (health), 9090 (metrics & admin)

## Quick Start

### Build from source

```bash
git clone <repository-url>
cd dispa

# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

cargo build --release
./target/release/dispa --help
```

### Docker

```bash
docker build -t dispa .
docker run -d --name dispa \
  -p 8080:8080 -p 8081:8081 -p 9090:9090 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/logs:/app/logs \
  dispa
```

## Configuration Guide

TOML file structure (see `config/config.toml`):

```toml
[server]
[domains]
[[targets.targets]]
[targets.load_balancing]
[targets.health_check]
[logging]
[monitoring]
# optional
[http_client]
[plugins]
[routing]
[tls]
[security]
```

Key sections
- server: `bind_address`, `workers`, `keep_alive_timeout`, `request_timeout`
- domains: `intercept_domains` (supports `*.example.com`), `exclude_domains`, `wildcard_support`
- targets: list of upstreams (`name`, `url`, `weight`, `timeout`)
- load_balancing: `type`: `roundrobin|weighted|random|leastconnections`, `sticky_sessions`
- health_check: `enabled`, `interval`, `timeout`, `healthy_threshold`, `unhealthy_threshold`
- logging: `type`: `file|database|both`, file/db sub-configs, `retention_days`
- monitoring: `metrics_port`, `health_check_port`, optional `histogram_buckets`
- http_client: upstream pool tuning: `pool_max_idle_per_host`, `pool_idle_timeout_secs`, `connect_timeout_secs`
- plugins: global plugin chain (see `docs/PLUGINS.md`)
- routing: advanced per-route matching and transformations
- tls: TLS server options (PEM cert/key paths, SNI, versions)
- security: access control, rate limiting, DDoS limits, optional JWT auth

### HTTP Client Pool (performance)

```toml
[http_client]
pool_max_idle_per_host = 32
pool_idle_timeout_secs = 90
connect_timeout_secs = 5
```

Environment overrides:
- `DISPA_HTTP_POOL_MAX_IDLE_PER_HOST`
- `DISPA_HTTP_POOL_IDLE_TIMEOUT_SECS`
- `DISPA_HTTP_CONNECT_TIMEOUT_SECS`

### Custom Prometheus Histogram Buckets

Configure finer buckets for latency metrics. Values are in milliseconds; metrics ending with `_seconds` will be converted (ms/1000).

```toml
[monitoring]
metrics_port = 9090
health_check_port = 8081

[[monitoring.histogram_buckets]]
metric = "dispa_log_write_duration_ms"
buckets_ms = [0.5, 1, 2, 5, 10, 20, 50, 100, 200]

[[monitoring.histogram_buckets]]
metric = "dispa_target_health_check_duration_ms"
buckets_ms = [5, 10, 25, 50, 100, 250, 500, 1000]

[[monitoring.histogram_buckets]]
metric = "dispa_request_duration_seconds" # still in ms here; auto-converted
buckets_ms = [1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000]
```

Defaults:
- log write (ms): `[0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]`
- health check (ms): `[1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]`
- request duration (s): `[0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]`

## Run & Manage

```bash
# default config
./target/release/dispa
# custom config
./target/release/dispa -c config/config.toml
# custom bind
./target/release/dispa -b 0.0.0.0:9000
# verbose logs
./target/release/dispa -v
```

Systemd example and Docker Compose are available in `docs/USER_MANUAL.md`.

## Endpoints & Monitoring

- Proxy: `:8080`
- Health API: `:8081/health`
- Metrics: `:9090/metrics`

Key metrics
- `dispa_requests_total`
- `dispa_request_duration_seconds`
- `dispa_target_healthy`
- `dispa_active_connections`

See `src/monitoring/metrics.rs` for additional series.

Ports overview

| Service | Port | Notes |
|---|---|---|
| Proxy | 8080 | HTTP/HTTPS proxy (TLS optional) |
| Health | 8081 | `/health` readiness/status |
| Metrics/Admin | 9090 | Prometheus `/metrics`, Admin UI `/admin` |

## Logs

- Structured logs via `tracing`
- Traffic logs to file/DB with rotation
- Tail: `tail -f logs/traffic-YYYY-MM-DD.log`

Traffic log (JSON) example when file logging is enabled:

```json
{
  "id": "uuid",
  "timestamp": "2024-01-01T12:00:00Z",
  "client_ip": "192.168.1.10",
  "host": "example.com",
  "target": "backend1",
  "status_code": 200,
  "duration_ms": 45
}
```

## Performance Tuning

- Increase file descriptors, kernel backlog; tune timeouts per workload
- Adjust worker threads (`server.workers`)
- Tune `http_client` pool

## Troubleshooting

- Port in use: change `bind_address` or stop conflicting process
- Backend unavailable: check `targets` status and connectivity
- Domain not intercepted: verify `intercept_domains` and `wildcard_support`
- DB errors: ensure `data/` exists or switch to file logging

## Best Practices

- Restrict health/metrics ports; run behind TLS-terminating LB
- Avoid logging secrets; rotate and protect log files
- Multi-instance HA behind a frontend LB
- Prometheus alerting rules for availability and error rate

## Plugins

See `docs/PLUGINS.md` for the full plugin system: built-ins, per-route chains, external command plugins, WASM (PoC), metrics, and troubleshooting. Build with features:
- `cmd-plugin` for external command plugins
- `wasm-plugin` for WASM plugins

## Environment Variables

Common overrides:
- `RUST_LOG`
- `DISPA_BIND_ADDRESS`, `DISPA_WORKERS`, `DISPA_REQUEST_TIMEOUT`
- `DISPA_METRICS_PORT`, `DISPA_HEALTH_CHECK_PORT`
- `DISPA_LOGGING_ENABLED`, `DISPA_LOGGING_TYPE`, `DISPA_LOG_DIRECTORY`
- `DISPA_HTTP_POOL_MAX_IDLE_PER_HOST`, `DISPA_HTTP_POOL_IDLE_TIMEOUT_SECS`, `DISPA_HTTP_CONNECT_TIMEOUT_SECS`

## Exit Codes & Signals

- Exit codes: `0` ok, `1` config error, `2` bind failure, `3` DB error
- Signals: `SIGTERM`/`SIGINT` graceful shutdown; `SIGUSR1` planned for reload

## Support

- Issues & discussions on GitHub
- See `docs/USER_MANUAL.md` for Docker/systemd and Chinese full manual.

---

## Run as a Systemd Service

Create `/etc/systemd/system/dispa.service`:

```ini
[Unit]
Description=Dispa Traffic Proxy
After=network.target

[Service]
Type=simple
User=dispa
Group=dispa
WorkingDirectory=/opt/dispa
ExecStart=/opt/dispa/dispa -c /opt/dispa/config/config.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/dispa/logs /opt/dispa/data

[Install]
WantedBy=multi-user.target
```

Bootstrap service:

```bash
sudo useradd -r -s /bin/false dispa
sudo mkdir -p /opt/dispa/{config,logs,data}
sudo chown -R dispa:dispa /opt/dispa
sudo cp target/release/dispa /opt/dispa/
sudo cp config/config.toml /opt/dispa/config/
sudo systemctl daemon-reload && sudo systemctl enable dispa && sudo systemctl start dispa
sudo systemctl status dispa
```

## Docker Compose

```yaml
version: '3.8'
services:
  dispa:
    build: .
    container_name: dispa
    restart: unless-stopped
    ports:
      - "8080:8080"  # proxy
      - "8081:8081"  # health
      - "9090:9090"  # metrics (and /admin)
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
      - ./data:/app/data
    environment:
      - RUST_LOG=info
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Additional Performance Tuning

System-level hints:

```bash
# Larger file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Linux TCP backlog tuning
echo "net.core.somaxconn = 65536" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" | sudo tee -a /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 65536" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Application config hints:

```toml
[server]
workers = 8                # match CPU cores
keep_alive_timeout = 120   # workload dependent
request_timeout = 60       # align with upstream SLAs

[targets.health_check]
interval = 15              # faster failover
timeout = 5
```

## Troubleshooting (Extended)

- Port in use
  - Check: `sudo lsof -i :8080` or `netstat -tlnp | grep :8080`
  - Fix: change `server.bind_address` or stop the conflicting process

- Backend unavailable
  - Check upstream: `curl -I http://<backend-host>:<port>/`
  - Check health logs and connectivity: `ping`, `telnet <host> <port>`

- Domain not intercepted
  - Verify config: `intercept_domains`, `exclude_domains`, `wildcard_support`
  - Verify request Host header: `curl -v -H "Host: example.com" http://localhost:8080/`

- Database connection failed
  - Ensure `data/` exists and has proper permissions
  - Switch to file logging: `logging.type = "file"`

- Memory pressure
  - Reduce DB connections, enable log rotation, lower health check frequency

## Debugging Tips

- Verbose logs

```bash
./target/release/dispa -c config/config.toml -v
# or
RUST_LOG=debug ./target/release/dispa -c config/config.toml
```

- Packet capture

```bash
sudo tcpdump -i any -w dispa.pcap port 8080
wireshark dispa.pcap
```

- Runtime inspection

```bash
strace -p <pid> -e network
htop -p <pid>
```

## Best Practices (Alerts & Admin UI)

- Restrict access to `:8081` and `:9090`; prefer running behind a TLS-terminating LB
- Avoid logging secrets; rotate and protect log files; set secure permissions
- Multi-instance HA: run multiple dispa instances and front with Nginx/Envoy/HAProxy

Prometheus alert examples:

```yaml
groups:
- name: dispa
  rules:
  - alert: DispaDown
    expr: up{job="dispa"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Dispa instance is down"

  - alert: DispaHighErrorRate
    expr: rate(dispa_requests_errors_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High error rate in Dispa"
```

Admin UI:
- Served on the metrics port (`/admin` under `:9090` by default)
- Tokens (env): `DISPA_ADMIN_TOKEN` (admin), `DISPA_EDITOR_TOKEN` (editor), `DISPA_VIEWER_TOKEN` (viewer)
- Also supports reusing `security.auth` (API key or Bearer) as fallback auth
- Harden access with firewall and reverse proxy; audit log at `logs/admin_audit.log`

## High Availability

Run multiple instances on different ports and front them with a load balancer (e.g., Nginx):

```bash
./dispa -c config/config.toml -b 0.0.0.0:8080 &
./dispa -c config/config.toml -b 0.0.0.0:8082 &
```

Nginx upstream example:

```nginx
upstream dispa_backend {
    server 127.0.0.1:8080;
    server 127.0.0.1:8082;
}

server {
    listen 80;
    server_name proxy.example.com;
    location / { proxy_pass http://dispa_backend; }
}
```

## Additional Environment Variables

- Admin UI: `DISPA_ADMIN_TOKEN`, `DISPA_EDITOR_TOKEN`, `DISPA_VIEWER_TOKEN`
