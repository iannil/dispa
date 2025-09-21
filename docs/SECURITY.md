# 安全配置与防护

本节介绍 Dispa 的全局安全功能（对应 ROADMAP 4.1）。

功能概览
- 访问控制（IP 允许/拒绝列表，支持信任代理头）
- 简单认证（API Key / Bearer Token 静态列表 / JWT HS256 / JWT RS256）
- 全局限流（基于客户端 IP 的令牌桶）
- DDoS 基础防护（请求头数量/大小限制，最大请求体，是否要求 Content-Length）

配置示例（片段）：

```toml
[security]
enabled = true

[security.access_control]
allowed_ips = ["10.0.0.*", "127.0.0.1"]
dENIED_ips = ["192.168.1.13"]
trust_proxy_headers = true   # 信任 X-Forwarded-For 的第一个 IP

[security.auth] # 可选：静态 Key/Token 列表
enabled = true
mode = "apikey"              # apikey | bearer
header_name = "x-api-key"    # apikey 模式默认 x-api-key；bearer 模式默认 authorization
keys = ["k1", "k2"]          # 静态 Key/Token 列表

[security.jwt]  # 可选：JWT（目前支持 HS256）
enabled = true
algorithm = "HS256"         # HS256 | RS256
secret = "secret"
leeway_secs = 5
issuer = "me"
audience = "you"
cache_enabled = true

# RS256 额外选项（需启用 feature `jwt-rs256`）
# 静态 JWK（n,e 为 base64url），可配 kid 用于匹配 token header 的 kid
# security.jwt.rs256_keys = [ { kid = "k1", n = "...", e = "AQAB" } ]

# JWKS 拉取（需启用 feature `jwt-rs256-net`）
# security.jwt.jwks_url = "https://example.com/.well-known/jwks.json"
# security.jwt.jwks_cache_secs = 600

[security.rate_limit]
enabled = true
rate_per_sec = 100.0
burst = 200.0

[security.ddos]
max_headers = 128
max_header_bytes = 16384
max_body_bytes = 10485760     # 10MB
require_content_length = false
```

返回码
- 429 Too Many Requests：超出全局限流
- 431 Request Header Fields Too Large：请求头数量/大小超限
- 413 Payload Too Large / 411 Length Required：请求体超限或缺失 Content-Length（按配置）
- 403 Forbidden：访问控制拒绝
- 401 Unauthorized：认证失败（Bearer 模式带 WWW-Authenticate）

指标（metrics）
- 安全拒绝总数：`dispa_security_denied_total{kind}`
  - kind 取值包含：headers_len、headers_size、body_too_large、length_required、rate_limit、denied_ip、not_allowed_ip、auth_apikey、auth_bearer、auth_missing、jwt_invalid、body_stream_too_large
- 流式请求体统计（仅在启用流式限流包装时统计）：
  - `dispa_request_body_stream_chunks_total{limited}`：转发的 chunk 数；limited=true 表示启用了流式限流包装
  - `dispa_request_body_stream_bytes_total{limited}`：转发的累计字节

注意事项
- IP 匹配：支持精确匹配、`a.b.c.*` 通配、CIDR（IPv4/IPv6，如 `192.168.1.0/24`、`2001:db8::/32`）
- Bearer 模式：可选静态 Token 校验；如启用 JWT，建议配置 issuer/audience/有效期与 leeway。RS256 校验需开启相应 feature。
- 对于分块传输的请求体，当前仅基于 Content-Length 预检，流式限制将后续增强
- 每路由/全局插件链可与安全模块共同使用；安全检查最先执行
