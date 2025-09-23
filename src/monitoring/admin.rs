use hyper::{Body, Method, Request, Response, StatusCode};
use once_cell::sync::OnceCell;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

use crate::balancer::LoadBalancer;
use crate::config::Config;
use crate::config::DomainConfig;
use crate::plugins::SharedPluginEngine;
use crate::routing::RoutingEngine;
use crate::security::SharedSecurity;

static ADMIN_STATE: OnceCell<AdminState> = OnceCell::new();
static ADMIN_TOKEN: OnceCell<Option<String>> = OnceCell::new();

pub struct AdminState {
    pub config_path: PathBuf,
    pub domain_config: std::sync::Arc<std::sync::RwLock<DomainConfig>>,
    pub load_balancer: Arc<RwLock<LoadBalancer>>,
    pub routing_engine: Arc<RwLock<Option<RoutingEngine>>>,
    pub plugins: SharedPluginEngine,
    pub security: SharedSecurity,
}

pub fn init_admin(state: AdminState) {
    let _ = ADMIN_STATE.set(state);
    let _ = ADMIN_TOKEN.set(std::env::var("DISPA_ADMIN_TOKEN").ok());
}

pub async fn handle_admin(req: Request<Body>) -> Result<Response<Body>, hyper::http::Error> {
    let path = req.uri().path();
    match (req.method(), path) {
        (&Method::GET, "/admin") | (&Method::GET, "/admin/") => ok_html(index_html()),
        (&Method::GET, "/admin/status") => {
            if !authorized(&req).await {
                return unauthorized();
            }
            let role = role_of(&req).await;
            ok_json(status_json_with_role(role).await)
        }
        (&Method::GET, "/admin/config") => {
            if !authorized(&req).await {
                return unauthorized();
            }
            // editor/admin allowed
            config_get().await
        }
        (&Method::POST, "/admin/config") | (&Method::PUT, "/admin/config") => {
            // only admin allowed
            let role = role_of(&req).await.unwrap_or_default();
            if role != "admin" {
                return unauthorized();
            }
            config_set(req).await
        }
        (&Method::GET, "/admin/config/json") => {
            if !authorized(&req).await {
                return unauthorized();
            }
            config_get_json().await
        }
        (&Method::POST, "/admin/config/json") | (&Method::PUT, "/admin/config/json") => {
            // editor/admin allowed; viewer denied
            let role = role_of(&req).await.unwrap_or_default();
            if role == "admin" || role == "editor" {
                config_set_json(req).await
            } else {
                unauthorized()
            }
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found")),
    }
}

fn ok_html(body: String) -> Result<Response<Body>, hyper::http::Error> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(body))
}

fn ok_json<T: Serialize>(val: T) -> Result<Response<Body>, hyper::http::Error> {
    let body = serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body))
}

fn unauthorized<T>() -> Result<Response<Body>, T> {
    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Bearer, Basic, X-Admin-Token")
        .body(Body::from("Unauthorized"))
        .unwrap())
}

async fn config_get() -> Result<Response<Body>, hyper::http::Error> {
    if let Some(state) = ADMIN_STATE.get() {
        match tokio::fs::read_to_string(&state.config_path).await {
            Ok(mut content) => {
                // naive redaction: mask `secret = "..."` in jwt section
                content = redact_secrets(&content);
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain; charset=utf-8")
                    .body(Body::from(content))
            }
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to read config")),
        }
    } else {
        Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::from("Admin state not initialized"))
    }
}

async fn config_set(mut req: Request<Body>) -> Result<Response<Body>, hyper::http::Error> {
    use hyper::body::to_bytes;
    if let Some(state) = ADMIN_STATE.get() {
        let bytes = to_bytes(req.body_mut()).await.unwrap_or_default();
        if bytes.is_empty() {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Empty body"));
        }
        // Best-effort: Write to config file path; file watcher will reload
        let ok = tokio::fs::write(&state.config_path, &bytes).await.is_ok();
        audit(&req, ok, bytes.len(), "/admin/config").await;
        if ok {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("OK"))
        } else {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to write config"))
        }
    } else {
        Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::from("Admin state not initialized"))
    }
}

async fn config_get_json() -> Result<Response<Body>, hyper::http::Error> {
    if let Some(state) = ADMIN_STATE.get() {
        match tokio::fs::read_to_string(&state.config_path).await {
            Ok(content) => {
                if let Ok(cfg) = toml::from_str::<Config>(&content) {
                    let obj = serde_json::json!({
                        "routing": cfg.routing,
                        "plugins": cfg.plugins,
                        "security": cfg.security,
                    });
                    return ok_json(obj);
                }
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Invalid config"))
            }
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to read config")),
        }
    } else {
        Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::from("Admin state not initialized"))
    }
}

async fn config_set_json(mut req: Request<Body>) -> Result<Response<Body>, hyper::http::Error> {
    use hyper::body::to_bytes;
    if let Some(state) = ADMIN_STATE.get() {
        let bytes = to_bytes(req.body_mut()).await.unwrap_or_default();
        if bytes.is_empty() {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Empty body"));
        }
        match tokio::fs::read_to_string(&state.config_path).await {
            Ok(content) => {
                match toml::from_str::<Config>(&content) {
                    Ok(mut cfg) => {
                        if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            if let Some(routing) = v.get_mut("routing") {
                                cfg.routing = serde_json::from_value(routing.take()).ok();
                            }
                            if let Some(plugins) = v.get_mut("plugins") {
                                cfg.plugins = serde_json::from_value(plugins.take()).ok();
                            }
                            // Merge security section partially if provided
                            if let Some(security) = v.get_mut("security") {
                                if let Some(obj) = security.as_object() {
                                    if let Some(existing) = cfg.security.clone() {
                                        let mut merged = existing;
                                        if let Some(rl_val) = obj.get("rate_limit") {
                                            merged.rate_limit =
                                                serde_json::from_value(rl_val.clone()).ok();
                                        }
                                        if let Some(enabled_val) = obj.get("enabled") {
                                            if let Some(b) = enabled_val.as_bool() {
                                                merged.enabled = b;
                                            }
                                        }
                                        cfg.security = Some(merged);
                                    } else {
                                        // Try to parse full security object if complete
                                        if let Ok(parsed) = serde_json::from_value::<
                                            crate::security::SecurityConfig,
                                        >(
                                            security.clone()
                                        ) {
                                            cfg.security = Some(parsed);
                                        }
                                    }
                                }
                                let _ = security.take();
                            }
                            let toml_str =
                                toml::to_string_pretty(&cfg).unwrap_or_else(|_| content.clone());
                            let ok = tokio::fs::write(&state.config_path, toml_str).await.is_ok();
                            audit(&req, ok, bytes.len(), "/admin/config/json").await;
                            if ok {
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Body::from("OK"))
                            } else {
                                Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from("Failed to write config"))
                            }
                        } else {
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from("Invalid JSON"))
                        }
                    }
                    Err(_) => Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Invalid config")),
                }
            }
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to read config")),
        }
    } else {
        Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::from("Admin state not initialized"))
    }
}

async fn status_json_with_role(role: Option<String>) -> serde_json::Value {
    if let Some(state) = ADMIN_STATE.get() {
        let domains = state.domain_config.read().unwrap().intercept_domains.len();
        let exclude_domains = state
            .domain_config
            .read()
            .unwrap()
            .exclude_domains
            .as_ref()
            .map(|v| v.len())
            .unwrap_or(0);
        let summary = state.load_balancer.read().await.get_summary().await;
        let targets = summary.total_targets;
        let routing_enabled = state.routing_engine.read().await.is_some();
        let plugins_enabled = state.plugins.read().await.is_some();
        let security_enabled = state.security.read().await.is_some();
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "domains": domains,
            "exclude_domains": exclude_domains,
            "targets": targets,
            "routing_enabled": routing_enabled,
            "plugins_enabled": plugins_enabled,
            "security_enabled": security_enabled,
            "config_path": state.config_path.to_string_lossy().to_string(),
            "role": role.unwrap_or_else(|| "viewer".to_string())
        })
    } else {
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "domains": 0,
            "exclude_domains": 0,
            "targets": 0,
            "routing_enabled": false,
            "plugins_enabled": false,
            "security_enabled": false,
            "config_path": "",
            "role": role.unwrap_or_else(|| "viewer".to_string())
        })
    }
}

fn index_html() -> String {
    let html = r#"<!doctype html>
<html><head><meta charset='utf-8'><title>Dispa Admin</title>
<style>body{font-family:system-ui,Arial;margin:20px}pre{background:#f7f7f7;padding:12px;overflow:auto}section{margin-bottom:24px}code{background:#f0f0f0;padding:2px 4px;border-radius:3px}</style>
</head><body>
<h1>Dispa 管理界面</h1>
<section>
  <h2>系统状态</h2>
  <div>Admin Token: <input id='admintoken' placeholder='留空=不校验' style='width:240px'/> <button onclick='saveToken()'>保存</button></div>
  <div id='status'>Loading...</div>
</section>
<section>
  <h2>监控面板（简要）</h2>
  <div>
    <label><input type='checkbox' id='show_req' checked/> 请求</label>
    <label><input type='checkbox' id='show_err' checked/> 错误</label>
    <label><input type='checkbox' id='show_healthy' checked/> 健康目标</label>
    <label><input type='checkbox' id='show_conn'/> 活跃连接</label>
    <label><input type='checkbox' id='show_err_rate'/> 错误率</label>
    窗口：<input type='range' id='window' min='20' max='300' value='60' style='vertical-align:middle'/> <span id='winval'>60</span>
  </div>
  <div>请求总数：<span id='req_total'>-</span>，错误总数：<span id='err_total'>-</span>，健康目标：<span id='healthy'>-</span>/<span id='targets'>-</span></div>
  <div style='position:relative;width:600px;height:180px'>
    <canvas id='chart' width='600' height='160' style='border:1px solid #ddd'></canvas>
    <div id='tooltip' style='position:absolute;display:none;background:#333;color:#fff;padding:2px 6px;border-radius:3px;font-size:12px'></div>
  </div>
</section>
<section>
  <h2>配置管理</h2>
  <button id='btn_load_cfg' onclick='loadConfig()'>加载配置</button>
  <button id='btn_save_cfg' onclick='saveConfig()'>保存配置</button>
  <div><small>直接编辑下方文本区域，点击保存将写入配置文件，并通过热重载生效。</small></div>
  <pre><textarea id='cfg' style='width:100%;height:320px'></textarea></pre>
  <div id='cfg_msg'></div>
</section>
<section>
  <h2>路由 / 插件 / 安全（JSON 部分编辑）</h2>
  <button id='btn_load_sections' onclick='loadSections()'>加载分区</button>
  <button id='btn_save_sections' onclick='saveSections()'>保存分区</button>
  <div style='display:flex;gap:12px'>
    <div style='flex:1'>
      <h3>Routing</h3>
      <div id='routing_rules'></div>
      <textarea id='routing' style='width:100%;height:200px'></textarea>
    </div>
    <div style='flex:1'>
      <h3>Plugins</h3>
      <label><input type='checkbox' id='plugins_enabled'/> 启用插件</label>
      <label><input type='checkbox' id='plugins_before'/> 请求插件优先于域名检查</label>
      <textarea id='plugins' style='width:100%;height:200px'></textarea>
    </div>
    <div style='flex:1'>
      <h3>Security</h3>
      <label><input type='checkbox' id='rl_enabled'/> 全局限流</label>
      速率：<input type='number' id='rl_rate' step='1' min='0' style='width:80px'/>/s
      峰值：<input type='number' id='rl_burst' step='1' min='0' style='width:80px'/>
      <textarea id='security' style='width:100%;height:200px'></textarea>
    </div>
  </div>
</section>
<script>
let token = localStorage.getItem('admin_token')||'';
document.addEventListener('DOMContentLoaded', ()=>{ document.getElementById('admintoken').value = token; });
function saveToken(){ token = document.getElementById('admintoken').value; localStorage.setItem('admin_token', token); }
function authHeaders(){ const h={}; if(token) h['x-admin-token']=token; return h; }
async function refresh(){
  const s = await fetch('/admin/status',{headers:authHeaders()}).then(r=>r.json());
  document.getElementById('status').innerText = `版本 ${s.version} | 域名 ${s.domains}（排除 ${s.exclude_domains}）| 目标 ${s.targets} | 路由 ${s.routing_enabled} | 插件 ${s.plugins_enabled} | 安全 ${s.security_enabled} | 配置文件 ${s.config_path}`;
  applyRole(s.role||'viewer');
  const m = await fetch('/metrics/json').then(r=>r.json());
  document.getElementById('req_total').innerText = m.requests_total;
  document.getElementById('err_total').innerText = m.errors_total;
  document.getElementById('targets').innerText = m.targets_total;
  document.getElementById('healthy').innerText = m.targets_healthy;
  pushPoint(m.requests_total, m.errors_total, m.targets_healthy, m.connections_active, m.error_rate);
}
async function loadConfig(){
  const t = await fetch('/admin/config',{headers:authHeaders()}).then(r=>r.text());
  document.getElementById('cfg').value = t;
}
async function saveConfig(){
  const v = document.getElementById('cfg').value;
  const res = await fetch('/admin/config', {method:'POST', headers:authHeaders(), body: v});
  document.getElementById('cfg_msg').innerText = res.ok ? '保存成功（将自动热重载）' : '保存失败';
}
async function loadSections(){
  const j = await fetch('/admin/config/json',{headers:authHeaders()}).then(r=>r.json());
  document.getElementById('routing').value = JSON.stringify(j.routing, null, 2);
  document.getElementById('plugins').value = JSON.stringify(j.plugins, null, 2);
  document.getElementById('security').value = JSON.stringify(j.security, null, 2);
  // 控件映射
  if(j.plugins){ document.getElementById('plugins_enabled').checked = !!j.plugins.enabled; document.getElementById('plugins_before').checked = !!(j.plugins.apply_before_domain_match); }
  if(j.security && j.security.rate_limit){ document.getElementById('rl_enabled').checked = !!j.security.rate_limit.enabled; document.getElementById('rl_rate').value = j.security.rate_limit.rate_per_sec||0; document.getElementById('rl_burst').value = j.security.rate_limit.burst||0; }
  renderRoutingRules();
}
async function saveSections(){
  const routing = document.getElementById('routing').value;
  const plugins = document.getElementById('plugins').value;
  const security = document.getElementById('security').value;
  // 应用控件到 JSON
  let p = plugins?JSON.parse(plugins):null; if(p){ p.enabled = document.getElementById('plugins_enabled').checked; p.apply_before_domain_match = document.getElementById('plugins_before').checked; }
  let s = security?JSON.parse(security):null; if(s){ if(!s.rate_limit) s.rate_limit = {}; s.rate_limit.enabled = document.getElementById('rl_enabled').checked; s.rate_limit.rate_per_sec = parseFloat(document.getElementById('rl_rate').value||'0'); s.rate_limit.burst = parseFloat(document.getElementById('rl_burst').value||'0'); }
  const body = JSON.stringify({ routing: routing?JSON.parse(routing):null, plugins: p, security: s });
  const res = await fetch('/admin/config/json',{method:'POST', headers:Object.assign({'content-type':'application/json'},authHeaders()), body});
  alert(res.ok?'保存成功（将自动热重载）':'保存失败');
}
function renderRoutingRules(){ const box=document.getElementById('routing_rules'); box.innerHTML=''; let rtxt=document.getElementById('routing').value; if(!rtxt){ box.innerText='（空）'; return; } let obj; try{ obj=JSON.parse(rtxt);}catch(_){ box.innerText='（JSON 无法解析）'; return;} if(!obj||!obj.rules){ box.innerText='（无规则）'; return;} const addBtn=document.createElement('button'); addBtn.textContent='新增规则'; addBtn.onclick=()=>{ obj.rules.push({name:'rule-'+Date.now(), priority:100, enabled:true, target:'default', conditions:{}, actions:{}, plugins_order:'as_listed', plugins_dedup:false}); document.getElementById('routing').value=JSON.stringify(obj,null,2); renderRoutingRules(); }; box.appendChild(addBtn); const tbl=document.createElement('table'); tbl.style.width='100%'; tbl.style.fontSize='12px'; const head=document.createElement('tr'); head.innerHTML='<th>名称</th><th>优先级</th><th>目标</th><th>启用</th><th>插件排序</th><th>去重</th><th>操作</th>'; tbl.appendChild(head); obj.rules.forEach((rule,idx)=>{ const tr=document.createElement('tr'); const name=document.createElement('input'); name.value=rule.name||''; name.onchange=()=>{ rule.name=name.value; updateRouting(obj); }; const pri=document.createElement('input'); pri.type='number'; pri.style.width='70px'; pri.value=rule.priority||0; pri.onchange=()=>{ rule.priority=parseInt(pri.value||'0'); updateRouting(obj); }; const tgt=document.createElement('input'); tgt.value=rule.target||''; tgt.onchange=()=>{ rule.target=tgt.value; updateRouting(obj); }; const ena=document.createElement('input'); ena.type='checkbox'; ena.checked=!!rule.enabled; ena.onchange=()=>{ rule.enabled=ena.checked; updateRouting(obj); }; const order=document.createElement('select'); ['as_listed','name_asc','name_desc'].forEach(v=>{ const o=document.createElement('option'); o.value=v; o.textContent=v; if((rule.plugins_order||'as_listed')===camel(v)) o.selected=true; order.appendChild(o); }); order.onchange=()=>{ rule.plugins_order = toEnum(order.value); updateRouting(obj); }; const dedup=document.createElement('input'); dedup.type='checkbox'; dedup.checked=!!rule.plugins_dedup; dedup.onchange=()=>{ rule.plugins_dedup=dedup.checked; updateRouting(obj); }; const del=document.createElement('button'); del.textContent='删除'; del.onclick=()=>{ obj.rules.splice(idx,1); updateRouting(obj); renderRoutingRules(); }; const td=(el)=>{ const td=document.createElement('td'); td.appendChild(el); return td; }; tr.appendChild(td(name)); tr.appendChild(td(pri)); tr.appendChild(td(tgt)); tr.appendChild(td(ena)); tr.appendChild(td(order)); tr.appendChild(td(dedup)); tr.appendChild(td(del)); tbl.appendChild(tr); }); box.appendChild(tbl); }
function updateRouting(obj){ document.getElementById('routing').value=JSON.stringify(obj,null,2); }
function camel(s){ return s.replace(/_([a-z])/g,(_,c)=>c.toUpperCase()); }
function toEnum(v){ if(v==='as_listed') return 'AsListed'; if(v==='name_asc') return 'NameAsc'; if(v==='name_desc') return 'NameDesc'; return 'AsListed'; }
// 简易趋势图（可切换系列 + 窗口 + tooltip）
const data={req:[],err:[],healthy:[],conn:[],err_rate:[],max:60};
document.getElementById('window').addEventListener('input',e=>{ data.max=parseInt(e.target.value); document.getElementById('winval').innerText=data.max; draw();});
['show_req','show_err','show_healthy','show_conn','show_err_rate'].forEach(id=>{ document.getElementById(id).addEventListener('change',draw); });
function pushPoint(req,err,healthy,conn,err_rate){ data.req.push(req); data.err.push(err); data.healthy.push(healthy); data.conn.push(conn||0); data.err_rate.push((err_rate||0)*100); for(const k of Object.keys(data)){ if(k!=='max'){ if(data[k].length>data.max) data[k].shift(); }} draw(); }
function draw(){ const c=document.getElementById('chart'); const ctx=c.getContext('2d'); ctx.clearRect(0,0,c.width,c.height); const pad=20; const w=c.width-2*pad; const h=c.height-2*pad; const series=[]; if(document.getElementById('show_req').checked) series.push(['req','#2a7']); if(document.getElementById('show_err').checked) series.push(['err','#e55']); if(document.getElementById('show_healthy').checked) series.push(['healthy','#27c']); if(document.getElementById('show_conn').checked) series.push(['conn','#b80']); if(document.getElementById('show_err_rate').checked) series.push(['err_rate','#a3a']); const maxY=Math.max(1, ...series.flatMap(s=>data[s[0]])); const scale = (v)=> pad + h - (v/maxY)*h; const step= data.max>1 ? w/(data.max-1): w; series.forEach(([key,color])=>{ ctx.beginPath(); data[key].forEach((v,i)=>{ const x=pad + i*step; const y=scale(v); if(i) ctx.lineTo(x,y); else ctx.moveTo(x,y); }); ctx.strokeStyle=color; ctx.stroke(); }); drawAxes(ctx,pad,w,h,maxY); }
function drawAxes(ctx,pad,w,h,maxY){ ctx.strokeStyle='#ccc'; ctx.beginPath(); ctx.moveTo(pad,pad); ctx.lineTo(pad,pad+h); ctx.lineTo(pad+w,pad+h); ctx.stroke(); ctx.fillStyle='#666'; ctx.fillText('0', 2, pad+h); ctx.fillText(String(Math.round(maxY)), 2, pad); }
// tooltip
const chart=document.getElementById('chart'); const tip=document.getElementById('tooltip'); chart.addEventListener('mousemove',evt=>{ const rect=chart.getBoundingClientRect(); const x=evt.clientX-rect.left; const pad=20; const w=chart.width-2*pad; const idx=Math.round(((x-pad)/w)*(data.max-1)); if(idx>=0 && idx<data.req.length){ tip.style.display='block'; tip.style.left=(evt.clientX-rect.left+8)+'px'; tip.style.top=(evt.clientY-rect.top+8)+'px'; tip.innerText=`#${idx} req:${data.req[idx]||0} err:${data.err[idx]||0} ok:${data.healthy[idx]||0} conn:${data.conn[idx]||0} err%:${(data.err_rate[idx]||0).toFixed(2)}`; } else { tip.style.display='none'; } }); chart.addEventListener('mouseleave',()=>{ tip.style.display='none'; });

function applyRole(role){ const v = (id, ena)=>{ const el=document.getElementById(id); if(!el) return; el.disabled = !ena; if(!ena) el.classList.add('disabled'); else el.classList.remove('disabled'); };
  if(role==='admin'){ v('btn_save_cfg', true); v('btn_save_sections', true); }
  else if(role==='editor'){ v('btn_save_cfg', false); v('btn_save_sections', true); }
  else { v('btn_save_cfg', false); v('btn_save_sections', false); }
}
setInterval(refresh, 3000);refresh();
</script>
</body></html>"#;
    html.to_string()
}

fn redact_secrets(s: &str) -> String {
    // very naive: replace lines containing `secret = "..."`
    s.lines()
        .map(|line| {
            if line.trim_start().starts_with("secret = ") {
                "secret = \"***\"".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn audit(req: &Request<Body>, ok: bool, bytes: usize, path: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let remote = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into());
    let role = role_of(req).await.unwrap_or_else(|| "unknown".into());
    let line = format!(
        "{} method={} path={} ok={} bytes={} ip={} role={}\n",
        now,
        req.method(),
        path,
        ok,
        bytes,
        remote,
        role
    );
    // write to logs/admin_audit.log
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/admin_audit.log")
        .await
    {
        let _ = f.write_all(line.as_bytes()).await;
    }
    if ok {
        tracing::info!(target: "admin_audit", %remote, %path, %role, bytes=bytes, "admin write ok");
    } else {
        tracing::warn!(target: "admin_audit", %remote, %path, %role, bytes=bytes, "admin write failed");
    }
}

async fn role_of(req: &Request<Body>) -> Option<String> {
    if let Some(Some(tok)) = ADMIN_TOKEN.get() {
        if has_token(req, tok) {
            return Some("admin".into());
        }
    }
    if let Ok(v) = std::env::var("DISPA_EDITOR_TOKEN") {
        if has_token(req, &v) {
            return Some("editor".into());
        }
    }
    if let Ok(v) = std::env::var("DISPA_VIEWER_TOKEN") {
        if has_token(req, &v) {
            return Some("viewer".into());
        }
    }
    // Fallback: map security.auth keys to editor role (write JSON) if present
    if let Some(state) = ADMIN_STATE.get() {
        if let Ok(content) = tokio::fs::read_to_string(&state.config_path).await {
            if let Ok(cfg) = toml::from_str::<Config>(&content) {
                if let Some(auth) = cfg.security.and_then(|s| s.auth) {
                    match auth.mode {
                        crate::security::AuthMode::ApiKey => {
                            if let Some(name) = auth.header_name {
                                if let Some(h) = req.headers().get(name) {
                                    if let Ok(v) = h.to_str() {
                                        if auth.keys.iter().any(|k| k == v) {
                                            return Some("editor".into());
                                        }
                                    }
                                }
                            }
                        }
                        crate::security::AuthMode::Bearer => {
                            if let Some(h) = req.headers().get("authorization") {
                                if let Ok(v) = h.to_str() {
                                    if let Some(tok) = v
                                        .strip_prefix("Bearer ")
                                        .or_else(|| v.strip_prefix("bearer "))
                                    {
                                        if auth.keys.iter().any(|k| k == tok) {
                                            return Some("editor".into());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

async fn authorized(req: &Request<Body>) -> bool {
    // Accept any known role token for authorization; role-based checks
    // (admin/editor/viewer) are applied per-endpoint.
    if let Some(Some(tok)) = ADMIN_TOKEN.get() {
        if has_token(req, tok) {
            return true;
        }
    }
    if let Ok(v) = std::env::var("DISPA_EDITOR_TOKEN") {
        if has_token(req, &v) {
            return true;
        }
    }
    if let Ok(v) = std::env::var("DISPA_VIEWER_TOKEN") {
        if has_token(req, &v) {
            return true;
        }
    }

    // Fallback: reuse security.auth if present in config
    if let Some(state) = ADMIN_STATE.get() {
        if let Ok(content) = tokio::fs::read_to_string(&state.config_path).await {
            if let Ok(cfg) = toml::from_str::<Config>(&content) {
                if let Some(auth) = cfg.security.and_then(|s| s.auth) {
                    match auth.mode {
                        crate::security::AuthMode::ApiKey => {
                            if let Some(name) = auth.header_name {
                                if let Some(h) = req.headers().get(name) {
                                    if let Ok(v) = h.to_str() {
                                        if auth.keys.iter().any(|k| k == v) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                        crate::security::AuthMode::Bearer => {
                            if let Some(h) = req.headers().get("authorization") {
                                if let Ok(v) = h.to_str() {
                                    if let Some(tok) = v
                                        .strip_prefix("Bearer ")
                                        .or_else(|| v.strip_prefix("bearer "))
                                    {
                                        if auth.keys.iter().any(|k| k == tok) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

fn has_token(req: &Request<Body>, tok: &str) -> bool {
    // Header x-admin-token takes precedence
    if let Some(h) = req.headers().get("x-admin-token") {
        if let Ok(v) = h.to_str() {
            if v == tok {
                return true;
            }
        }
    }
    // Authorization: Bearer/Basic
    if let Some(h) = req.headers().get("authorization") {
        if let Ok(v) = h.to_str() {
            if let Some(b) = v
                .strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
            {
                if b == tok {
                    return true;
                }
            } else if let Some(b64) = v.strip_prefix("Basic ") {
                // very naive basic: expecting admin:token
                if let Ok(decoded) = basic_decode(b64) {
                    if decoded.ends_with(&format!(":{}", tok)) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn basic_decode(s: &str) -> Result<String, ()> {
    // Minimal base64 decoder (standard alphabet with padding)
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(64),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let a = val(bytes[i]).ok_or(())?;
        let b = val(bytes[i + 1]).ok_or(())?;
        let c = val(bytes[i + 2]).ok_or(())?;
        let d = val(bytes[i + 3]).ok_or(())?;
        i += 4;
        if a == 64 || b == 64 {
            return Err(());
        }
        let n = ((a as u32) << 18)
            | ((b as u32) << 12)
            | (if c == 64 { 0 } else { (c as u32) << 6 })
            | (if d == 64 { 0 } else { d as u32 });
        out.push(((n >> 16) & 0xFF) as u8);
        if c != 64 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if d != 64 {
            out.push((n & 0xFF) as u8);
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Body;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_admin_rbac_and_config_json_merge() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        // Prepare temp config file
        let mut cfg = crate::config::Config {
            server: crate::config::ServerConfig {
                bind: "127.0.0.1:8080".parse().unwrap(),
                workers: Some(2),
                max_connections: Some(1000),
                connection_timeout: Some(30),
            },
            domains: crate::config::DomainConfig {
                intercept_domains: vec!["example.com".to_string()],
                exclude_domains: None,
                wildcard_support: true,
            },
            targets: crate::config::TargetConfig {
                targets: vec![],
                load_balancing: crate::config::LoadBalancingConfig {
                    algorithm: crate::config::LoadBalancingType::RoundRobin,
                    lb_type: crate::config::LoadBalancingType::RoundRobin,
                    sticky_sessions: Some(false),
                },
                health_check: crate::config::HealthCheckConfig {
                    enabled: false,
                    interval: 30,
                    timeout: 10,
                    healthy_threshold: 2,
                    unhealthy_threshold: 3,
                    threshold: 2,
                },
            },
            logging: crate::config::LoggingConfig {
                enabled: false,
                log_type: crate::config::LoggingType::File,
                database: None,
                file: None,
                retention_days: None,
            },
            monitoring: crate::config::MonitoringConfig::default(),
            tls: None,
            routing: None,
            cache: None,
            http_client: None,
            plugins: None,
            security: None,
        };
        // Add security section for redaction test
        cfg.security = Some(crate::security::SecurityConfig{ enabled: true, access_control: None, auth: None, rate_limit: Some(crate::security::GlobalRateLimitConfig{ enabled: false, rate_per_sec: 0.0, burst: 0.0 }), ddos: None, jwt: Some(crate::security::JwtConfig{ enabled: true, algorithm: "HS256".into(), secret: Some("s3cr3t".into()), leeway_secs: Some(0), issuer: None, audience: None, cache_enabled: Some(true), rs256_keys: None, jwks_url: None, jwks_cache_secs: None }) });
        let mut temp = NamedTempFile::new().unwrap();
        write!(temp, "{}", toml::to_string_pretty(&cfg).unwrap()).unwrap();

        // Build admin state
        let domain = std::sync::Arc::new(std::sync::RwLock::new(crate::config::DomainConfig{ intercept_domains: vec!["example.com".into()], exclude_domains: None, wildcard_support: true }));
        let lb_cfg = crate::config::TargetConfig{ targets: vec![], load_balancing: crate::config::LoadBalancingConfig{ algorithm: crate::config::LoadBalancingType::RoundRobin, lb_type: crate::config::LoadBalancingType::RoundRobin, sticky_sessions: Some(false) }, health_check: crate::config::HealthCheckConfig{ enabled:false, interval:30, timeout:10, healthy_threshold:2, unhealthy_threshold:3, threshold: 2 } };
        let lb = std::sync::Arc::new(tokio::sync::RwLock::new(crate::balancer::LoadBalancer::new_for_test(lb_cfg)));
        let routing = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        let plugins = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        let security = std::sync::Arc::new(tokio::sync::RwLock::new(None));

        // Set admin/editor tokens and init
        std::env::set_var("DISPA_ADMIN_TOKEN", "adm");
        std::env::set_var("DISPA_EDITOR_TOKEN", "ed");
        let _ = super::init_admin(super::AdminState{ config_path: temp.path().to_path_buf(), domain_config: domain, load_balancer: lb, routing_engine: routing, plugins, security });

        // 1) GET /admin/status with admin token
        let req = Request::builder().method("GET").uri("/admin/status").header("x-admin-token","adm").body(Body::empty()).unwrap();
        let resp = super::handle_admin(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.get("role").and_then(|x| x.as_str()).unwrap_or("") , "admin");

        // 2) GET /admin/config with admin token -> redacted secret
        let req = Request::builder().method("GET").uri("/admin/config").header("x-admin-token","adm").body(Body::empty()).unwrap();
        let resp = super::handle_admin(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let txt = String::from_utf8(hyper::body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();
        assert!(txt.lines().any(|l| l.trim_start().starts_with("secret = \"***\"")));

        // 3) POST /admin/config/json with editor token -> allowed
        let patch = serde_json::json!({"security": {"rate_limit": {"enabled": true, "rate_per_sec": 5.0, "burst": 10.0}}});
        let req = Request::builder().method("POST").uri("/admin/config/json").header("x-admin-token","ed").header("content-type","application/json").body(Body::from(patch.to_string())).unwrap();
        let resp = super::handle_admin(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // verify updated
        let new_cfg: crate::config::Config = toml::from_str(&std::fs::read_to_string(temp.path()).unwrap()).unwrap();
        let rl = new_cfg.security.unwrap().rate_limit.unwrap();
        assert!(rl.enabled && (rl.rate_per_sec - 5.0).abs() < 1e-6 && (rl.burst - 10.0).abs() < 1e-6);

        // 4) POST /admin/config (full file) with editor token -> unauthorized
        let req = Request::builder().method("POST").uri("/admin/config").header("x-admin-token","ed").body(Body::from("x".to_string())).unwrap();
        let resp = super::handle_admin(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 5) viewer token cannot write json
        std::env::set_var("DISPA_VIEWER_TOKEN", "vw");
        let req = Request::builder().method("POST").uri("/admin/config/json").header("x-admin-token","vw").header("content-type","application/json").body(Body::from("{}".to_string())).unwrap();
        let resp = super::handle_admin(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }).await.expect("test_admin_rbac_and_config_json_merge timed out");
    }
}
