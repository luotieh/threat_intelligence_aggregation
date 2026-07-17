const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtTime = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? esc(iso) : d.toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
};

const fields = [
  "ta_node_enabled", "ta_node_source_name", "ta_node_push_interval_seconds",
  "ioc_output_dir", "ioc_rule_filename", "otx_api_key", "whoisxml_api_key",
  "ta_node_top_per_source", "ta_node_min_severity",
  "llm_enabled", "llm_base_url", "llm_api_key", "llm_model",
  "pipeline_target", "pipeline_max_enrich",
];

function show(data) { $("output").textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2); }

function toast(msg, type) {
  const el = document.createElement("div");
  el.className = "toast-item " + (type || "");
  el.textContent = typeof msg === "string" ? msg : JSON.stringify(msg);
  $("toast").appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function setStatus(id, msg, kind) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const type = response.headers.get("content-type") || "";
  const data = type.includes("json") ? await response.json() : await response.text();
  if (!response.ok) throw data;
  return data;
}

async function loadConfig() {
  const cfg = await api("/api/config");
  for (const field of fields) {
    if (field.endsWith("api_key") || field.endsWith("token")) continue;
    const el = $(field);
    if (!el) continue;
    if (el.type === "checkbox") el.checked = Boolean(cfg[field]);
    else el.value = cfg[field] ?? "";
  }
}

function collectConfig() {
  const data = {};
  for (const field of fields) {
    const el = $(field);
    if (!el) continue;
    data[field] = el.type === "checkbox" ? el.checked : el.value;
  }
  return data;
}

async function saveConfig(statusId, okMsg) {
  setStatus(statusId, "保存中…");
  try {
    await api("/api/config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(collectConfig()) });
    await loadConfig();
    setStatus(statusId, "✓ " + okMsg, "ok");
    toast(okMsg, "ok");
  } catch (e) { setStatus(statusId, "✗ 保存失败", "err"); toast(e, "err"); show(e); }
}

// ---- 导航 + 主题 ----
const titles = {
  overview: ["概览", "威胁情报聚合平台运行态势"],
  sources: ["情报源", "OTX / WhoisXML 数据源配置"],
  ai: ["AI 描述", "LLM 证据润色配置"],
  pipeline: ["每日流水线", "自动化编排 · 每日 23:00"],
  push: ["推送规则", "ta_node 规则生成与上传"],
  intel: ["情报列表", "精选高危流量情报"],
};
document.querySelectorAll(".nav-item").forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll(".nav-item").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    const p = b.dataset.panel;
    $("panel-" + p).classList.add("active");
    $("page-title").textContent = titles[p][0];
    $("page-sub").textContent = titles[p][1];
    if (p === "overview") loadOverview();
    if (p === "intel") loadTop();
  };
});

if (localStorage.getItem("theme")) document.documentElement.setAttribute("data-theme", localStorage.getItem("theme"));
$("theme-toggle").onclick = () => {
  const cur = document.documentElement.getAttribute("data-theme");
  const isDark = cur === "dark" || (!cur && matchMedia("(prefers-color-scheme: dark)").matches);
  const next = isDark ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("theme", next);
};

// ---- 概览 ----
async function loadOverview() {
  try {
    // 概览与列表同口径:只统计真正出过规则的,否则"描述覆盖"会把未推送的候选算进分母
    const top = await api("/indicators/top?top_per_source=0&min_severity=low&pushed_only=true");
    const items = top.sources.flatMap((s) => s.items);
    $("s-total").textContent = items.length;
    $("s-confirmed").textContent = items.filter((i) => (i.whoisxml || {}).threat_type).length;
    const narr = items.filter((i) => i.narrative).length;
    $("s-narrated").innerHTML = narr + ` <small>/ ${items.length}</small>`;
  } catch (e) { /* 忽略概览加载错误 */ }
  try {
    const ps = await api("/push/ta-node/status");
    $("s-pushed").textContent = ps.generated_count ?? "—";
    $("push-summary").textContent = `已生成 ${ps.generated_count ?? 0} 条 · 待推 ${ps.pending_count ?? 0} · 最近成功 ${ps.last_success_at ?? "—"}` + (ps.last_error ? ` · 错误 ${ps.last_error}` : "");
    show(ps);
  } catch (e) { $("push-summary").textContent = "推送状态获取失败"; }
}

async function checkHealth(name) {
  const badge = $("h-" + name);
  badge.className = "badge"; badge.innerHTML = '<span class="dot"></span>检测中…';
  try {
    const r = await api("/health/" + name);
    const cls = r.status === "ok" ? "ok" : (r.status === "failed" ? "bad" : "warn");
    badge.className = "badge " + cls;
    badge.innerHTML = '<span class="dot"></span>' + r.status + (r.model ? " · " + r.model : "");
    show(r);
  } catch (e) { badge.className = "badge bad"; badge.innerHTML = '<span class="dot"></span>失败'; show(e); }
}
document.querySelectorAll("[data-health]").forEach((b) => { b.onclick = () => checkHealth(b.dataset.health); });

// ---- 情报列表 ----
function renderTop(resp) {
  const rows = [];
  for (const src of resp.sources) {
    for (const item of src.items) {
      const wx = item.whoisxml
        ? (item.whoisxml.threat_type ? `<span class="wx-ok">✔ ${esc(item.whoisxml.threat_type)}</span>` : '<span class="muted">已查·无记录</span>')
        : '<span class="muted">—</span>';
      const sev = `<span class="sev ${esc(item.severity)}">${esc(item.severity)}</span>`;
      const narr = item.narrative ? esc(item.narrative) : '<span class="muted">—</span>';
      const when = resp.pushed_only ? item.pushed_at : item.created_at;
      rows.push(`<tr><td>${esc(src.source)}</td><td class="mono">${esc(item.value)}</td><td>${esc(item.misp_type)}</td>` +
        `<td>${sev}</td><td>${esc(item.confidence ?? "")}</td><td>${wx}</td><td class="narr">${narr}</td>` +
        `<td class="mono">${fmtTime(when)}</td></tr>`);
    }
  }
  const dr = (resp.date_from || resp.date_to) ? ` · 日期 ${resp.date_from || "…"} ~ ${resp.date_to || "…"}` : "";
  const scope = resp.pushed_only ? "只看已出规则" : `全部候选 · 每源上限 ${resp.top_per_source}`;
  $("top_meta").textContent = `共 ${rows.length} 条 · ${scope} · 最低危险度 ${resp.min_severity}${dr}`;
  $("top_table").innerHTML = `<div class="table-wrap"><table><thead><tr><th>源</th><th>IOC</th><th>类型</th>` +
    `<th>危险度</th><th>置信</th><th>WhoisXML</th><th>LLM 描述</th>` +
    `<th>${resp.pushed_only ? "推送时间" : "获取时间"}</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}
async function loadTop() {
  const pushedOnly = $("top_pushed_only").checked;
  // 只看已出规则时不截断:出过的规则本来就没几条,截断反而看不全历史
  const n = pushedOnly ? 0 : ($("top_preview_n").value || 10);
  const sev = $("top_preview_sev").value || "high";
  let url = `/indicators/top?top_per_source=${n}&min_severity=${sev}`;
  if (pushedOnly) url += "&pushed_only=true";
  const df = $("top_date_from").value, dt = $("top_date_to").value;
  if (df) url += `&date_from=${df}`;
  if (dt) url += `&date_to=${dt}`;
  try { renderTop(await api(url)); }
  catch (e) { toast(e, "err"); show(e); }
}
$("top_pushed_only").onchange = () => { $("top_preview_n").disabled = $("top_pushed_only").checked; loadTop(); };
$("load-top").onclick = loadTop;
$("clear-date").onclick = () => { $("top_date_from").value = ""; $("top_date_to").value = ""; loadTop(); };

// ---- 情报源 ----
$("save-sources").onclick = () => saveConfig("sources_status", "情报源 Key 已保存(密文,回显 masked)");
async function runHealth(name, path, statusId) {
  setStatus(statusId, `测试 ${name} 中…`);
  try {
    const r = await api(path);
    const line = `${name}: ${r.status}` + (r.model ? ` · ${r.model}` : "") + (r.username ? ` (${r.username})` : "") + (r.error ? ` — ${r.error}` : "") + (r.reason ? ` — ${r.reason}` : "");
    setStatus(statusId, line, r.status === "ok" ? "ok" : "");
    toast(line, r.status === "ok" ? "ok" : "");
    show(r);
  } catch (e) { setStatus(statusId, `${name} 测试失败`, "err"); toast(e, "err"); show(e); }
}
$("test-otx").onclick = () => runHealth("OTX", "/health/otx", "sources_status");
$("test-whoisxml").onclick = () => runHealth("WhoisXML", "/health/whoisxml", "sources_status");
$("sync-otx-now").onclick = async () => {
  setStatus("sources_status", "拉取 OTX 中(后台直连入库)…");
  try { const r = await api("/sync/otx", { method: "POST" }); setStatus("sources_status", "✓ OTX 拉取已在后台执行", "ok"); toast("OTX 拉取已启动", "ok"); show(r); }
  catch (e) { setStatus("sources_status", "OTX 拉取失败", "err"); toast(e, "err"); show(e); }
};
$("enrich-whoisxml").onclick = async () => {
  setStatus("sources_status", "富化中(查询 WhoisXML)…");
  try { const r = await api("/enrich/whoisxml", { method: "POST" }); const m = `富化 ${r.enriched ?? 0} 条(确认 ${r.confirmed_malicious ?? 0}, 失败 ${r.failed ?? 0})`; setStatus("sources_status", "✓ " + m, "ok"); toast(m, "ok"); show(r); }
  catch (e) { setStatus("sources_status", "富化失败", "err"); toast(e, "err"); show(e); }
};

// ---- AI 描述 ----
$("save-llm").onclick = () => saveConfig("llm_status", "LLM 配置已保存(Key 密文)");
$("test-llm").onclick = () => runHealth("LLM", "/health/llm", "llm_status");
$("gen-narrative").onclick = async () => {
  setStatus("llm_status", "生成告警叙述中(调用 LLM)…");
  try { const r = await api("/enrich/narrative", { method: "POST" }); const m = `叙述生成 ${r.generated ?? 0} 条(失败 ${r.failed ?? 0})` + (r.reason ? ` — ${r.reason}` : ""); setStatus("llm_status", "✓ " + m, "ok"); toast(m, "ok"); show(r); }
  catch (e) { setStatus("llm_status", "生成失败", "err"); toast(e, "err"); show(e); }
};

// ---- 流水线 ----
$("save-pipeline").onclick = () => saveConfig("pipeline_status", "流水线配置已保存");
async function runPipeline(statusId) {
  setStatus(statusId, "流水线已在后台运行(拉取 → 富化 → LLM → 推送,可能数分钟)…");
  toast("每日流水线已启动", "ok");
  try { show(await api("/pipeline/run", { method: "POST" })); }
  catch (e) { setStatus(statusId, "启动失败", "err"); toast(e, "err"); show(e); }
}
$("run-pipeline").onclick = () => runPipeline("pipeline_status");
$("quick-run").onclick = () => runPipeline("pipeline_status");

// ---- 推送规则 ----
$("save").onclick = () => saveConfig("push_status_line", "全部配置已保存");
async function genRules(mode) {
  setStatus("push_status_line", `生成${mode === "full" ? "全量" : "增量"}规则中…`);
  try { const r = await api("/ioc-rules/generate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode }) }); const m = `已生成 ${r.count ?? 0} 条规则`; setStatus("push_status_line", "✓ " + m, "ok"); toast(m, "ok"); show(r); }
  catch (e) { setStatus("push_status_line", "生成失败", "err"); toast(e, "err"); show(e); }
}
$("push-full").onclick = () => genRules("full");
$("push-inc").onclick = () => genRules("incremental");
$("upload-ioc").onclick = async () => {
  const file = $("ioc_upload_file").files[0];
  if (!file) { toast("请先选择 intel.yaml / zip 文件", "err"); return; }
  const body = new FormData(); body.append("file", file);
  try { const r = await api("/ioc-rules/upload", { method: "POST", body }); toast("上传成功", "ok"); show(r); }
  catch (e) { toast(e, "err"); show(e); }
};
$("push-status").onclick = async () => { try { show(await api("/push/ta-node/status")); await loadOverview(); toast("已刷新推送状态", "ok"); } catch (e) { toast(e, "err"); show(e); } };
$("check-files").onclick = async () => {
  setStatus("file_status_line", "检查规则文件…");
  try {
    const r = await api("/ioc-rules/file-status");
    const y = r.yaml || {}, z = r.zip || {};
    const yTxt = y.exists ? `yaml ${y.count ?? "?"}条(${fmtTime(y.mtime)})` : "yaml 缺失";
    const zTxt = z.exists ? `zip ${z.count ?? "?"}条` : "zip 缺失";
    const kind = r.taken_by_gate ? "ok" : (y.exists && z.exists ? "ok" : "err");
    setStatus("file_status_line", `${r.taken_by_gate ? "✓" : (y.exists && z.exists ? "•" : "!")} ${yTxt} · ${zTxt} · ${r.verdict}`, kind);
    toast(r.verdict, r.taken_by_gate || (y.exists && z.exists) ? "ok" : "err");
    show(r);
  } catch (e) { setStatus("file_status_line", "检查失败", "err"); toast(e, "err"); show(e); }
};
// 运行日志:流水线写文件时当场落库的事实,网闸取走文件也不影响追溯
function fmtRun(r) {
  const q = r.type_quota || {}, p = r.pushed_by_type || {};
  const f = r.files || {}, y = f.yaml || {}, z = f.zip || {};
  const rules = r.rules || [];
  // 覆盖率才是"每条规则有没有研判"的答案;narrated 只是本次新生成数,已有描述的会跳过
  const narrCover = rules.filter((x) => x.narrated).length;
  const wxCover = rules.filter((x) => x.whoisxml_confirmed).length;
  const head = `#${r.id} ${fmtTime(r.started_at)} · ${r.trigger === "beat" ? "定时" : "手动"} · ${r.status}`;
  const bits = [
    head,
    r.reason ? `原因:${r.reason}` : null,
    `富化 WhoisXML 查询 ${r.enrich_attempts ?? 0} 次 → 确认 ${r.confirmed ?? 0} 条` +
      (r.otx_only ? ` · OTX 单源补 ${r.otx_only} 条` : ""),
    rules.length ? `双源确认覆盖 ${wxCover}/${rules.length}` + (wxCover === 0 ? "(全部为 OTX 单源)" : "") : null,
    rules.length ? `LLM 描述覆盖 ${narrCover}/${rules.length}` +
      (narrCover < rules.length ? ` ⚠ 缺 ${rules.length - narrCover} 条` : "") +
      ` · 本次新生成 ${r.narrated ?? 0} · 失败 ${r.narrate_failed ?? 0}` : null,
    `出规则 ${r.pushed ?? 0} 条(ip ${p.ip ?? 0}/${q.ip ?? 0} · 域名 ${p.domain ?? 0}/${q.domain ?? 0} · url ${p.url ?? 0}/${q.url ?? 0})`,
    y.exists ? `yaml ${y.name} · ${y.count} 条 · ${y.size}B · sha ${(y.sha256 || "").slice(0, 12)}` : "yaml 未生成",
    z.exists ? `zip  ${z.name} · ${z.size}B · sha ${(z.sha256 || "").slice(0, 12)}` : "zip 未生成",
    r.duration_ms != null ? `耗时 ${(r.duration_ms / 1000).toFixed(1)}s` : null,
  ].filter(Boolean);
  for (const n of r.notes || []) bits.push("· " + n);
  if (rules.length) {
    bits.push("规则清单:");
    for (const x of rules) {
      bits.push(`  ${x.narrated ? "✔" : "✘"} ${(x.type || "").padEnd(6)} ${x.value}` +
        (x.whoisxml_confirmed ? "  [双源确认]" : ""));
    }
  }
  return bits.join("\n");
}
// 详情必须写在本面板内的可见元素里:#output 在概览面板且默认折叠,在这儿写等于不显示
function runLogOut(text) {
  const el = $("run_log_out");
  el.textContent = text;
  el.hidden = !text;
}
$("run-log").onclick = async () => {
  setStatus("run_log_line", "读取运行日志…");
  runLogOut("");
  try {
    const r = await api("/pipeline/runs?limit=30");
    const runs = r.runs || [];
    if (!runs.length) {
      setStatus("run_log_line", "暂无运行记录(流水线还没跑过)", "");
      runLogOut("暂无运行记录。每日 23:00 自动执行,也可在「每日流水线」手动触发。");
      return;
    }
    const last = runs[0];
    setStatus("run_log_line", `最近 ${runs.length} 次运行 · 最新 ${fmtTime(last.started_at)} ${last.status} 出规则 ${last.pushed ?? 0} 条`,
      last.status === "success" ? "ok" : "err");
    runLogOut(runs.map(fmtRun).join("\n\n"));
    show(runs);
  } catch (e) { setStatus("run_log_line", "读取失败", "err"); runLogOut(""); toast(e, "err"); show(e); }
};

// 初始化
loadConfig().then(loadOverview).catch((e) => toast(e, "err"));
