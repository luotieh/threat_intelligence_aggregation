const $ = (id) => document.getElementById(id);
const fields = [
  "misp_url",
  "misp_api_key",
  "misp_verify_cert",
  "misp_sync_interval_seconds",
  "ta_node_enabled",
  "ta_node_base_url",
  "ta_node_token",
  "ta_node_source_name",
  "ta_node_push_interval_seconds",
  "ioc_output_dir",
  "ioc_rule_filename",
  "otx_api_key",
  "whoisxml_api_key",
  "ta_node_top_per_source",
  "ta_node_min_severity",
];

function show(data) {
  $("output").textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
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

$("save").onclick = async () => show(await api("/api/config", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(collectConfig()),
}));
$("test-misp").onclick = async () => show(await api("/health/misp"));
$("sync-misp").onclick = async () => show(await api("/sync/misp", { method: "POST" }));
$("push-full").onclick = async () => show(await api("/ioc-rules/generate", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ mode: "full" }),
}));
$("push-inc").onclick = async () => show(await api("/ioc-rules/generate", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ mode: "incremental" }),
}));
$("push-status").onclick = async () => show(await api("/push/ta-node/status"));
$("upload-ioc").onclick = async () => {
  const file = $("ioc_upload_file").files[0];
  if (!file) {
    show("请选择 ta_node intel.yaml 或同名 zip 文件");
    return;
  }
  const body = new FormData();
  body.append("file", file);
  show(await api("/ioc-rules/upload", { method: "POST", body }));
};

function renderTop(resp) {
  const rows = [];
  for (const src of resp.sources) {
    for (const item of src.items) {
      rows.push(`<tr><td>${src.source}</td><td>${item.value}</td><td>${item.misp_type}</td>` +
        `<td>${item.severity ?? ""}</td><td>${item.confidence ?? ""}</td>` +
        `<td>${item.last_seen ?? ""}</td></tr>`);
    }
  }
  const summary = `generated_at=${resp.generated_at} · top_per_source=${resp.top_per_source}` +
    ` · min_severity=${resp.min_severity} · 共 ${rows.length} 条`;
  $("top_table").innerHTML = `<p>${summary}</p>` +
    `<table class="top"><thead><tr><th>源</th><th>值</th><th>类型</th>` +
    `<th>危险度</th><th>置信度</th><th>最近出现</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

$("load-top").onclick = async () => {
  const n = $("top_preview_n").value;
  const sev = $("top_preview_sev").value;
  try {
    renderTop(await api(`/indicators/top?top_per_source=${n}&min_severity=${sev}`));
  } catch (e) { show(e); }
};

$("save-sources").onclick = async () => {
  const st = $("sources_status");
  st.textContent = "保存中…";
  try {
    await api("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(collectConfig()),
    });
    await loadConfig();
    st.textContent = "✓ 情报源 Key 已保存(密文存储,回显为 masked)";
    show("情报源 Key 已保存");
  } catch (e) {
    st.textContent = "✗ 保存失败: " + (typeof e === "string" ? e : JSON.stringify(e));
    show(e);
  }
};
async function runHealth(name, path) {
  const st = $("sources_status");
  st.textContent = `测试 ${name} 中…`;
  try {
    const r = await api(path);
    st.textContent = `${name}: ${r.status}` + (r.error ? ` — ${r.error}` : "") + (r.username ? ` (${r.username})` : "");
    show(r);
  } catch (e) {
    st.textContent = `${name} 测试失败: ` + (typeof e === "string" ? e : JSON.stringify(e));
    show(e);
  }
}
$("test-otx").onclick = () => runHealth("OTX", "/health/otx");
$("test-whoisxml").onclick = () => runHealth("WhoisXML", "/health/whoisxml");
$("enrich-whoisxml").onclick = async () => {
  const st = $("sources_status");
  st.textContent = "富化中(查询 WhoisXML,约 10 次)…";
  try {
    const r = await api("/enrich/whoisxml", { method: "POST" });
    st.textContent = `富化完成: ${r.enriched ?? 0} 条(确认恶意 ${r.confirmed_malicious ?? 0}, 失败 ${r.failed ?? 0})`;
    show(r);
  } catch (e) { st.textContent = "富化失败: " + (typeof e === "string" ? e : JSON.stringify(e)); show(e); }
};

loadConfig().catch(show);
