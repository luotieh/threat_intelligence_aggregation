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

loadConfig().catch(show);
