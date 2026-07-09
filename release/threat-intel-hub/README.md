# Threat Intel Hub

Threat Intel Hub 是一个基于 MISP 的威胁情报聚合服务，用于同步 MISP IOC、标准化并分类为 `traffic` / `other`，再把可用于流量检测的 `traffic` IOC 生成 `ta_node` 可加载的规则文件包。

## 架构图

```text
MISP -> Threat Intel Hub -> ta_node
          | sync/normalize/classify
          | local DB/API/export/config page
```

## 快速启动

```bash
cp .env.example .env
docker compose up -d
curl http://127.0.0.1:18080/health
```

配置页面：

```text
http://127.0.0.1:18080/config
```

## 环境变量说明

主要配置位于 `.env.example`：

- `DATABASE_URL`: PostgreSQL 连接串。
- `REDIS_URL`: Celery broker/backend。
- `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFY_CERT`, `MISP_SYNC_INTERVAL_SECONDS`: MISP 同步配置。
- `TA_NODE_ENABLED`, `TA_NODE_SOURCE_NAME`, `TA_NODE_PUSH_INTERVAL_SECONDS`: ta_node 规则文件生成配置。
- `EXPORT_DIR`: release 包和 IOC 导出文件目录。
- `IOC_OUTPUT_DIR`: 规则文件输出目录，默认 `/data/ftp/ioc`。
- `IOC_RULE_FILENAME`: ta_node 规则文件名，默认 `intel.yaml`，会同时生成同名 `intel.zip`。

配置优先级为：环境变量 > 数据库配置 > 默认配置。

## 配置页面说明

访问 `/config` 可配置 MISP、ta_node、同步周期和推送周期。密钥字段不会明文返回；页面默认显示 `******`，保存时留空会保留旧密钥。

## MISP 同步说明

手动触发：

```bash
curl -X POST http://127.0.0.1:18080/sync/misp
```

同步逻辑读取上次 `sync_state`，首次默认同步最近 24 小时，搜索 published/to_ids attributes，标准化后写入 `intel_indicator`。同步失败会记录状态，不会删除本地 IOC。

## ta_node 规则文件说明

Threat Intel Hub 不直接调用 ta_node。它会生成 ta_node `intel.yaml` 格式的规则文件，并压缩为同名 zip，默认保存到 `/data/ftp/ioc`，由网闸同步到内网。

文件格式与 `ta_node` 的 `configs/intel.yaml` 一致：

```yaml
items:
  - id: "misp-attribute-uuid"
    type: "domain"
    value: "evil.example.com"
    category: "c2"
    severity: "high"
    source: "Threat Intel Hub"
    description: "MISP domain IOC from Threat Intel Hub"
    tags: ["tlp:white", "c2"]
    enabled: true
    created_at: 1710000000
    updated_at: 1710000000
```

手动生成：

```bash
curl -X POST http://127.0.0.1:18080/ioc-rules/generate \
  -H 'Content-Type: application/json' \
  -d '{"mode":"full"}'
```

兼容入口 `/push/ta-node` 仍可用，但现在只排队生成规则包，不再发送 HTTP 请求到 ta_node。

手动上传已有规则文件：

```bash
curl -X POST http://127.0.0.1:18080/ioc-rules/upload \
  -F 'file=@intel.yaml'
```

上传 `.yaml` / `.yml` 时会校验顶层 `items` 列表和 ta_node 必需字段，然后生成同名 zip；上传 `.zip` 时直接保存到网闸目录。

## 下载导出说明

IOC 导出：

```bash
curl http://127.0.0.1:18080/exports/traffic?format=txt
curl http://127.0.0.1:18080/exports/traffic?format=csv
curl http://127.0.0.1:18080/exports/traffic?format=json
```

发布包：

```bash
make package
curl -O http://127.0.0.1:18080/downloads/latest
```

部署包位于 `release/threat-intel-hub.zip` 或 `release/threat-intel-hub.tar.gz`，解压后复制 `.env.example` 为 `.env`，按需填写 MISP 和 ta_node 配置，再执行 `docker compose up -d`。

## API 列表

- `GET /health`
- `GET /health/misp`
- `GET /health/ta-node`
- `GET /indicators`
- `GET /indicators/{id}`
- `POST /sync/misp`
- `POST /push/ta-node`
- `GET /push/ta-node/status`
- `POST /ioc-rules/generate`
- `POST /ioc-rules/upload`
- `GET /exports/traffic?format=json|csv|txt`
- `GET /downloads/latest`
- `GET /downloads/{filename}`
- `GET /config`
- `GET /api/config`
- `POST /api/config`

## 常见问题

`/health/misp` 失败：检查 `MISP_URL`、`MISP_API_KEY` 和证书校验配置。

`/health/ta-node` 失败：确认 `TA_NODE_BASE_URL` 可从容器内访问。Linux 宿主机服务通常需要使用宿主机网关地址，而不是容器内的 `127.0.0.1`。

生成后没有 IOC：确认 IOC 为 `platform_category=traffic` 且 `to_ids=true`。增量生成只包含未成功生成过的 IOC，全量生成使用 `{"mode":"full"}`。

## 测试

```bash
pytest -q
```
