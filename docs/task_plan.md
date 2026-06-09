# Codex 任务计划书：MISP 威胁情报聚合平台对接 ta_node

## 0. 背景与目标

目标：实现一个基于 MISP 的威胁情报聚合平台，完成以下能力：

1. 从 MISP 同步威胁情报。
2. 将情报分为两大类：
   - 流量类：traffic
   - 其他类：other
3. 将流量类 IOC 推送给 `ta_node` 使用。
4. 提供一个简单配置页面，用于配置 MISP、ta_node、同步策略和导出选项。
5. 提供可下载版本，包括源码包、Docker Compose 部署包和构建产物。
6. 项目完成后推送到目标仓库或指定分支，供 `https://github.com/luotieh/ta_node.git` 集成使用。

目标仓库：

```text
https://github.com/luotieh/ta_node.git
```

`ta_node` 是一个 Go 语言流量分析节点，已有本地情报 API。当前应优先对接：

```http
POST /api/v1/intel/sync-source
```

示例请求：

```json
{
  "source": "Threat Intel Hub",
  "items": [
    {
      "id": "misp-domain-example.com",
      "type": "domain",
      "value": "example.com",
      "category": "c2",
      "severity": "high",
      "enabled": true
    }
  ]
}
```

---

## 1. 总体架构

```text
MISP
  │
  │ REST API / PyMISP
  ▼
Threat Intel Hub
  ├── MISP 同步
  ├── 情报标准化
  ├── traffic / other 分类
  ├── 本地存储
  ├── 查询 API
  ├── 下载导出
  ├── Web 配置页
  └── 推送 traffic IOC 到 ta_node
          │
          ▼
      ta_node
      POST /api/v1/intel/sync-source
```

设计原则：

```text
1. MISP 是上游威胁情报源。
2. Threat Intel Hub 是聚合、清洗、分类、分发服务。
3. ta_node 是流量分析执行节点，只接收可用于流量检测的 IOC。
4. other 类情报默认不推送给 ta_node，仅保存在平台内供查询和后续扩展。
5. ta_node 推送失败时不得影响 MISP 同步任务。
```

---

## 2. 技术栈

```text
后端：Python 3.11 + FastAPI
任务队列：Celery
定时任务：Celery Beat
缓存 / Broker：Redis
数据库：PostgreSQL
ORM：SQLAlchemy 2.x
迁移：Alembic
MISP SDK：PyMISP
前端配置页：FastAPI Jinja2 模板或简单静态 HTML + 原生 JS
部署：Docker Compose
测试：pytest
打包：Makefile + release 目录 + zip/tar.gz
```

---

## 3. 项目结构

```text
threat-intel-hub/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── db.py
│   ├── models/
│   │   ├── indicator.py
│   │   ├── sync_state.py
│   │   └── app_config.py
│   ├── schemas/
│   │   ├── indicator.py
│   │   ├── sync.py
│   │   └── config.py
│   ├── api/
│   │   ├── health.py
│   │   ├── indicators.py
│   │   ├── sync.py
│   │   ├── exports.py
│   │   ├── push.py
│   │   └── config.py
│   ├── services/
│   │   ├── misp_client.py
│   │   ├── classifier.py
│   │   ├── normalizer.py
│   │   ├── indicator_service.py
│   │   ├── ta_node_client.py
│   │   └── export_service.py
│   ├── tasks/
│   │   ├── celery_app.py
│   │   ├── sync_misp.py
│   │   └── push_ta_node.py
│   ├── templates/
│   │   └── config.html
│   ├── static/
│   │   └── config.js
│   └── tests/
│       ├── test_classifier.py
│       ├── test_normalizer.py
│       ├── test_ta_node_mapper.py
│       ├── test_exports.py
│       └── test_config_api.py
├── alembic/
├── configs/
│   └── default.yaml
├── scripts/
│   ├── build_release.sh
│   └── smoke_test.sh
├── release/
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── pyproject.toml
├── README.md
└── .env.example
```

---

## 4. 配置要求

支持两种配置方式：

1. 环境变量
2. Web 配置页写入数据库或配置文件

优先级：

```text
环境变量 > 数据库配置 > 默认配置
```

`.env.example`：

```env
APP_ENV=production
APP_HOST=0.0.0.0
APP_PORT=18080

DATABASE_URL=postgresql+psycopg://intel:intel@postgres:5432/intel
REDIS_URL=redis://redis:6379/0

MISP_URL=https://misp.example.com
MISP_API_KEY=change-me
MISP_VERIFY_CERT=true
MISP_SYNC_INTERVAL_SECONDS=600

TA_NODE_ENABLED=true
TA_NODE_BASE_URL=http://127.0.0.1:19090
TA_NODE_TOKEN=
TA_NODE_SOURCE_NAME=Threat Intel Hub
TA_NODE_PUSH_INTERVAL_SECONDS=600

EXPORT_DIR=/app/release/exports
```

---

## 5. 数据库设计

### 5.1 intel_indicator

```sql
CREATE TABLE intel_indicator (
    id BIGSERIAL PRIMARY KEY,
    misp_event_id TEXT,
    misp_event_uuid UUID,
    misp_attribute_uuid UUID UNIQUE,

    platform_category TEXT NOT NULL,
    misp_category TEXT,
    misp_type TEXT NOT NULL,
    value TEXT NOT NULL,

    normalized_type TEXT,
    normalized_value TEXT,

    to_ids BOOLEAN DEFAULT FALSE,
    tlp TEXT,
    confidence INTEGER,
    threat_level TEXT,
    severity TEXT,

    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    valid_until TIMESTAMP,

    source_org TEXT,
    tags JSONB,
    galaxies JSONB,
    raw JSONB,

    pushed_to_ta_node BOOLEAN DEFAULT FALSE,
    pushed_at TIMESTAMP,
    push_error TEXT,

    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);
```

索引：

```sql
CREATE INDEX idx_intel_platform_category ON intel_indicator(platform_category);
CREATE INDEX idx_intel_misp_type ON intel_indicator(misp_type);
CREATE INDEX idx_intel_normalized_value ON intel_indicator(normalized_value);
CREATE INDEX idx_intel_last_seen ON intel_indicator(last_seen);
CREATE INDEX idx_intel_type_value ON intel_indicator(normalized_type, normalized_value);
CREATE INDEX idx_intel_pushed ON intel_indicator(pushed_to_ta_node);
```

---

### 5.2 sync_state

```sql
CREATE TABLE sync_state (
    id BIGSERIAL PRIMARY KEY,
    source_name TEXT UNIQUE,
    last_timestamp TEXT,
    last_success_at TIMESTAMP,
    status TEXT,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);
```

---

### 5.3 app_config

```sql
CREATE TABLE app_config (
    id BIGSERIAL PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    value TEXT,
    encrypted BOOLEAN DEFAULT FALSE,
    description TEXT,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);
```

敏感字段：

```text
MISP_API_KEY
TA_NODE_TOKEN
```

要求：

```text
1. 不要在 API 响应中直接返回完整密钥。
2. 配置页面中密钥字段默认显示为 ******。
3. 用户填写新值时才更新密钥。
```

---

## 6. 情报分类规则

### 6.1 流量类 traffic

满足以下任一条件归为 `traffic`：

```text
1. MISP category == "Network activity"
2. MISP type 属于 TRAFFIC_TYPES
```

```python
TRAFFIC_TYPES = {
    "ip-src",
    "ip-dst",
    "ip-src|port",
    "ip-dst|port",
    "domain",
    "domain|ip",
    "hostname",
    "hostname|port",
    "url",
    "uri",
    "user-agent",
    "ja3-fingerprint-md5",
    "jarm-fingerprint",
    "pattern-in-traffic",
    "snort",
    "zeek",
    "bro",
}
```

### 6.2 其他类 other

不满足 traffic 条件的归为：

```text
other
```

---

## 7. MISP 同步任务

实现：

```python
sync_misp_attributes()
```

流程：

```text
1. 读取 MISP 配置。
2. 从 sync_state 获取上次同步时间。
3. 默认首次同步最近 24 小时。
4. 调用 PyMISP 搜索 attributes。
5. 查询条件：
   - published=True
   - to_ids=True
   - enforceWarninglist=True
   - timestamp=last_timestamp 或 "24h"
6. 标准化 value。
7. 分类为 traffic / other。
8. 写入 intel_indicator。
9. 更新 sync_state。
10. 同步成功后触发 push_traffic_to_ta_node。
```

---

## 8. ta_node 推送功能

### 8.1 推送接口

实现客户端：

```text
app/services/ta_node_client.py
```

推送目标：

```http
POST {TA_NODE_BASE_URL}/api/v1/intel/sync-source
```

Header：

```http
Content-Type: application/json
Authorization: Bearer {TA_NODE_TOKEN}
```

如果 `TA_NODE_TOKEN` 为空，不发送 Authorization 头。

---

### 8.2 MISP IOC 到 ta_node item 映射

实现：

```python
def map_indicator_to_ta_node_item(indicator) -> dict:
    ...
```

映射规则：

| MISP type | ta_node type | 说明 |
|---|---|---|
| ip-src | ip | 源 IP |
| ip-dst | ip | 目的 IP |
| ip-src\|port | ip_port | 源 IP + 端口 |
| ip-dst\|port | ip_port | 目的 IP + 端口 |
| domain | domain | 域名 |
| domain\|ip | domain | 优先取 domain |
| hostname | domain | 主机名按 domain 处理 |
| hostname\|port | domain | 优先取 hostname |
| url | url | URL |
| uri | url | URI |
| user-agent | user_agent | UA |
| ja3-fingerprint-md5 | ja3 | JA3 |
| jarm-fingerprint | jarm | JARM |
| snort | rule | 规则 |
| zeek | rule | 规则 |
| bro | rule | 规则 |
| pattern-in-traffic | pattern | 流量特征 |

ta_node item 格式：

```json
{
  "id": "misp-attribute-uuid",
  "type": "domain",
  "value": "evil.example.com",
  "category": "c2",
  "severity": "high",
  "enabled": true
}
```

字段生成规则：

```text
id:
  优先 misp_attribute_uuid
  否则 sha256("misp_type:normalized_value")

type:
  由 MISP type 映射

value:
  使用 normalized_value

category:
  根据 MISP tags / galaxy / category 生成
  默认 "misp"

severity:
  根据 MISP threat_level / confidence / tags 生成
  默认 "medium"

enabled:
  to_ids == true 且 platform_category == traffic
```

---

### 8.3 推送任务

实现：

```python
push_traffic_to_ta_node()
```

流程：

```text
1. 读取 TA_NODE_ENABLED。
2. 如果未启用，直接返回 skipped。
3. 查询 platform_category=traffic 且 to_ids=true 的 IOC。
4. 默认只推送新增或未成功推送的 IOC。
5. 转换为 ta_node items。
6. 调用 /api/v1/intel/sync-source。
7. 推送成功后更新 pushed_to_ta_node=true、pushed_at。
8. 推送失败时记录 push_error，但不删除本地 IOC。
```

要求：

```text
1. 支持手动推送。
2. 支持定时推送。
3. 支持全量重新推送。
4. 单批次默认最多 5000 条。
5. ta_node 不可用时，API 返回清晰错误。
```

---

## 9. API 设计

### 9.1 健康检查

```http
GET /health
```

返回：

```json
{
  "status": "ok"
}
```

---

### 9.2 MISP 健康检查

```http
GET /health/misp
```

---

### 9.3 ta_node 健康检查

```http
GET /health/ta-node
```

内部请求：

```http
GET {TA_NODE_BASE_URL}/api/v1/health
```

返回：

```json
{
  "status": "ok",
  "ta_node_base_url": "http://127.0.0.1:19090"
}
```

失败：

```json
{
  "status": "failed",
  "error": "connection refused"
}
```

---

### 9.4 查询情报

```http
GET /indicators
```

查询参数：

```text
category=traffic|other
misp_type=domain
value=example.com
tag=tlp:white
pushed_to_ta_node=true|false
limit=50
offset=0
```

---

### 9.5 情报详情

```http
GET /indicators/{id}
```

---

### 9.6 手动同步 MISP

```http
POST /sync/misp
```

返回：

```json
{
  "task_id": "xxxx",
  "status": "queued"
}
```

---

### 9.7 推送到 ta_node

```http
POST /push/ta-node
```

请求：

```json
{
  "mode": "incremental"
}
```

可选：

```json
{
  "mode": "full"
}
```

返回：

```json
{
  "task_id": "xxxx",
  "status": "queued"
}
```

---

### 9.8 查询推送状态

```http
GET /push/ta-node/status
```

返回：

```json
{
  "enabled": true,
  "ta_node_base_url": "http://127.0.0.1:19090",
  "last_success_at": "2026-06-09T01:00:00Z",
  "last_error": null,
  "pending_count": 20,
  "pushed_count": 1000
}
```

---

### 9.9 导出 traffic IOC

```http
GET /exports/traffic?format=json
GET /exports/traffic?format=csv
GET /exports/traffic?format=txt
```

要求：

```text
1. 仅导出 platform_category=traffic。
2. 默认仅导出 to_ids=true。
3. txt：每行一个 value。
4. csv：type,value,category,severity,tags,last_seen。
5. json：结构化数组。
```

---

### 9.10 下载发布包

```http
GET /downloads/latest
GET /downloads/threat-intel-hub.zip
GET /downloads/traffic-ioc.txt
GET /downloads/traffic-ioc.csv
GET /downloads/traffic-ioc.json
```

要求：

```text
1. /downloads/latest 返回最新 release 包。
2. release 包位于 release/ 目录。
3. API 需要使用 FileResponse。
4. 文件不存在时返回 404。
```

---

## 10. 简单配置页面

### 10.1 页面地址

```http
GET /config
```

### 10.2 页面功能

配置页面使用简单 HTML + 原生 JS，不需要复杂前端框架。

页面包含以下区域：

```text
1. MISP 配置
   - MISP URL
   - MISP API Key
   - Verify Cert
   - Sync Interval Seconds
   - 测试 MISP 连接按钮

2. ta_node 配置
   - Enable Push
   - ta_node Base URL
   - ta_node Token
   - Source Name
   - Push Interval Seconds
   - 测试 ta_node 连接按钮
   - 手动推送按钮

3. 同步控制
   - 手动同步 MISP 按钮
   - 查看最近同步状态
   - 查看最近推送状态

4. 下载区
   - 下载最新部署包
   - 下载 traffic-ioc.txt
   - 下载 traffic-ioc.csv
   - 下载 traffic-ioc.json
```

### 10.3 配置页面 API

读取配置：

```http
GET /api/config
```

保存配置：

```http
POST /api/config
```

请求：

```json
{
  "misp_url": "https://misp.example.com",
  "misp_api_key": "new-key-or-empty",
  "misp_verify_cert": true,
  "misp_sync_interval_seconds": 600,
  "ta_node_enabled": true,
  "ta_node_base_url": "http://127.0.0.1:19090",
  "ta_node_token": "new-token-or-empty",
  "ta_node_source_name": "Threat Intel Hub",
  "ta_node_push_interval_seconds": 600
}
```

要求：

```text
1. 保存配置后立即生效于手动任务。
2. 定时任务允许重启后生效。
3. 密钥字段为空时保留旧值。
4. 返回配置时密钥字段用 masked=true 表示，不返回明文。
```

返回：

```json
{
  "status": "saved"
}
```

---

## 11. 可下载版本要求

实现 Makefile：

```makefile
.PHONY: test build package release

test:
	pytest -q

build:
	docker compose build

package:
	mkdir -p release/threat-intel-hub
	cp -r app alembic configs scripts release/threat-intel-hub/
	cp Dockerfile docker-compose.yml pyproject.toml alembic.ini README.md .env.example release/threat-intel-hub/
	cd release && tar -czf threat-intel-hub.tar.gz threat-intel-hub
	cd release && zip -r threat-intel-hub.zip threat-intel-hub

release: test build package
```

交付产物：

```text
release/threat-intel-hub.zip
release/threat-intel-hub.tar.gz
release/traffic-ioc.txt
release/traffic-ioc.csv
release/traffic-ioc.json
```

README 中需要说明：

```text
1. 如何下载部署包。
2. 如何解压。
3. 如何配置 MISP。
4. 如何配置 ta_node。
5. 如何手动同步。
6. 如何手动推送。
7. 如何访问配置页面。
```

---

## 12. Docker Compose 要求

至少包含：

```text
api
worker
beat
postgres
redis
```

端口：

```text
api: 18080
postgres: 5432
redis: 6379
```

启动后应可访问：

```text
http://127.0.0.1:18080/health
http://127.0.0.1:18080/config
```

---

## 13. 与 ta_node 的联调流程

假设 ta_node 已启动：

```bash
./ta_node --config ./configs/ta_node.yaml --config-only
```

Threat Intel Hub 启动：

```bash
docker compose up -d
```

配置页面：

```text
http://127.0.0.1:18080/config
```

配置：

```text
TA_NODE_BASE_URL=http://127.0.0.1:19090
TA_NODE_SOURCE_NAME=Threat Intel Hub
```

测试：

```bash
curl http://127.0.0.1:18080/health/ta-node
curl -X POST http://127.0.0.1:18080/push/ta-node \
  -H 'Content-Type: application/json' \
  -d '{"mode":"full"}'
```

在 ta_node 查看：

```bash
curl http://127.0.0.1:19090/api/v1/intel/stats
curl http://127.0.0.1:19090/api/v1/intel
```

---

## 14. 测试要求

### 14.1 分类测试

```text
test_network_activity_category_is_traffic
test_ip_src_type_is_traffic
test_domain_type_is_traffic
test_sha256_type_is_other
test_vulnerability_type_is_other
```

### 14.2 ta_node 映射测试

```text
test_map_ip_src_to_ta_node_ip
test_map_domain_to_ta_node_domain
test_map_url_to_ta_node_url
test_map_ja3_to_ta_node_ja3
test_map_unknown_traffic_type_to_pattern
test_indicator_without_uuid_generates_stable_id
```

### 14.3 推送测试

```text
test_push_disabled_skips
test_push_sends_sync_source_payload
test_push_with_token_sets_authorization_header
test_push_failure_records_error
test_full_push_includes_all_traffic_ioc
test_incremental_push_includes_unpushed_only
```

### 14.4 配置页面 / API 测试

```text
test_get_config_masks_secret
test_post_config_updates_misp_url
test_post_config_empty_secret_keeps_old_secret
test_health_ta_node_success
test_health_ta_node_failed
```

### 14.5 下载测试

```text
test_download_latest_release
test_download_missing_file_returns_404
test_export_traffic_txt
test_export_traffic_csv
test_export_traffic_json
```

---

## 15. 推送到 GitHub 的要求

Codex 完成后执行：

```bash
git status
git checkout -b feature/misp-threat-intel-hub-ta-node
git add .
git commit -m "feat: add MISP threat intel hub with ta_node push"
git push origin feature/misp-threat-intel-hub-ta-node
```

如果有权限，创建 Pull Request：

```text
base: main
compare: feature/misp-threat-intel-hub-ta-node
title: feat: add MISP threat intel hub with ta_node push
```

PR 描述需要包含：

```text
1. 新增 MISP 同步能力。
2. 新增 traffic / other 分类。
3. 新增 ta_node 推送能力。
4. 新增配置页面 /config。
5. 新增下载包 /downloads/latest。
6. 新增 Docker Compose 部署。
7. 新增测试覆盖。
```

---

## 16. README 必须包含

```text
1. 项目简介
2. 架构图
3. 快速启动
4. 环境变量说明
5. 配置页面说明
6. MISP 同步说明
7. ta_node 推送说明
8. 下载导出说明
9. API 列表
10. 常见问题
```

---

## 17. 验收标准

必须满足：

```text
1. docker compose up -d 能启动完整服务。
2. http://127.0.0.1:18080/health 返回 ok。
3. http://127.0.0.1:18080/config 可以打开配置页面。
4. 配置页面可以保存 MISP 和 ta_node 配置。
5. /health/misp 可以测试 MISP 连接。
6. /health/ta-node 可以测试 ta_node 连接。
7. /sync/misp 可以手动触发 MISP 同步。
8. MISP 情报正确分为 traffic / other。
9. /push/ta-node 可以把 traffic IOC 推送给 ta_node。
10. /exports/traffic 支持 txt/csv/json。
11. /downloads/latest 可以下载 release 包。
12. make release 可以生成 zip 和 tar.gz。
13. pytest 全部通过。
14. 代码推送到 feature/misp-threat-intel-hub-ta-node 分支。
15. README 写清楚如何给 ta_node 使用。
```

---

## 18. 非目标

当前版本不做：

```text
1. 用户登录和权限管理。
2. 多租户。
3. 高级情报评分模型。
4. STIX/TAXII 服务端。
5. Suricata/Snort/Zeek 自动规则生成。
6. SIEM 主动推送。
7. 前端复杂管理后台。
```

先完成可运行、可同步、可推送、可下载、可配置的 MVP。
