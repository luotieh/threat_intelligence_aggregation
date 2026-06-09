# Threat Intel Hub

Threat Intel Hub 是一个基于 MISP 的威胁情报聚合服务，用于同步 MISP IOC、标准化并分类为 `traffic` / `other`，再把可用于流量检测的 `traffic` IOC 推送到 `ta_node`。

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
- `TA_NODE_ENABLED`, `TA_NODE_BASE_URL`, `TA_NODE_TOKEN`, `TA_NODE_SOURCE_NAME`, `TA_NODE_PUSH_INTERVAL_SECONDS`: ta_node 推送配置。
- `EXPORT_DIR`: release 包和 IOC 导出文件目录。

配置优先级为：环境变量 > 数据库配置 > 默认配置。

## 配置页面说明

访问 `/config` 可配置 MISP、ta_node、同步周期和推送周期。密钥字段不会明文返回；页面默认显示 `******`，保存时留空会保留旧密钥。

## MISP 同步说明

手动触发：

```bash
curl -X POST http://127.0.0.1:18080/sync/misp
```

同步逻辑读取上次 `sync_state`，首次默认同步最近 24 小时，搜索 published/to_ids attributes，标准化后写入 `intel_indicator`。同步失败会记录状态，不会删除本地 IOC。

## ta_node 推送说明

健康检查：

```bash
curl http://127.0.0.1:18080/health/ta-node
```

手动推送：

```bash
curl -X POST http://127.0.0.1:18080/push/ta-node \
  -H 'Content-Type: application/json' \
  -d '{"mode":"full"}'
```

推送接口为 `POST {TA_NODE_BASE_URL}/api/v1/intel/sync-source`。`TA_NODE_TOKEN` 为空时不发送 Authorization 头。

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
- `GET /exports/traffic?format=json|csv|txt`
- `GET /downloads/latest`
- `GET /downloads/{filename}`
- `GET /config`
- `GET /api/config`
- `POST /api/config`

## 常见问题

`/health/misp` 失败：检查 `MISP_URL`、`MISP_API_KEY` 和证书校验配置。

`/health/ta-node` 失败：确认 `TA_NODE_BASE_URL` 可从容器内访问。Linux 宿主机服务通常需要使用宿主机网关地址，而不是容器内的 `127.0.0.1`。

推送后没有 IOC：确认 IOC 为 `platform_category=traffic` 且 `to_ids=true`。增量推送只推送未成功推送过的 IOC，全量推送使用 `{"mode":"full"}`。

## 测试

```bash
pytest -q
```
