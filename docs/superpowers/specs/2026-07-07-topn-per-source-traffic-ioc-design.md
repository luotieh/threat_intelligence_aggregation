# 每源每日 Top-N 高危流量侧 IOC 精选 — 设计文档

- 日期:2026-07-07
- 状态:已通过设计评审,待写实施计划
- 涉及组件:`app/services`(精选/推送)、`app/api`(展示)、`app/config.py`、`app/services/config_service.py`、`app/templates/config.html`、`app/static/config.js`

## 1. 背景与目标

平台经 MISP 汇聚多源威胁情报(CIRCL/botvrij feeds、OTX、WhoisXML),`sync_misp` 增量入库到 `intel_indicator` 表,再由 `generate_ta_node_ioc_package` 生成 `intel.yaml` 推送给流量分析(TA)节点。

当前推送是「全部 traffic + to_ids 的 IOC」增量推送,规则量会随情报累积持续膨胀,且不区分危险度与来源。

目标:让运营人员通过**前端参数**控制,使每个情报源每天只把**最高危、流量侧可用**的 **Top-N** 条 IOC 纳入推送规则,并在**前端提供该 Top 列表的可视化**。前端展示与实际推送共用同一套精选逻辑,保证一致。

## 2. 已确定的关键决策

| 决策点 | 结论 |
|---|---|
| 精选落点 | **推送层**(`generate_ta_node_ioc_package`);`sync_misp` 拉取与入库完全不变,`intel_indicator` 表保留全量、可追溯 |
| 「源」的识别 | 优先 `tags` 中第一个 `source:` 标签值 → 回退 `source_org`(事件组织名)→ 再回退 `"unknown"` |
| 高危阈值与排序 | 过滤 `severity ∈ 允许集`(默认仅 `high`);排序 `confidence DESC NULLS LAST, last_seen DESC`;每源取前 N |
| 「每天」语义 | **每日快照覆盖**:每次生成时每源从全部符合条件的 IOC 取 Top-N,**覆盖写** `intel.yaml`;规则总量恒定 ≈ 源数 × N,幂等可复现。频率复用现有 `ta_node_push_interval_seconds`(设为 `86400` 即每天) |
| 前端展示 | 在 `config.html` 新增 section 卡片,走只读 API `GET /indicators/top`;数据实时按当前库计算,不落历史快照 |
| 兼容性 | `ta_node_top_per_source = 0` 时关闭精选,退回现有「全量 traffic + to_ids」增量推送行为 |

## 3. 架构

```
MISP(全量)
   │  sync_misp(每 10min,不改动)——附带补充 source_org 填充
   ▼
intel_indicator 表(全量保留)
   │
   ├─ select_top_per_source(db, top_n, min_severity)   ← 新增公共函数(单一实现)
   │        │
   │        ├─ generate_ta_node_ioc_package  → 覆盖写 intel.yaml → TA 节点
   │        └─ GET /indicators/top           → 前端「每日 Top」卡片
```

精选逻辑抽出为单一函数,推送与展示两处复用,从根本上杜绝「前端看到的」与「实际推送的」不一致。

## 4. 组件设计

### 4.1 公共精选函数 `app/services/selection.py`(新建)

```python
# 允许集:min_severity -> 参与精选的 severity 集合
SEVERITY_TIERS = {"high": {"high"},
                  "medium": {"high", "medium"},
                  "low": {"high", "medium", "low"}}

def indicator_source(indicator: IntelIndicator) -> str:
    """从 tags 找第一个 'source:' 标签值;回退 source_org;再回退 'unknown'。"""

def select_top_per_source(db, top_n: int, min_severity: str) -> list[dict]:
    """
    返回按源分组的精选结果,每组 {"source": str, "items": list[IntelIndicator]}。
    过滤: platform_category == 'traffic' AND to_ids == True
           AND severity ∈ SEVERITY_TIERS[min_severity]
    分组: indicator_source(row)
    排序: (confidence DESC NULLS LAST, last_seen DESC)
    截断: 每组前 top_n 条(top_n <= 0 表示不截断)
    分组顺序稳定(按 source 名排序),便于展示与测试。
    """
```

- 排序在 DB 层尽量下推(`confidence` 降序、`last_seen` 降序),`NULLS LAST` 用数据库无关写法(如 `confidence.is_(None)` 次序键)保证 PostgreSQL 与 SQLite(测试)一致。
- 分组在 Python 层完成(源自 tags/字段派生,SQL 不易表达)。

### 4.2 推送层改造 `app/services/ta_node_client.py`

`generate_ta_node_ioc_package(db, mode, batch_size)`:
- 读取有效配置 `ta_node_top_per_source`、`ta_node_min_severity`。
- **当 `top_per_source > 0`(精选模式)**:候选 = `select_top_per_source(db, top_per_source, min_severity)` 摊平 → **覆盖写** `intel.yaml`(每日快照)。运行状态以 `SyncState`(本次 `count`、`last_success_at`、`status`)为准;纳入本次快照的 indicator 置 `pushed_to_ta_node=True/pushed_at=now`,未纳入的不改动其既有标记。快照覆盖非增量,故 `pushed_to_ta_node` 在此模式下仅表示「曾被某次快照纳入」,不作为过滤依据(见 §6 pending 语义)。
- **当 `top_per_source == 0`**:保持现有逻辑(`platform_category=='traffic' AND to_ids`,`mode` 增量/全量,`batch_size` 限制)不变。
- `map_indicator_to_ta_node_item` 复用不变;`source` 字段仍填 `ta_node_source_name`(TA 节点侧「数据来源」语义指本平台,不变)。

### 4.3 展示 API `app/api/indicators.py`

新增 `GET /indicators/top`:

- Query 参数:`top_per_source: int | None`、`min_severity: str | None`(省略时取 `get_effective_settings` 的配置值;允许覆盖以便前端预览不同参数)。
- `min_severity` 校验 ∈ {high, medium, low},非法返回 422。
- 响应:
```json
{ "generated_at": 1783372800, "top_per_source": 10, "min_severity": "high",
  "sources": [ { "source": "otx", "count": 10,
                 "items": [ {"value","misp_type","normalized_type","severity",
                             "confidence","last_seen","tags"}, ... ] },
               ... ] }
```
- item 序列化复用/对齐现有 `serialize`,补充 `confidence` 字段。

### 4.4 源填充附带改动 `sync_misp` + `upsert_indicator`

当前 `source_org` 字段存在但从未写入。为让 CIRCL/botvrij 等无 `source:` 标签的 feed 数据可分源:
- `app/services/misp_client.py::_fetch_attributes`:MISP `search` 增加返回事件上下文(如 `include_event_uuid`/`includeEventTags` 或 `withAttachments=False, include_context=True`),使属性带回其 Event 的 `Orgc.name`。
- `app/services/indicator_service.py::upsert_indicator`:填充 `indicator.source_org = 事件 Orgc 名`(从 attribute 关联的 Event 提取,取不到则保持 None)。

> 注:此改动只增加字段填充,不改变过滤/入库语义,对现有行为向后兼容。

### 4.5 前端参数接入(四处)

| 文件 | 改动 |
|---|---|
| `app/config.py` | `DEFAULTS` 加 `TA_NODE_TOP_PER_SOURCE="10"`、`TA_NODE_MIN_SEVERITY="high"`;`Settings` 加 `ta_node_top_per_source: int`、`ta_node_min_severity: str`;`settings_from_values` 映射与类型转换 |
| `app/services/config_service.py` | `API_TO_ENV` 加两键;`public_config` 输出两值 |
| `app/templates/config.html` | 「ta_node 规则文件」section 内加 `每源条数`(number)、`最低危险度`(select: high/medium/low);新增「每日 Top 高危流量情报」section |
| `app/static/config.js` | 读写两参数;新增 Top 列表加载/渲染逻辑 |

### 4.6 前端「每日 Top 高危流量情报」卡片

- 控件:`每源条数`、`最低危险度` 输入(默认取配置值)+ `刷新` 按钮。
- 主体:按源分组表格,列 `源 | 值 | 类型 | 危险度 | 置信度 | 最近出现`。
- 行为:调 `GET /indicators/top?...` 实时渲染;展示即「此刻若生成规则会推送的精选集」。
- 样式复用现有内联 CSS(新增最小 table 样式)。

## 5. 数据流与幂等

- 每次生成:纯函数 `select_top_per_source` → 覆盖写 `intel.yaml` + `intel.zip`。相同库状态 → 相同输出(幂等)。
- 规则总量恒定 ≈ Σ min(源i 数量, N),不随时间膨胀。
- 「每天」由调度频率保证(`ta_node_push_interval_seconds=86400`);严格定点(如每日 08:00)为后续可选项(celery crontab),本次不实现。

## 6. 边界与错误处理

- 无 `source:` 标签且无 `source_org` 的 IOC → 归入 `"unknown"` 源,仍参与(不静默丢弃)。
- `confidence` 为 NULL → 排序置于该源末尾(NULLS LAST)。
- `min_severity` 非法值 → API 返回 422;推送层遇非法配置回退到默认 `high` 并记录告警。
- 某源条数不足 N → 取全部(不补齐、不跨源借位)。
- `top_per_source == 0` → 关闭精选,行为与当前版本完全一致。
- 精选模式下 `pending_and_pushed_counts` 的 pending 计数不代表「欠推」(未进 Top-N 的高危项会长期为 not-pushed),仅作信息展示;推送是否成功以 `SyncState.status` 与 `last_success_at` 判断。

## 7. 测试策略

单元(`selection.py`):
- `indicator_source`:三级回退(有 `source:` 标签 / 无标签有 `source_org` / 都无→unknown);多个 `source:` 标签取第一个。
- `select_top_per_source`:每源截断到 N;severity 允许集(high / medium / low 三档)过滤;排序键(confidence 降序,平手按 last_seen 降序,NULL 置尾);某源少于 N 取全部;多源分组;`top_n=0` 不截断。

集成:
- `GET /indicators/top`:返回结构、`count == len(items)`、参数覆盖生效、`min_severity` 非法返回 422。
- `generate_ta_node_ioc_package` 精选模式:写出的 `intel.yaml` items 数 == Σ min(源i, N);`top_per_source=0` 时退回原行为(扩展现有 `test_push.py`)。

回归:现有 `test_push.py`、`test_exports.py` 保持通过。

## 8. 兼容性与回滚

- 新参数默认 `top_per_source=10 / min_severity=high`:**升级后默认即启用精选**。若需保留旧全量行为,将 `每源条数` 设为 `0`。
- `source_org` 填充为纯增量字段写入,不影响既有数据读取。
- 回滚:参数置 0 即恢复旧推送语义;新 API 与前端卡片为增量,不影响既有端点。

## 9. 不做(YAGNI)

- 不做按日期回看的历史快照存储(展示只呈现当前实时精选)。
- 不做严格定点调度(先用间隔;定点留待需要时上 celery crontab)。
- 不做每源独立的 N/severity(全局统一参数)。
- 不改 `sync_misp` 的过滤与入库语义(仅补 `source_org` 填充)。
