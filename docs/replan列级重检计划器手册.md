# 列级变更影响与最小重检计划器（replan）使用手册

## 1. 定位与边界

`replan` 是一个**独立**的离线工具，解决“每来一个新数据包都要从压缩包、字段、
血缘到抽检整包重跑”的问题。它接收：

- 上一版数据包（zip / tar.gz / 已展开目录，可选）；
- 上一版数据包的**准入结果存档**（含列级指纹，可选但强烈建议提供）；
- 当前数据包；
- 当前数据契约；
- 当前血缘规则。

输出两份产物：

- **可执行的 JSON 重检计划**：精确到表、列、规则、血缘关系的三级决策；
- **可归档的 Markdown 摘要**：人工可读的触发原因、依据与可沿用清单。

它**不修改、不依赖任何现有 gateway 校验逻辑**，不连接网络、不使用外部数据库，
零第三方依赖（仅 Python 标准库；PyYAML/pyarrow 存在时自动利用，缺失时安全降级），
兼容 Python 3.9 / 3.10 / 3.11。

## 2. 三级决策

| 决策 | 含义 |
| --- | --- |
| `must_recheck` | 旧结论确定失效，必须重检（改名、删除、类型收窄、可空性收紧、约束变化、数据指纹变化、被外键传播命中） |
| `suggested_recheck` | 旧结论大概率有效但存在语义风险，建议重检（类型放宽、可空性放宽、启发式改名） |
| `reuse` | 列级 SHA256 指纹与规则指纹均未变化，旧抽检/血缘结论可沿用 |

关键不是“列出差异”，而是据此**收窄实际重检范围**，并明确哪些旧结论仍可沿用。

## 3. 命令行用法

```bash
PYTHONPATH=/path/to/repo python3 -P -m replan \
  --old-packet   /data/old/retail_v1.zip \
  --old-archive  /data/old/admission_v1.json \
  --packet       /data/new/retail_v2.zip \
  --contract     /conf/contract.yaml \
  --lineage      /conf/lineage.yaml \
  --plan-out     /out/recheck_plan.json \
  --summary-out  /out/recheck_summary.md \
  --emit-archive /out/admission_v2.json \
  --temp-base    /var/tmp/replan
```

`-P` 把当前目录/脚本目录排除出 `sys.path`，防止数据目录中被植入的同名模块
（例如 `json.py`）被导入；`PYTHONPATH` 只注入受信任的代码目录。

退出码：

| 码 | 含义 |
| --- | --- |
| 0 | 成功，包括保守降级为整包全量重检（降级原因写入计划） |
| 2 | 致命输入错误：当前数据包/契约/血缘缺失或无法读取，无计划产出 |
| 3 | 输出落盘失败 |

## 4. 数据流与列级指纹

### 4.1 流式只读读取

- zip/tar.gz 直接流式读取成员，**不做整包解压**；目录形态只读遍历；
- 只有需要随机访问的 SQLite/Parquet 表文件会被复制进隔离临时目录；
- 每个成员计算 SHA256，用于与旧存档的完整性声明交叉核对；
- 支持 CSV（UTF-8/UTF-8 BOM/GBK）、JSONL、SQLite；Parquet 在有 pyarrow 时可用。

### 4.2 列级指纹

对每张表的每一列，按物理行序逐单元格更新一个 SHA256。单元格采用
**类型标签 + 长度前缀 + 内容**的确定性编码，避免 `["a","b"]` 与 `["ab"]`
之类的拼接歧义，并正确区分 `1`（整数）、`1.0`（浮点）、`"1"`（文本）、
`true`（布尔）、空值。同时记录 `row_count` 与 `null_count`。

```
列指纹   = sha256( concat( b"r" + encode(cell) for cell in 列 ) )
表/整包指纹 = 基于成员名与成员 SHA256 的规范化 JSON 再哈希
```

## 5. 差异识别与引用传播

### 5.1 改名列映射（两层）

1. **显式映射（高置信）**：契约 `column_renames` 声明
   `{table: [{from: 旧名, to: 新名}]}`。命中即 `must_recheck`，因为名称绑定的
   规则与引用关系必须按新名重新解析。
2. **启发式映射（低置信）**：无显式声明时，若旧列与新列的列级指纹完全一致、
   仅列名不同，则判定为疑似改名，给 `suggested_recheck`，在计划中标注
   `mapping: heuristic`，不静默当成同一列直接沿用。

### 5.2 列事件

| 事件 | 决策 |
| --- | --- |
| 新增可空列 | 该列 `must_recheck`，同表未改列仍可沿用 |
| 新增非空列 | 该列 `must_recheck`，整表行结构变化 |
| 删除列 | `must_recheck`，绑定规则与引用全部失效，列入 `removed_columns` |
| 类型收窄（number→integer、跨数值/文本族等） | `must_recheck` |
| 类型放宽（integer→number 同族） | `suggested_recheck` |
| 可空性收紧 | `must_recheck`；可空性放宽 | `suggested_recheck` |
| 约束变化（enum/pattern/长度/范围） | `must_recheck` |
| 数据指纹变化 | `must_recheck`（改名列上为建议级） |
| 指纹与定义均未变 | `reuse` |

### 5.3 沿引用关系传播

血缘规则解析为以 `(表, 列)` 为节点、外键关系为边的邻接表。任何参与血缘的
节点发生非 `reuse` 变化（含被删除、改名、键值变化），都沿边做 BFS 传播：

- 被外键引用的键变化 → 引用方对应列 `must_recheck`，原因码 `lineage_propagated`，
  并记录 `via_relation`、上游节点与传播深度；
- 对应血缘关系本身标记 `must_recheck`；
- 传播可跨多跳，递归覆盖整条引用链。

因此判断不只依赖表名或文件哈希。

## 6. 保守降级（绝不静默漏检）

出现以下任一情况，计划模式从 `targeted` 切换为 `full_fallback`，
所有表/列/规则/关系一律 `must_recheck`，并在 `fallback_reasons` 与
Markdown 第一节写明**可读原因 + 稳定原因码**：

| 原因码 | 触发条件 |
| --- | --- |
| `missing_old_archive` | 未提供旧准入存档 |
| `old_archive_table_level_only` | 旧存档是 gateway 历史表级摘要，无列级指纹块 |
| `old_archive_missing_fingerprints` | 列级指纹字段不全（缺 sha256/row_count/null_count） |
| `old_archive_unreadable` / `old_archive_invalid` | 旧存档编码或格式无法可靠读取 |
| `old_packet_mismatch` | 旧数据包成员哈希/表/列与存档声明不一致，旧指纹不可信 |
| `old_packet_unreadable` | 旧数据包无法可靠读取，无法交叉核对 |
| `packet_read_error` | 当前/旧包成员编码、行列结构、SQLite 完整性等无法可靠读取 |
| `unsupported_format` | 如缺少 pyarrow 却遇到 Parquet |
| `rule_reference_unresolved` | 契约/血缘引用的表或列无法解析 |
| `old_archive_missing_contract_snapshot` / `..._lineage_snapshot` | 契约/血缘已变但存档缺少对应快照，无法逐列/逐条比较 |

> 历史存档字段不全是常态。规划器的原则是：**无法可靠判断就全量重检并标注原因，
> 永远不基于猜测沿用旧结论。**

## 7. 确定性保证

相同输入重复运行，除 `generated_at` 外产出**字节级一致**的计划：

- 所有 JSON 以 `sort_keys=True`、统一缩进与分隔符序列化；
- 成员、表、列、规则、关系、原因列表全部按稳定键显式排序，不依赖
  目录遍历顺序或字典插入序；
- 单元格编码、指纹计算均为纯函数；
- 计划内容指纹 `plan_fingerprint` 只覆盖内容字段，显式排除 `generated_at`
  与 `environment`（数据包包体路径、zip/tar/目录形态等环境信息），
  因此同内容的不同承载形态产生相同指纹；
- 输出经同目录临时文件 + `os.replace` 原子落盘，并发运行不会互相截断。

## 8. 临时目录隔离与清理

- 每次运行在 `--temp-base`（默认系统临时目录）下创建
  `replan-<pid>-<uuid8>` 独立目录，并发分析同一输入目录互不干扰；
- `WorkDir` 上下文管理器在正常结束、异常、`SIGINT`/`SIGTERM` 时清理，
  并由 `atexit` 兜底；清理用 `rmtree(ignore_errors=True)`，不掩盖原始异常；
- `cleanup_stale()` 只清理前缀匹配且属主进程已不存在的遗留目录，
  不会误删并发运行中的目录；
- 输入数据包始终只读，不向输入目录写入。

## 9. 存档格式（replan-admission-archive/1）

可由 `--emit-archive` 生成，或由准入流水线按此结构产出：

```json
{
  "schema": "replan-admission-archive/1",
  "packet": {"kind": "zip", "files": {"data/t.csv": {"sha256": "..."}}},
  "contract_fingerprint": "...",
  "lineage_fingerprint": "...",
  "contract": {"tables": {"t": {"fields": {"c": {"type": "string",
    "nullable": true, "required": false, "constraints": {}}}}}},
  "lineage": {"edges": [{"name": "r", "fingerprint": "..."}]},
  "tables": {"t": {"member": "data/t.csv", "format": "csv",
    "row_count": 10,
    "columns": {"c": {"sha256": "...", "row_count": 10, "null_count": 0}}}},
  "rules": [{"id": "t.c.range.0", "fingerprint": "...",
    "table": "t", "column": "c", "kind": "range"}],
  "admission": {"passed": true, "task_id": "..."}
}
```

## 10. JSON 计划结构（replan-minimal-recheck/1，节选）

```json
{
  "schema": "replan-minimal-recheck/1",
  "mode": "targeted",
  "fallback_reasons": [],
  "scope_summary": {"columns": {"must_recheck": 1,
    "suggested_recheck": 0, "reuse": 7}, "reuse_ratio": 0.875},
  "table_changes": {"added": [], "removed": [],
    "renames": {"trades": [{"from": "amount", "to": "trade_amount",
      "confidence": "explicit"}]}},
  "columns": [{"table": "trades", "column": "trade_amount",
    "decision": "must_recheck", "events": ["renamed_column", "type_narrowed"],
    "old_name": "amount", "reasons": [{"code": "type_narrowed",
      "message": "..."}]} ],
  "rules": [{"rule_id": "trades.trade_amount.range.0",
    "decision": "must_recheck", "reasons": []}],
  "relations": [{"relation": "trade_owner", "decision": "reuse"}],
  "recheck_plan": {"full_recheck": false,
    "tables": [{"table": "trades", "must_columns": ["trade_amount"],
      "rule_ids": ["trades.trade_amount.range.0"], "relation_names": []}],
    "rule_ids": [], "relation_names": []},
  "reuse_evidence": {"columns": [], "rules": [], "relations": []},
  "plan_fingerprint": "...",
  "generated_at": "2026-01-01T00:00:00Z"
}
```

`recheck_plan` 可直接被现有校验流水线消费：只跑列出的表/列/规则/关系，
其余依据 `reuse_evidence` 沿用上一版结论。

## 11. 测试

```bash
./test_replan.sh
# 或
PYTHONPATH=. python3 -P -m unittest tests.replan.test_planner \
  tests.replan.test_extended -v
```

覆盖：改名+类型收窄命中与外键传播、新增可空列、删除列、新增/删除表、
规则定义变化、缺存档/表级摘要/指纹不全/旧包篡改/成员损坏/引用解析失败的
降级路径、跨 zip/tar/目录的确定性、两次并发分析、临时目录异常清理与
遗留回收、路径穿越/重复成员拦截、GBK/JSONL/SQLite 读取。
