# 数包闸检

面向跨安全域数据交换场景的**离线结构化数据包准入校验工具**。工具在本机完成压缩包安全检查、完整性核验、数据契约校验、跨表血缘一致性与异常值抽检，输出可归档的 Markdown、HTML、JSON 报告，并把任务历史保存在本地 SQLite 中。

- 纯本地运行，不连接云服务、外部 API、消息队列或外部数据库。
- 默认仅监听 `127.0.0.1:5000`，页面资源全部本地化，不引用 CDN。
- 适用 Python 3.9、3.10、3.11；已在三个版本分别跑通全部测试。
- 仅做入域校验，不承担 ETL、清洗、脱敏、调度、治理平台等职责。

## 一、适用场景

1. 业务方把 csv、parquet、sqlite 数据组织成 zip 或 tar.gz 数据包，经单向导入设备送入内网。
2. 接收方在导入前检查压缩包是否存在路径穿越、压缩炸弹、可执行文件、符号链接等风险。
3. 核对 manifest 声明的文件清单与 MD5/SHA256，拦截缺失、冗余和被篡改文件。
4. 按数据契约检查字段、类型、非空、枚举、正则、长度、日期等约束。
5. 检查用户、交易、商品、订单等表之间的引用完整性与基数关系。
6. 对抽样数据执行范围、正则、日期、空值率、重复率等异常规则，保留 Top20 样例。
7. 生成可审计报告，供人工复核、归档和问题退回。

## 二、功能清单

| 模块 | 能力 |
| --- | --- |
| 压缩包安全 | zip/tar.gz、路径规范化、拒绝越界/绝对路径/链接/设备文件、条目数限制、解压总量与单文件限制、压缩比检测、重复成员拦截、加密包拦截 |
| 完整性校验 | 逐文件 MD5/SHA256、manifest 声明文件核对、冗余文件检测、可选整包哈希、危险扩展名黑名单与白名单例外；manifest 路径统一反斜杠、`./` 与大小写后比对 |
| Schema 校验 | JSON Schema Draft 7、字段缺失、多余字段、类型、required、nullable、enum、minimum/maximum、pattern、minLength/maxLength、format、别名映射 |
| 血缘校验 | 一对多、多对一、一对一；空引用、孤立记录、被引用键缺失、基数异常；跨 csv/parquet/sqlite 键规范化；文字与 Mermaid 链路图 |
| 异常抽检 | range、regex、date、null_rate、duplicate_rate、受控 custom 函数；确定性抽样；阈值与异常率；Top20 样例 |
| 报告与历史 | Markdown/HTML/JSON；HTML 单文件内联样式；配置指纹与工具版本；历史/详情/报告状态一致；原子写入；SQLite 任务历史、筛选、删除 |
| 安全运行 | 仅回环监听、上传临时目录隔离、自动清理、CSP/X-Frame-Options/nosniff、报告路径越界防护 |

## 三、目录结构

```text
gateway/            应用工厂、流水线、解析器、校验器、报告与存储
fixtures/           内置契约、血缘规则、样例数据包生成脚本
templates/          Jinja2 页面模板
static/             本地 CSS 与 JavaScript
tests/              单元、集成与安全测试
docs/               契约配置、血缘规则、离线部署运维手册
run.sh / run.bat    一键启动
test.sh / test.bat  一键测试（覆盖率门槛 85%）
requirements.txt    固定版本依赖
```

## 四、环境准备

### 4.1 联网机器预下载依赖

在可联网的同架构、同 Python 版本机器上执行：

```bash
python -m pip download -r requirements.txt -d vendor/wheels
```

把项目与 `vendor/wheels` 一并复制到离线机器。依赖均为公开开源包，不含业务数据。

### 4.2 离线安装

```bash
python -m venv .venv
# Windows
.venv\Scripts\python -m pip install --no-index --find-links vendor/wheels -r requirements.txt
# Linux / macOS
.venv/bin/python -m pip install --no-index --find-links vendor/wheels -r requirements.txt
```

`python-magic` 是可选的增强识别项。Windows 缺少 libmagic 时自动退回安全默认 MIME，不影响核心校验。

## 五、启动与访问

```bash
# Linux / macOS
./run.sh
# Windows
run.bat
```

浏览器访问 `http://127.0.0.1:5000`。可通过环境变量指定解释器与工作目录：

```bash
PYTHON=/opt/py311/bin/python GATEWAY_WORKSPACE=/srv/gateway-data ./run.sh
```

工作目录默认是项目下的 `workspace/`，启动后自动创建 `reports/`、`uploads/`、`tmp/`、`logs/` 和 `gateway.db`。服务只允许绑定 `127.0.0.1`、`localhost` 或 `::1`。

## 六、使用流程

1. 在首页选择内置样例契约 `trade` 或 `product`，也可上传自定义契约与血缘 YAML。
2. 选择 zip 或 tar.gz 数据包；可填写整包 SHA256 作为额外校验。
3. 提交后进入任务详情，查看压缩包、哈希、表读取、Schema、血缘、异常抽检六类结果。
4. 下载 Markdown、HTML 或 JSON 报告；HTML 报告可脱离系统直接打开。
5. 在历史任务页按 ID/名称、状态、日期筛选；删除任务会同时清理报告与日志。

## 七、数据包约定

压缩包根目录必须包含 `manifest.yaml`，其中 `files` 声明文件哈希，`tables` 声明逻辑表到文件路径的映射：

```yaml
schema_version: "1.0"
packet:
  name: retail_valid_1
tables:
  users: {path: data/users.csv, format: csv}
  products: {path: data/products.parquet, format: parquet}
  orders: {path: data/orders.sqlite, format: sqlite, table: orders}
files:
  data/users.csv: {md5: "...", sha256: "..."}
```

详细字段与校验规则见 `docs/契约配置手册.md`。仓库中的 `fixtures/valid_packets/` 提供 2 份 zip 与 2 份 tar.gz 合法包；`fixtures/invalid_packets/` 提供 8 类异常包。

重新生成样例：

```bash
python fixtures/generate_fixtures.py
```

## 八、测试与覆盖率

```bash
# Linux / macOS
./test.sh
# Windows
test.bat
```

脚本运行全部单元、集成与安全用例，覆盖率低于 85% 时返回非零退出码。测试覆盖：

- 4 份合法包全流程通过，含跨格式表与自定义契约/血缘上传。
- 8 类异常包：字段类型不符、字段缺失、血缘断裂、哈希篡改、空值率超标、路径穿越、Zip 炸弹、冗余文件。
- 路径穿越无法逃逸、压缩炸弹预检拦截、可执行文件拦截、网络访问拦截、离线页面资源检查。
- 核心校验模块目标覆盖率 100%，项目整体门槛 85%。

本机实测：Python 3.9.25、3.10.21、3.11.16 在固定依赖下均为 **102 passed**，覆盖率 92.77%；另在 Python 3.13.15 的较新依赖环境中回归同样全部通过。正式支持范围仍为 3.9–3.11。

## 九、配置项摘要

配置可通过 `AppConfig` 注入或在代码中调用 `load_config(path)` 加载 YAML。常用项：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `host` / `port` | `127.0.0.1` / `5000` | 仅允许回环地址 |
| `sample_ratio` | `0.1` | 异常抽检比例，血缘使用全量 |
| `random_seed` | `42` | 抽样可复现 |
| `max_uncompressed_bytes` | 10 GiB | 解压总量上限 |
| `max_single_file_bytes` | 4 GiB | 单文件上限 |
| `max_archive_entries` | 5000 | 条目数上限 |
| `max_compression_ratio` | 500 | 压缩比阈值 |
| `max_content_length` | 1.5 GiB | 上传请求体上限 |
| `blocked_extensions` | 内置列表 | 可执行/脚本扩展名 |
| `allowed_extra_paths` | 空 | 允许的额外文件路径 |

## 十、安全边界

- 解压只写入 `workspace/tmp/gateway-*` 随机目录，结束或异常时自动清理。
- 上传副本只写入 `workspace/tmp/upload-*`，请求结束即删除。
- 成员路径经 POSIX 规范化，拒绝 `..`、绝对路径、盘符、重复成员、符号/硬链接与设备文件，并拒绝仅大小写不同的重复成员。
- 超过总量、单文件、条目数或压缩比阈值时，在解压前终止。
- 报告下载与日志预览均校验路径必须位于对应工作子目录。
- 自定义异常规则只从 `gateway/validator/custom_rules.py` 的白名单加载，不执行上传代码。
- 应用不包含任何出站网络调用；测试会拦截 socket 连接并扫描禁用导入。

## 十一、明确不做

本工具不实现实时网关、ETL/清洗/脱敏、分布式调度、非结构化媒体分析、外部数据库/API/MQ 连接器、自动修复或重跑、通用命令行工具、爬虫、用户/RBAC/多租户。以上能力应在其他系统承担。

## 十二、常见问题

**上传后提示缺少 manifest.yaml**：确认清单位于压缩包根目录，而不是外层再套一层目录。

**SQLite 表读取失败**：确认 `manifest.tables` 中 `format: sqlite` 且 `table` 名称正确，数据库未加密、未损坏。

**中文 CSV 乱码**：读取器依次尝试 UTF-8 与 GBK；仍失败时请在上游统一为 UTF-8。

**报告下载 404**：报告文件可能已被手工删除，任务记录仍在；删除该任务后重新提交。

**Windows 删除任务提示文件占用**：关闭正在查看的报告文件后重试；系统也会尽力保留记录供后续清理。

**端口被占用**：修改配置中的 `port`，保持 `host` 为回环地址。

## 十三、版本

当前版本 `1.0.0`。变更时同步更新 `gateway/__init__.py`、报告页脚与本文档。
