#!/usr/bin/env bash
# replan 列级变更影响与最小重检计划器的独立测试入口。
# 仅使用标准库 unittest，无需 pytest/第三方依赖，兼容 Python 3.9-3.11。
# 不触碰 gateway 现有测试与覆盖率门槛。
set -euo pipefail
cd "$(dirname "$0")"
if [ -n "${PYTHON:-}" ]; then
  PYTHON_BIN="$PYTHON"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  PYTHON_BIN="python"
fi
# -P：把脚本目录/当前目录排除出 sys.path，防止数据目录中的同名模块（如
#  planted json.py）被导入；PYTHONPATH 仅注入受信任的仓库代码目录。
PYTHONPATH="$(pwd)" exec "$PYTHON_BIN" -P -m unittest \
  tests.replan.test_planner \
  tests.replan.test_extended \
  tests.replan.test_fallback -v
