"""列级变更影响与最小重检计划器（replan）。

独立于现有 gateway 校验流水线：本包只读输入数据包/存档并产出重检计划，
不修改、不依赖任何现有校验逻辑。零第三方依赖，兼容 Python 3.9-3.11，
完全离线运行。
"""

__version__ = "1.0.0"

MUST = "must_recheck"
SUGGESTED = "suggested_recheck"
REUSE = "reuse"

SEVERITIES = (MUST, SUGGESTED, REUSE)
SEVERITY_RANK = {MUST: 3, SUGGESTED: 2, REUSE: 1}

MODE_TARGETED = "targeted"
MODE_FULL_FALLBACK = "full_fallback"
