"""统一错误类型。

两类错误：

* :class:`PlannerError` —— 输入本身无法处理（当前数据包/契约缺失或损坏），
  对应 CLI 退出码 2，不能生成任何计划。
* :class:`FallbackError` —— 可被保守降级吸收的问题（旧存档缺列级指纹、
  旧包读不了、规则引用解析失败等），不中断流程，而是触发整包全量重检。
"""


class PlannerError(Exception):
    """致命输入错误：无法继续分析。"""

    def __init__(self, message, code="planner_error"):
        super().__init__(message)
        self.code = code


class FallbackError(Exception):
    """可降级问题：触发全量重检而不是中断。

    Args:
        message: 面向人工的可读原因（中文）。
        code: 稳定的机器可读原因码，用于 JSON 计划与测试断言。
        scope: 影响范围标识，默认 ``package`` 表示整包级降级。
    """

    def __init__(self, message, code, scope="package"):
        super().__init__(message)
        self.code = code
        self.scope = scope
