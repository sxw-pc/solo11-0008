"""可扩展的异常规则函数白名单。

自定义函数签名为 ``func(series: pandas.Series) -> pandas.Series``，返回值
必须是同索引布尔序列，True 表示该行异常。函数只应使用标准库与 pandas，
不得执行网络访问、系统命令或文件改写。为避免执行任意上传代码，规则引擎
只允许调用本模块 ``CUSTOM_RULES`` 中登记的函数。
"""

from typing import Any, Callable, Dict

import pandas as pd


def no_negative(series: pd.Series) -> pd.Series:
    """数值字段不得为负数；非数值同样视为异常。"""
    numeric = pd.to_numeric(series, errors="coerce")
    return series.notna() & (numeric.isna() | (numeric < 0))


def non_empty(series: pd.Series) -> pd.Series:
    """字符串字段去除空白后不得为空。"""
    text = series.astype("string").str.strip()
    return series.notna() & (text.isna() | (text == ""))


CUSTOM_RULES: Dict[str, Callable[[pd.Series], Any]] = {
    "no_negative": no_negative,
    "non_empty": non_empty,
}


def get_custom_rule(name: str) -> Callable[[pd.Series], Any]:
    """按名称取自定义规则，未登记时抛出 KeyError。"""
    return CUSTOM_RULES[name]
