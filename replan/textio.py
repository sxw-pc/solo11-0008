"""文本读取与最小 YAML 子集解析。

工具默认支持 JSON（.json）与 YAML（.yaml/.yml）。环境中若安装了 PyYAML
则优先使用；否则使用本模块内置的最小缩进解析器，保证在只有标准库的
离线机器上也能读取 gateway 风格的契约/血缘/manifest 文件。

内置解析器仅覆盖数据包配置常见子集：

* 键值映射、嵌套映射、列表（``- item`` 与块内联 ``[a, b]``）
* 标量：字符串、整数、浮点、true/false、null、单/双引号字符串
* ``#`` 注释、空行、UTF-8

不支持锚点、多文档、流式花括号映射、多行字符串等高级特性；遇到无法
可靠解析的内容时抛出 :class:`ValueError`，由上层保守降级，绝不静默猜测。
"""

import json
import os
import re

_SCALAR_RE = re.compile(r"^-?[0-9]+$")
_FLOAT_RE = re.compile(r"^-?[0-9]+\.[0-9]+$")


def read_text_file(path):
    """以 UTF-8（允许 BOM）读取文本文件，失败时抛出 OSError/UnicodeError。"""
    with open(path, "r", encoding="utf-8-sig") as handle:
        return handle.read()


def _strip_comment(text):
    """移除 # 注释（引号内的 # 保留）。"""
    result = []
    in_single = in_double = False
    for char in text:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            break
        result.append(char)
    return "".join(result)


def _parse_scalar(raw):
    text = raw.strip()
    if text == "":
        return None
    if (text.startswith('"') and text.endswith('"')) or \
            (text.startswith("'") and text.endswith("'")):
        return text[1:-1]
    low = text.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", "none"):
        return None
    if _SCALAR_RE.match(text):
        return int(text)
    if _FLOAT_RE.match(text):
        return float(text)
    return text


def _split_inline_list(text):
    """解析 ``[a, b, c]`` 形式的内联列表。"""
    inner = text.strip()
    if not (inner.startswith("[") and inner.endswith("]")):
        raise ValueError("无法解析的内联值: %r" % text)
    inner = inner[1:-1].strip()
    if not inner:
        return []
    return [_parse_scalar(part) for part in _split_top_level(inner)]


def _split_top_level(text):
    """按顶层逗号切分（忽略引号内逗号）。"""
    parts, buf = [], []
    in_single = in_double = False
    for char in text:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if char == "," and not in_single and not in_double:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return parts


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def parse_yaml_subset(text):
    """把 YAML 子集文本解析为 dict/list/标量。"""
    lines = []
    for raw in text.splitlines():
        cleaned = _strip_comment(raw.rstrip())
        if cleaned.strip():
            lines.append(cleaned)
    if not lines:
        return {}
    value, index = _parse_block(lines, 0, _indent(lines[0]))
    if index != len(lines):
        raise ValueError("YAML 缩进结构无法可靠解析（第 %d 行附近）" % (index + 1))
    return value


def _parse_block(lines, start, indent):
    """解析缩进不小于 ``indent`` 的一个块，返回 (value, 下一行索引)。"""
    if start >= len(lines):
        return None, start
    first = lines[start].strip()
    if first.startswith("- "):
        return _parse_list(lines, start, indent)
    if first == "-":
        return _parse_list(lines, start, indent)
    return _parse_map(lines, start, indent)


def _parse_map(lines, start, indent):
    result = {}
    index = start
    while index < len(lines):
        line = lines[index]
        current_indent = _indent(line)
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ValueError("YAML 出现意外缩进（第 %d 行）" % (index + 1))
        content = line.strip()
        if content.startswith("- "):
            raise ValueError("YAML 映射位置出现列表项（第 %d 行）" % (index + 1))
        if ":" not in content:
            raise ValueError("YAML 映射项缺少冒号（第 %d 行）: %r" % (index + 1, content))
        key, _, rest = content.partition(":")
        key = _parse_scalar(key.strip())
        rest = rest.strip()
        index += 1
        if rest:
            if rest.startswith("["):
                result[key] = _split_inline_list(rest)
            else:
                result[key] = _parse_scalar(rest)
            continue
        # 子块（映射或列表），缩进必须更深。
        if index < len(lines) and _indent(lines[index]) > indent:
            child_indent = _indent(lines[index])
            value, index = _parse_block(lines, index, child_indent)
            result[key] = value
        else:
            result[key] = None
    return result, index


def _parse_list(lines, start, indent):
    result = []
    index = start
    while index < len(lines):
        line = lines[index]
        current_indent = _indent(line)
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ValueError("YAML 出现意外缩进（第 %d 行）" % (index + 1))
        content = line.strip()
        if not content.startswith("-"):
            break
        item_text = content[1:].strip()
        index += 1
        if not item_text:
            # 列表项是一个嵌套块。
            if index < len(lines) and _indent(lines[index]) > indent:
                value, index = _parse_block(lines, index, _indent(lines[index]))
                result.append(value)
            else:
                result.append(None)
            continue
        if ":" in item_text and not (
                item_text.startswith('"') or item_text.startswith("'")):
            # 列表项是一个映射：把 "- key: value" 视作映射首行。
            key, _, rest = item_text.partition(":")
            synthetic = " " * (indent + 2) + key.strip() + ":" + rest
            map_lines = [synthetic]
            child_indent = indent + 2
            while index < len(lines) and _indent(lines[index]) > indent:
                map_lines.append(lines[index])
                index += 1
            value, _ = _parse_map(map_lines, 0, child_indent)
            result.append(value)
        elif item_text.startswith("["):
            result.append(_split_inline_list(item_text))
        else:
            result.append(_parse_scalar(item_text))
    return result, index


def load_structured_file(path):
    """按扩展名加载 JSON/YAML 配置文件。

    优先使用 PyYAML（若环境已安装）；否则回退到内置子集解析器。
    任何解析失败都抛出 :class:`ValueError`，由调用方决定降级方式。
    """
    text = read_text_file(path)
    ext = os.path.splitext(str(path))[1].lower()
    if ext == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore
    except ImportError:
        return parse_yaml_subset(text)
    return yaml.safe_load(text)
