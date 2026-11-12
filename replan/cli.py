"""命令行入口。

用法::

    python -m replan \
        --old-packet   /path/old.zip \
        --old-archive  /path/old_admission.json \
        --packet       /path/new.zip \
        --contract     /path/contract.yaml \
        --lineage      /path/lineage.yaml \
        --plan-out     /out/recheck_plan.json \
        --summary-out  /out/recheck_summary.md

退出码：

* 0  成功（含保守降级为整包全量重检的情况，降级原因写入计划）；
* 2  致命输入错误（当前数据包/契约/血缘缺失或无法读取），无计划产出；
* 3  输出落盘失败。
"""

import argparse
import json
import sys

from .errors import PlannerError
from .planner import build_plan, build_archive_from_plan
from .render import atomic_write, canonical_json, render_markdown
from .workdir import cleanup_stale


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m replan",
        description="数据包列级变更影响与最小重检计划器（离线、零第三方依赖）")
    parser.add_argument("--old-packet",
                        help="上一版数据包（zip/tar.gz/目录），可选")
    parser.add_argument("--old-archive",
                        help="上一版准入结果存档（JSON/YAML），可选；"
                             "缺失或缺少列级指纹时保守全量降级")
    parser.add_argument("--packet", required=True,
                        help="当前数据包（zip/tar.gz/目录）")
    parser.add_argument("--contract", required=True, help="当前契约文件")
    parser.add_argument("--lineage", required=True, help="当前血缘规则文件")
    parser.add_argument("--plan-out", required=True,
                        help="JSON 重检计划输出路径")
    parser.add_argument("--summary-out", required=True,
                        help="Markdown 摘要输出路径")
    parser.add_argument("--temp-base",
                        help="临时目录根，默认使用系统临时目录")
    parser.add_argument("--emit-archive",
                        help="可选：把当前包的列级指纹存档写到该路径，"
                             "供下一版比对使用")
    parser.add_argument("--generated-at",
                        help="覆盖生成时间（测试确定性用，ISO 8601）")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cleanup_stale(args.temp_base)
        plan = build_plan(
            old_packet_path=args.old_packet,
            new_packet_path=args.packet,
            contract_path=args.contract,
            lineage_path=args.lineage,
            old_archive_path=args.old_archive,
            work_base=args.temp_base,
            generated_at=args.generated_at,
        )
        atomic_write(args.plan_out, canonical_json(plan))
        atomic_write(args.summary_out, render_markdown(plan))
        if args.emit_archive:
            archive = build_archive_from_plan(
                new_packet_path=args.packet,
                contract_path=args.contract,
                lineage_path=args.lineage,
                work_base=args.temp_base,
                admission={"generated_at": args.generated_at}
                if args.generated_at else None,
            )
            atomic_write(args.emit_archive,
                         json.dumps(archive, ensure_ascii=False, indent=2,
                                    sort_keys=True) + "\n")
    except PlannerError as exc:
        sys.stderr.write(json.dumps(
            {"error": True, "code": exc.code, "message": str(exc)},
            ensure_ascii=False, sort_keys=True) + "\n")
        return 2
    except OSError as exc:
        sys.stderr.write(json.dumps(
            {"error": True, "code": "output_write_failed",
             "message": str(exc)}, ensure_ascii=False, sort_keys=True) + "\n")
        return 3
    result = {
        "plan_out": args.plan_out,
        "summary_out": args.summary_out,
        "mode": plan["mode"],
        "plan_fingerprint": plan["plan_fingerprint"],
        "fallback_codes": sorted(
            reason["code"] for reason in plan["fallback_reasons"]),
        "scope_summary": plan["scope_summary"],
    }
    sys.stdout.write(json.dumps(result, ensure_ascii=False,
                                sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
