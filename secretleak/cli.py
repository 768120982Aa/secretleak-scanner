"""CLI 入口"""
import sys
import json
import argparse
import subprocess

from secretleak.engine import SecretScanner
from secretleak.hooks import install_precommit_hook
from secretleak.utils import Colors, cprint


def main():
    parser = argparse.ArgumentParser(
        prog="secretleak-scanner",
        description="SecretLeak Scanner — 敏感信息泄露扫描器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  %(prog)s scan .                          # 扫描当前目录（本地文件）
  %(prog)s scan . --git                    # 同时扫描本地文件 + Git 历史
  %(prog)s scan /path/to/project -g -v     # 全面扫描 + 详细输出
  %(prog)s git /path/to/repo               # 仅扫描 Git 历史
  %(prog)s install-hook                   # 安装预提交钩子
  %(prog)s check-staged                   # 扫描暂存文件（pre-commit 集成）
  %(prog)s report scan.json               # 查看 JSON 报告
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan 命令
    scan_parser = subparsers.add_parser("scan", help="扫描本地文件/目录（可配合 --git 同时扫 Git 历史）")
    scan_parser.add_argument("path", nargs="?", default=".", help="待扫描的目录或文件（默认: .）")
    scan_parser.add_argument("--exclude", "-e", nargs="+", default=[],
                             help="额外排除的目录")
    scan_parser.add_argument("--verbose", "-v", action="store_true",
                             help="显示详细上下文")
    scan_parser.add_argument("--output", "-o", help="导出 JSON 报告路径")
    scan_parser.add_argument("--git", "-g", action="store_true",
                             help="同时扫描目标目录的 Git 提交历史")

    # git 命令
    git_parser = subparsers.add_parser("git", help="扫描 Git 历史")
    git_parser.add_argument("path", nargs="?", default=".", help="Git 仓库路径（默认: .）")
    git_parser.add_argument("--output", "-o", help="导出 JSON 报告路径")

    # hook 命令
    hook_parser = subparsers.add_parser("install-hook", help="安装预提交钩子")
    hook_parser.add_argument("path", nargs="?", default=".", help="Git 仓库路径（默认: .）")

    # check-staged 命令（供 pre-commit 框架使用）
    staged_parser = subparsers.add_parser("check-staged", help="扫描暂存文件（pre-commit 集成）")

    # report 命令
    report_parser = subparsers.add_parser("report", help="查看已有 JSON 报告")
    report_parser.add_argument("file", help="JSON 报告文件路径")

    args = parser.parse_args()

    # ── scan ──────────────────────────────
    if args.command == "scan":
        scanner = SecretScanner()
        findings = scanner.scan_directory(
            args.path,
            exclude=set(args.exclude),
            verbose=args.verbose,
        )

        git_findings = []
        if getattr(args, "git", False):
            git_findings = scanner.scan_git_history(args.path, verbose=args.verbose)

        all_findings = findings + git_findings
        scanner.print_summary(findings, git_findings)

        if args.output:
            scanner.export_json(
                findings,
                args.output,
                git_findings=(git_findings if git_findings else None),
                git_repo_path=(args.path if git_findings else None),
            )
        sys.exit(1 if all_findings else 0)

    # ── git ───────────────────────────────
    elif args.command == "git":
        scanner = SecretScanner()
        findings = scanner.scan_git_history(args.path)
        scanner.print_summary(findings)

        if args.output:
            scanner.export_json(findings, args.output)
        sys.exit(1 if findings else 0)

    # ── install-hook ───────────────────────
    elif args.command == "install-hook":
        install_precommit_hook(args.path)

    # ── check-staged ────────────────────────
    elif args.command == "check-staged":
        from pathlib import Path
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True,
        )
        staged = [f.strip() for f in result.stdout.split("\n") if f.strip()]
        if not staged:
            print("SecretLeak Scanner: no staged files to check.")
            sys.exit(0)

        scanner = SecretScanner()
        all_findings = []
        for fname in staged:
            filepath = Path(fname)
            if filepath.is_file() and scanner.should_scan(filepath):
                all_findings.extend(scanner.scan_file(filepath))

        if all_findings:
            print("\n!! SecretLeak Scanner blocked this commit:\n")
            for f in all_findings:
                print(f"  [{f['severity']}] {f['type']} in {f['file']} line {f['line']}")
            print(f"\n{len(all_findings)} secret(s) detected. Commit blocked.\n")
            sys.exit(1)

        print("SecretLeak Scanner: pre-commit check passed.")

    # ── report ─────────────────────────────
    elif args.command == "report":
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"\n[REPORT] 报告: {args.file}")
        print(f"   生成时间: {data['scanned_at']}")
        print(f"   扫描文件: {data['files_scanned']}")
        print(f"   扫描行数: {data['lines_scanned']}")
        print(f"   泄露总数: {data['total_findings']}\n")

        for finding in data["findings"]:
            sev = finding["severity"].upper()
            color = Colors.RED if sev in ("CRITICAL", "HIGH") else Colors.YELLOW
            cprint(f"  [{color}{sev}{Colors.END}] {finding['type']}", color)
            print(f"    [FILE] {finding['file']} (L{finding['line']})")
            print(f"    [KEY]  {finding['matched']}\n")


if __name__ == "__main__":
    main()
