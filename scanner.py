#!/usr/bin/env python3
from __future__ import annotations
"""
SecretLeak Scanner — 敏感信息泄露扫描器
支持：本地文件扫描、Git 历史扫描、预提交钩子
"""

import re
import json
import os
import sys
import argparse
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Set, Union, Any, Tuple


# ─────────────────────────────────────────────
# 颜色输出
# ─────────────────────────────────────────────
class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    END    = "\033[0m"


def colored(text: str, color: str) -> str:
    return f"{color}{text}{Colors.END}"


def cprint(text: str, color: str = ""):
    print(colored(text, color) if color else text)


# ─────────────────────────────────────────────
# 核心扫描引擎
# ─────────────────────────────────────────────
class SecretScanner:
    """敏感信息扫描器"""

    # 支持扫描的文件扩展名
    SCANNABLE_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
        ".php", ".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".scala",
        ".env", ".ini", ".cfg", ".conf", ".config",
        ".json", ".yaml", ".yml", ".toml", ".xml",
        ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
        ".sql", ".md", ".rst", ".txt",
        "Dockerfile", ".dockerignore",
        "Makefile", ".htaccess", ".nginx",
    }

    # 默认排除目录
    DEFAULT_EXCLUDES = {
        ".git", ".svn", ".hg",
        "node_modules", "bower_components",
        "__pycache__", ".pytest_cache", ".tox",
        "venv", ".venv", "env", ".env.local",
        "dist", "build", "out", ".next", ".nuxt",
        "vendor", ".gradle", "target", "bin", "obj",
        ".idea", ".vscode", ".vs",
        "coverage", ".nyc_output", ".pytest_cache",
        ".DS_Store", "Thumbs.db",
    }

    def __init__(self, patterns_file: str = "patterns.json"):
        self.patterns_file = patterns_file
        self.patterns: dict = {}
        self.compiled_patterns: dict = {}
        self.total_files_scanned = 0
        self.total_lines_scanned = 0
        self._load_patterns()

    def _load_patterns(self) -> None:
        """加载检测规则"""
        if not os.path.exists(self.patterns_file):
            raise FileNotFoundError(
                f"规则文件不存在: {self.patterns_file}\n"
                f"请确保 patterns.json 位于正确路径。"
            )

        with open(self.patterns_file, "r", encoding="utf-8") as f:
            raw = json.load(f)

        for name, data in raw.items():
            pattern = data["pattern"] if isinstance(data, dict) else data
            try:
                self.compiled_patterns[name] = re.compile(pattern)
            except re.error as e:
                print(f"[WARN] 正则表达式解析失败 [{name}]: {e}", file=sys.stderr)
                continue

        self.patterns = raw
        print(f"[INFO] 已加载 {len(self.compiled_patterns)} 条检测规则")

    # ── 单文件扫描 ──────────────────────────────
    def scan_file(self, filepath: str | Path) -> list[dict]:
        """
        扫描单个文件，返回泄露信息列表。
        每条结果包含: file, type, severity, line, column, matched_text, context
        """
        filepath = Path(filepath)
        findings = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return findings

        self.total_files_scanned += 1
        self.total_lines_scanned += len(lines)

        # 将文件内容拼接用于正则匹配（保留行号映射）
        content = "".join(lines)

        for name, regex in self.compiled_patterns.items():
            severity = "medium"
            if isinstance(self.patterns.get(name), dict):
                severity = self.patterns[name].get("severity", "medium")

            for match in regex.finditer(content):
                # 计算匹配位置对应的行号
                line_num = content[:match.start()].count("\n") + 1
                col_num  = match.start() - content.rfind("\n", 0, match.start())

                matched_text = match.group()
                # 避免在日志中暴露完整密钥，截断显示
                display_text = (
                    matched_text[:12] + "***"
                    if len(matched_text) > 12 else "***"
                )

                # 提取匹配行上下文（前一行 + 当前行 + 后一行）
                context_before = (
                    lines[line_num - 2].strip()
                    if line_num > 1 else ""
                )
                context_after = (
                    lines[line_num].strip()
                    if line_num < len(lines) else ""
                )

                findings.append({
                    "file":        str(filepath),
                    "type":        name,
                    "severity":    severity,
                    "line":        line_num,
                    "column":      col_num,
                    "matched":     display_text,
                    "full_match": matched_text,
                    "context_before": context_before,
                    "context_after":  context_after,
                })

        return findings

    # ── 目录扫描 ──────────────────────────────
    def should_scan(self, filepath: Path) -> bool:
        """判断文件是否应该被扫描"""
        name = filepath.name

        # 排除隐藏文件（但 .env 等例外）
        if name.startswith(".") and name not in {".env", ".env.local", ".env.production"}:
            return False

        # 排除已知不可扫描的目录
        parts = filepath.parts
        if any(part in self.DEFAULT_EXCLUDES for part in parts):
            return False

        # 按扩展名过滤
        return (
            filepath.suffix.lower() in self.SCANNABLE_EXTENSIONS
            or filepath.name in {"Dockerfile", "Makefile", ".htaccess", ".nginx", "requirements.txt"}
        )

    def scan_directory(
        self,
        path: str | Path,
        exclude: Optional[set[str]] = None,
        verbose: bool = False,
    ) -> list[dict]:
        """
        递归扫描目录。
        exclude: 额外需要排除的目录名集合
        """
        path = Path(path).resolve()
        exclude = (exclude or set()) | self.DEFAULT_EXCLUDES
        all_findings = []

        print(f"\n{'='*60}")
        cprint(f"  开始扫描目录: {path}", Colors.CYAN)
        print(f"{'='*60}\n")

        for root, dirs, files in os.walk(path):
            root_path = Path(root)

            # 剪枝：跳过排除目录
            dirs[:] = [
                d for d in dirs
                if d not in exclude and not d.startswith(".")
            ]

            for filename in files:
                filepath = root_path / filename

                if not self.should_scan(filepath):
                    continue

                findings = self.scan_file(filepath)

                if findings:
                    for finding in findings:
                        all_findings.append(finding)
                        self._print_finding(finding, verbose)

        return all_findings

    # ── Git 历史扫描 ───────────────────────────
    def scan_git_history(self, repo_path: str | Path) -> list[dict]:
        """
        扫描 Git 历史上所有 commit 中的敏感信息泄露。
        使用 git log -p 遍历每个提交的差异文件。
        """
        repo_path = Path(repo_path).resolve()

        if not (repo_path / ".git").exists():
            print(f"[WARN] 目录不是 Git 仓库: {repo_path}", file=sys.stderr)
            return []

        all_findings = []
        cprint(f"\n{'='*60}", Colors.MAGENTA)
        cprint(f"  开始扫描 Git 历史: {repo_path}", Colors.MAGENTA)
        cprint(f"{'='*60}\n", Colors.MAGENTA)

        try:
            # 获取所有 commit 的哈希
            result = subprocess.run(
                ["git", "-C", str(repo_path), "log", "--all", "--format=%H", "--name-only"],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] git 命令执行失败: {e.stderr}", file=sys.stderr)
            return []

        commits = result.stdout.strip().split("\n")
        commit_hashes = [h for h in commits if h.strip()]

        # 扫描每个 commit 的完整内容
        for i, commit_hash in enumerate(commit_hashes[:200], 1):  # 限制最多 200 个 commit
            if not commit_hash.strip():
                continue

            try:
                # 获取该 commit 修改的所有文件内容
                result = subprocess.run(
                    ["git", "-C", str(repo_path), "show", "--name-only", "--format=",
                     commit_hash],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                patch_output = result.stdout

                # 对每个文件内容进行扫描
                lines = patch_output.split("\n")
                content = "\n".join(lines)

                for name, regex in self.compiled_patterns.items():
                    for match in regex.finditer(content):
                        line_num = content[:match.start()].count("\n") + 1

                        # 找到对应的文件名（在 + 行附近）
                        filename = "unknown"
                        for j in range(max(0, line_num - 5), min(len(lines), line_num + 2)):
                            if lines[j].startswith("+++ b/"):
                                filename = lines[j][4:].strip()
                                break

                        severity = "medium"
                        if isinstance(self.patterns.get(name), dict):
                            severity = self.patterns[name].get("severity", "medium")

                        all_findings.append({
                            "file":     f"git:commit:{commit_hash[:8]}:{filename}",
                            "type":     name,
                            "severity": severity,
                            "line":     line_num,
                            "column":   match.start() - content.rfind("\n", 0, match.start()),
                            "matched":  match.group()[:12] + "***",
                            "commit":   commit_hash,
                        })

                if i % 20 == 0:
                    cprint(f"  已扫描 {i} 个 commits ...", Colors.YELLOW)

            except subprocess.CalledProcessError:
                continue

        return all_findings

    # ── 扫描结果展示 ───────────────────────────
    def _print_finding(self, finding: dict, verbose: bool = False) -> None:
        """格式化打印单条发现"""
        severity_colors = {
            "critical": Colors.RED,
            "high":     Colors.RED,
            "medium":   Colors.YELLOW,
            "low":      Colors.GREEN,
        }
        color = severity_colors.get(finding["severity"], Colors.YELLOW)

        cprint(
            f"  [{color}{finding['severity'].upper():8}{Colors.END}]"
            f"  {finding['type']}",
            color,
        )
        print(f"    📄 {finding['file']}")
        print(f"    📍 第 {finding['line']} 行  列 {finding.get('column', '?')}")

        if verbose and finding.get("context_before"):
            print(f"    ├ {colored(finding['context_before'][:80], Colors.BLUE)}{Colors.END}")

        print(f"    └ {colored(finding['matched'], Colors.RED)}")

        if verbose and finding.get("context_after"):
            print(f"    ├ {colored(finding['context_after'][:80], Colors.BLUE)}{Colors.END}")
        print()

    # ── 报告摘要 ──────────────────────────────
    def print_summary(self, findings: list[dict]) -> None:
        """打印扫描摘要"""
        print(f"\n{'='*60}")
        cprint(f"  扫描摘要", Colors.BOLD)
        print(f"{'='*60}")
        print(f"  文件总数扫描: {self.total_files_scanned}")
        print(f"  代码行数扫描: {self.total_lines_scanned}")
        print(f"  泄露条数:     {len(findings)}")

        if not findings:
            cprint("  ✅ 未检测到敏感信息泄露！", Colors.GREEN)
            return

        # 按严重级别分组
        by_severity = {}
        for f in findings:
            s = f["severity"]
            by_severity[s] = by_severity.get(s, 0) + 1

        for sev in ["critical", "high", "medium", "low"]:
            if sev in by_severity:
                color = {"critical": Colors.RED, "high": Colors.RED,
                         "medium": Colors.YELLOW, "low": Colors.GREEN}.get(sev, "")
                cprint(f"    {sev.upper():12}: {by_severity[sev]}", color)

        print()

        # 按类型分组
        by_type: dict = {}
        for f in findings:
            t = f["type"]
            by_type[t] = by_type.get(t, 0) + 1

        cprint(f"  泄露类型 TOP 5:", Colors.BOLD)
        for t, cnt in sorted(by_type.items(), key=lambda x: -x[1])[:5]:
            print(f"    {cnt:4d} ×  {t}")

        print()

        if any(s in by_severity for s in ["critical", "high"]):
            cprint(
                "  ⚠️  发现高危/严重泄露！请立即轮换相关密钥并撤销旧凭证。",
                Colors.RED,
            )
        elif by_severity.get("medium"):
            cprint("  ⚡ 发现中危泄露，请检查是否需要修复。", Colors.YELLOW)
        else:
            cprint("  ✅ 仅发现低危泄露或误报，请人工复核。", Colors.GREEN)

    # ── 导出报告 ──────────────────────────────
    def export_json(self, findings: list[dict], output_file: str) -> None:
        """将结果导出为 JSON 报告"""
        report = {
            "scanned_at":      datetime.now().isoformat(),
            "files_scanned":   self.total_files_scanned,
            "lines_scanned":   self.total_lines_scanned,
            "total_findings":  len(findings),
            "findings":        findings,
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[INFO] 报告已导出: {output_file}")


# ─────────────────────────────────────────────
# 预提交钩子生成器
# ─────────────────────────────────────────────
def install_precommit_hook(repo_path: str | Path = ".") -> None:
    """在当前 Git 仓库安装预提交钩子，防止新提交包含密钥"""
    repo_path = Path(repo_path)
    hook_path = repo_path / ".git" / "hooks" / "pre-commit"

    hook_script = f"""#!/bin/sh
# SecretLeak Scanner — 预提交钩子
# 自动生成于 {datetime.now().isoformat()}

echo "Running SecretLeak Scanner pre-commit hook..."

SCANNER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PATTERNS_FILE="$SCANNER_DIR/scanner/patterns.json"

# 临时运行扫描
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

RESULT=$(python3 -c "
import sys
sys.path.insert(0, '{SCANNER_DIR}')
from scanner import SecretScanner
import glob, os

scanner = SecretScanner('{PATTERNS_FILE}')
all_findings = []
for f in ''' + "'\"'\n" + '''.split():
    if os.path.exists(f):
        all_findings.extend(scanner.scan_file(f))
if all_findings:
    print('FINDINGS:', len(all_findings))
    for finding in all_findings:
        print(f\"  [{{finding['severity']}}] {{finding['type']}} in {{finding['file']}} line {{finding['line']}}\")
    sys.exit(1)
print('OK')
" 2>&1)

if echo "$RESULT" | grep -q "FINDINGS:"; then
    echo ""
    echo "!! SecretLeak Scanner blocked this commit:"
    echo "$RESULT"
    exit 1
fi

echo "$RESULT"
echo "Pre-commit check passed."
exit 0
"""

    with open(hook_path, "w", encoding="utf-8") as f:
        f.write(hook_script)
    os.chmod(hook_path, 0o755)
    print(f"[INFO] 预提交钩子已安装: {hook_path}")


# ─────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="secretleak-scanner",
        description="🔍 SecretLeak Scanner — 敏感信息泄露扫描器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  %(prog)s scan .                          # 扫描当前目录
  %(prog)s scan /path/to/project --verbose # 详细输出
  %(prog)s git /path/to/repo              # 扫描 Git 历史
  %(prog)s install-hook                   # 安装预提交钩子
  %(prog)s report scan.json               # 生成 JSON 报告
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan 命令
    scan_parser = subparsers.add_parser("scan", help="扫描本地文件/目录")
    scan_parser.add_argument("path", nargs="?", default=".", help="待扫描的目录或文件（默认: .）")
    scan_parser.add_argument("--exclude", "-e", nargs="+", default=[],
                             help="额外排除的目录")
    scan_parser.add_argument("--verbose", "-v", action="store_true",
                             help="显示详细上下文")
    scan_parser.add_argument("--output", "-o", help="导出 JSON 报告路径")

    # git 命令
    git_parser = subparsers.add_parser("git", help="扫描 Git 历史")
    git_parser.add_argument("path", nargs="?", default=".", help="Git 仓库路径（默认: .）")
    git_parser.add_argument("--output", "-o", help="导出 JSON 报告路径")

    # hook 命令
    hook_parser = subparsers.add_parser("install-hook", help="安装预提交钩子")
    hook_parser.add_argument("path", nargs="?", default=".", help="Git 仓库路径（默认: .）")

    # report 命令（已有报告的查看）
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
        scanner.print_summary(findings)

        if args.output:
            scanner.export_json(findings, args.output)
        sys.exit(1 if findings else 0)

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

    # ── report ─────────────────────────────
    elif args.command == "report":
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"\n📊 报告: {args.file}")
        print(f"   生成时间: {data['scanned_at']}")
        print(f"   扫描文件: {data['files_scanned']}")
        print(f"   扫描行数: {data['lines_scanned']}")
        print(f"   泄露总数: {data['total_findings']}\n")

        for finding in data["findings"]:
            sev = finding["severity"].upper()
            color = Colors.RED if sev in ("CRITICAL", "HIGH") else Colors.YELLOW
            cprint(f"  [{color}{sev}{Colors.END}] {finding['type']}", color)
            print(f"    📄 {finding['file']} (L{finding['line']})")
            print(f"    🔑 {finding['matched']}\n")


if __name__ == "__main__":
    main()
