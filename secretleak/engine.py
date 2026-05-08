"""核心扫描引擎"""
import re
import json
import os
import sys
from pathlib import Path
from typing import Optional

from secretleak.utils import Colors, colored, cprint, should_scan, DEFAULT_EXCLUDES
from secretleak.git import scan_git_history


class SecretScanner:
    """敏感信息扫描器"""

    ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}

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
            if not isinstance(data, dict):
                raise ValueError(f"规则 '{name}' 格式错误，必须是对象")
            if "pattern" not in data:
                raise ValueError(f"规则 '{name}' 缺少 'pattern' 字段")
            severity = data.get("severity", "medium")
            if severity not in self.ALLOWED_SEVERITIES:
                raise ValueError(
                    f"规则 '{name}' 的 severity='{severity}' 无效，"
                    f"允许: {self.ALLOWED_SEVERITIES}"
                )
            try:
                self.compiled_patterns[name] = re.compile(data["pattern"])
            except re.error as e:
                raise ValueError(f"规则 '{name}' 正则表达式无效: {e}") from e

        self.patterns = raw
        print(f"[INFO] 已加载 {len(self.compiled_patterns)} 条检测规则")

    # ── 单文件扫描 ──────────────────────────
    def scan_file(self, filepath: str | Path) -> list[dict]:
        filepath = Path(filepath)
        findings = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return findings

        self.total_files_scanned += 1
        self.total_lines_scanned += len(lines)

        content = "".join(lines)

        for name, regex in self.compiled_patterns.items():
            severity = "medium"
            if isinstance(self.patterns.get(name), dict):
                severity = self.patterns[name].get("severity", "medium")

            for match in regex.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                col_num  = match.start() - content.rfind("\n", 0, match.start())

                matched_text = match.group()
                display_text = (
                    matched_text[:12] + "***"
                    if len(matched_text) > 12 else "***"
                )

                idx = line_num - 1  # 转为 0-indexed
                context_before = lines[idx - 1].strip() if idx > 0 else ""
                context_after = lines[idx + 1].strip() if idx + 1 < len(lines) else ""

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
                    "source":      "local",
                })

        return findings

    # ── 文件过滤 ────────────────────────────
    def should_scan(self, filepath: Path) -> bool:
        """判断文件是否应该被扫描（委托 standalone 函数）"""
        return should_scan(filepath)

    # ── 目录扫描 ────────────────────────────
    def scan_directory(
        self,
        path: str | Path,
        exclude: Optional[set[str]] = None,
        verbose: bool = False,
    ) -> list[dict]:
        path = Path(path).resolve()
        excludes = (exclude or set()) | DEFAULT_EXCLUDES
        all_findings = []

        print(f"\n{'='*60}")
        cprint(f"  开始扫描目录: {path}", Colors.CYAN)
        print(f"{'='*60}\n")

        for root, dirs, files in os.walk(path):
            root_path = Path(root)

            dirs[:] = [
                d for d in dirs
                if d not in excludes and not d.startswith(".")
            ]

            for filename in files:
                filepath = root_path / filename
                if not should_scan(filepath, excludes):
                    continue

                findings = self.scan_file(filepath)
                if findings:
                    for finding in findings:
                        all_findings.append(finding)
                        self._print_finding(finding, verbose)

        return all_findings

    # ── Git 历史扫描 ────────────────────────
    def scan_git_history(
        self,
        repo_path: str | Path,
        verbose: bool = False,
        max_commits: int = 200,
    ) -> list[dict]:
        return scan_git_history(
            compiled_patterns=self.compiled_patterns,
            patterns=self.patterns,
            repo_path=repo_path,
            verbose=verbose,
            max_commits=max_commits,
            print_finding=self._print_finding,
        )

    # ── 扫描结果展示 ────────────────────────
    def _print_finding(self, finding: dict, verbose: bool = False) -> None:
        severity_colors = {
            "critical": Colors.RED,
            "high":     Colors.RED,
            "medium":   Colors.YELLOW,
            "low":      Colors.GREEN,
        }
        color = severity_colors.get(finding["severity"], Colors.YELLOW)

        source_tag = ""
        if finding.get("source") == "git":
            source_tag = f"  {colored('[GIT历史]', Colors.MAGENTA)}  "

        cprint(
            f"  {source_tag}[{color}{finding['severity'].upper():8}{Colors.END}]"
            f"  {finding['type']}",
            color,
        )
        print(f"    [FILE] {finding['file']}")
        print(f"    Line {finding['line']}  col {finding.get('column', '?')}")

        if finding.get("source") == "git" and finding.get("commit"):
            print(f"    [commit] {finding['commit'][:8]}")

        if verbose and finding.get("context_before"):
            print(f"    ├ {colored(finding['context_before'][:80], Colors.BLUE)}{Colors.END}")

        print(f"    └ {colored(finding['matched'], Colors.RED)}")

        if verbose and finding.get("context_after"):
            print(f"    ├ {colored(finding['context_after'][:80], Colors.BLUE)}{Colors.END}")
        print()

    # ── 报告摘要 ────────────────────────────
    def print_summary(self, findings: list[dict], git_findings: Optional[list[dict]] = None) -> None:
        total_findings = findings + (git_findings or [])
        has_git = git_findings is not None and len(git_findings) > 0

        print(f"\n{'='*60}")
        cprint(f"  扫描摘要", Colors.BOLD)
        print(f"{'='*60}")

        if has_git:
            print(f"  [LOCAL] 本地扫描: 文件 {self.total_files_scanned} 个  行数 {self.total_lines_scanned} 条")
            print(f"  [GIT]  Git 历史: {len(git_findings)} 条泄露")
        else:
            print(f"  文件总数扫描: {self.total_files_scanned}")
            print(f"  代码行数扫描: {self.total_lines_scanned}")

        print(f"  泄露条数:     {len(total_findings)}")

        if not total_findings:
            cprint("  [OK] 未检测到敏感信息泄露！", Colors.GREEN)
            return

        by_severity: dict = {}
        for f in total_findings:
            s = f["severity"]
            by_severity[s] = by_severity.get(s, 0) + 1

        for sev in ["critical", "high", "medium", "low"]:
            if sev in by_severity:
                color = {"critical": Colors.RED, "high": Colors.RED,
                         "medium": Colors.YELLOW, "low": Colors.GREEN}.get(sev, "")
                cprint(f"    {sev.upper():12}: {by_severity[sev]}", color)

        print()

        by_type: dict = {}
        for f in total_findings:
            t = f["type"]
            by_type[t] = by_type.get(t, 0) + 1

        cprint(f"  泄露类型 TOP 5:", Colors.BOLD)
        for t, cnt in sorted(by_type.items(), key=lambda x: -x[1])[:5]:
            print(f"    {cnt:4d} ×  {t}")

        if has_git:
            local_count = len(findings)
            git_count = len(git_findings)
            print()
            print(f"  [STATS] 来源分布: 本地 {local_count} 条  |  Git 历史 {git_count} 条")

        print()

        if any(s in by_severity for s in ["critical", "high"]):
            cprint(
                "  [WARN] 发现高危/严重泄露！请立即轮换相关密钥并撤销旧凭证。",
                Colors.RED,
            )
        elif by_severity.get("medium"):
            cprint("  [WARN] 发现中危泄露，请检查是否需要修复。", Colors.YELLOW)
        else:
            cprint("  [OK] 仅发现低危泄露或误报，请人工复核。", Colors.GREEN)

    # ── 导出报告 ────────────────────────────
    def export_json(
        self,
        findings: list[dict],
        output_file: str,
        git_findings: Optional[list[dict]] = None,
        git_repo_path: Optional[str] = None,
    ) -> None:
        from datetime import datetime
        all_findings = findings + (git_findings or [])
        report = {
            "scanned_at":      datetime.now().isoformat(),
            "files_scanned":   self.total_files_scanned,
            "lines_scanned":   self.total_lines_scanned,
            "total_findings":  len(all_findings),
            "local_findings":  len(findings),
            "git_findings":    len(git_findings) if git_findings else 0,
            "git_repo":        str(git_repo_path) if git_repo_path else None,
            "findings":        all_findings,
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[INFO] 报告已导出: {output_file}")
