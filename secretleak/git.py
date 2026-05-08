"""Git 历史扫描器"""
import subprocess
import sys
from pathlib import Path
from typing import Optional

from secretleak.utils import Colors, cprint


def scan_git_history(
    compiled_patterns: dict,
    patterns: dict,
    repo_path: str | Path,
    verbose: bool = False,
    max_commits: int = 200,
    print_finding=None,
) -> list[dict]:
    """
    扫描 Git 历史提交 diff 中的敏感信息泄露。
    print_finding: 可选回调，用于打印每条发现
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
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-list", "--all", "-n", str(max_commits)],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] git 命令执行失败: {e.stderr}", file=sys.stderr)
        return []

    commit_hashes = [h.strip() for h in result.stdout.strip().split("\n") if h.strip()]

    for i, commit_hash in enumerate(commit_hashes, 1):
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "show", "--patch", "--format=", commit_hash],
                capture_output=True, text=True, check=True,
            )
            patch = result.stdout
            if not patch.strip():
                continue

            patch_lines = patch.split("\n")

            current_file = "unknown"
            added_lines: list[tuple[int, str]] = []  # (patch_line_index, content)

            for j, line in enumerate(patch_lines):
                if line.startswith("diff --git a/"):
                    current_file = line.split(" b/")[-1] if " b/" in line else "unknown"
                elif line.startswith("--- a/") or line.startswith("+++ b/"):
                    pass
                elif line.startswith("+") and not line.startswith("+++"):
                    added_lines.append((j, line[1:]))

            if not added_lines:
                continue

            for name, regex in compiled_patterns.items():
                severity = "medium"
                if isinstance(patterns.get(name), dict):
                    severity = patterns[name].get("severity", "medium")

                for patch_idx, added_line in added_lines:
                    for match in regex.finditer(added_line):
                        fname = current_file
                        for k in range(patch_idx - 1, max(0, patch_idx - 50), -1):
                            if patch_lines[k].startswith("+++ b/"):
                                fname = patch_lines[k][6:].strip()
                                break

                        matched_text = match.group()
                        finding = {
                            "file":     f"git:commit:{commit_hash[:8]}:{fname}",
                            "type":     name,
                            "severity": severity,
                            "line":     0,
                            "column":   match.start() + 1,
                            "matched":  matched_text[:12] + "***" if len(matched_text) > 12 else "***",
                            "full_match": matched_text,
                            "commit":   commit_hash,
                            "source":   "git",
                        }
                        all_findings.append(finding)
                        if print_finding:
                            print_finding(finding, verbose)

            if i % 20 == 0:
                cprint(f"  已扫描 {i} 个 commits ...", Colors.YELLOW)

        except subprocess.CalledProcessError:
            continue

    return all_findings
