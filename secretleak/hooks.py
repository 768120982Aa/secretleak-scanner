"""预提交钩子安装器"""
import os
import sys
from pathlib import Path
from datetime import datetime


def install_precommit_hook(repo_path: str | Path = ".") -> None:
    """在当前 Git 仓库安装预提交钩子，防止新提交包含密钥"""
    repo_path = Path(repo_path).resolve()
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        print(f"[ERROR] 目录不是 Git 仓库: {repo_path}", file=sys.stderr)
        return

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    scanner_dir = str(repo_path)
    patterns_file = str(repo_path / "patterns.json")

    hook_script = f'''#!/usr/bin/env python3
"""SecretLeak Scanner pre-commit hook — generated {datetime.now().isoformat()}"""
import sys
import os
import subprocess

SCANNER_DIR = {scanner_dir!r}
PATTERNS_FILE = {patterns_file!r}
SCANNER_PY = os.path.join(SCANNER_DIR, "scanner.py")

if not os.path.exists(SCANNER_PY):
    print(f"SecretLeak Scanner: scanner.py not found at {{SCANNER_PY}}, skipping check.")
    sys.exit(0)

sys.path.insert(0, SCANNER_DIR)
from scanner import SecretScanner

result = subprocess.run(
    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
    capture_output=True, text=True
)
staged = [f.strip() for f in result.stdout.split("\\n") if f.strip()]

scanner = SecretScanner(PATTERNS_FILE)
all_findings = []

for fname in staged:
    filepath = os.path.join(SCANNER_DIR, fname)
    if os.path.isfile(filepath):
        all_findings.extend(scanner.scan_file(filepath))

if all_findings:
    print("\\n!! SecretLeak Scanner blocked this commit:\\n")
    for f in all_findings:
        print(f"  [{{f['severity']}}] {{f['type']}} in {{f['file']}} line {{f['line']}}")
    print(f"\\n{{len(all_findings)}} secret(s) detected. Commit blocked.\\n")
    sys.exit(1)

print("SecretLeak Scanner: pre-commit check passed.")
'''

    with open(hook_path, "w", encoding="utf-8") as f:
        f.write(hook_script)

    try:
        os.chmod(hook_path, 0o755)
    except (OSError, PermissionError):
        pass  # Windows 上 chmod 是 no-op，但 Git Bash 下有效

    print(f"[INFO] 预提交钩子已安装: {hook_path}")
