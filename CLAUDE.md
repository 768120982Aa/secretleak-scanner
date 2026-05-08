# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**默认使用中文回答。**

## Project overview

SecretLeak Scanner — a Python CLI tool that detects secrets (API keys, tokens, private keys) in codebases via regex matching. Supports local file scanning, Git history scanning, and pre-commit hook installation. Zero external dependencies (stdlib only).

## Commands

```bash
# Scan local files in current directory
python scanner.py scan .

# Scan with verbose context (lines before/after match)
python scanner.py scan . --verbose

# Exclude additional directories
python scanner.py scan . --exclude node_modules build dist

# Full scan: local files + Git history
python scanner.py scan . --git --output report.json

# Scan only Git history (up to 200 commits)
python scanner.py git .

# Install pre-commit hook (cross-platform Python script)
python scanner.py install-hook

# View a JSON report
python scanner.py report report.json

# Run as package
python -m secretleak scan .

# Install dev dependencies
pip install -r requirements.txt

# Lint
ruff check secretleak/

# Type check
mypy secretleak/

# Run tests
pytest test_scanner.py -v
```

## Architecture

The project was refactored from a single-file script into a `secretleak/` package. `scanner.py` at the root is a thin backward-compatible wrapper.

```
scanner.py                   # backward-compat entry: from secretleak.cli import main
secretleak/
├── __init__.py              # __version__, public API exports
├── __main__.py              # python -m secretleak entry
├── cli.py                   # argparse CLI + main()
├── engine.py                # SecretScanner class: _load_patterns, scan_file, scan_directory, should_scan, _print_finding, print_summary, export_json
├── git.py                   # scan_git_history() standalone function
├── hooks.py                 # install_precommit_hook() — generates Python hook script
└── utils.py                 # Colors, colored, cprint, SCANNABLE_EXTENSIONS, DEFAULT_EXCLUDES, should_scan()
patterns.json                # 35 regex detection rules
test_scanner.py              # 24 test cases (pytest)
```

**Key classes and functions:**

- `SecretScanner` (engine.py) — core engine. Loads regex rules from `patterns.json` at init.
  - `scan_file(filepath)` — regex-match a single file, returns findings list
  - `scan_directory(path, exclude, verbose)` — recursive `os.walk`, delegates to standalone `should_scan()`
  - `scan_git_history(repo_path, verbose, max_commits=200)` — delegates to standalone `scan_git_history()` in `git.py`
  - `should_scan(filepath)` — thin method that calls standalone `should_scan()` in `utils.py`
  - `print_summary(findings, git_findings)` — severity/type breakdown to stdout
  - `export_json(findings, output_file, git_findings, git_repo_path)` — writes standardized JSON report

- `scan_git_history()` (git.py) — standalone function. Uses `git rev-list --all -n N` to get commits, then `git show --patch` to scan diff content (only `+` lines).

- `install_precommit_hook()` (hooks.py) — generates a Python script (not shell) at `.git/hooks/pre-commit`. Cross-platform: works in Git Bash/WSL/Linux/macOS.

- `should_scan()` (utils.py) — standalone function. Filters by hidden files, excluded dirs, and file extension/name whitelist. `.env` variants handled explicitly for Windows compatibility.

- `main()` (cli.py) — argparse CLI with 4 subcommands: `scan`, `git`, `install-hook`, `report`.

**Data flow:**
1. `patterns.json` loaded at `SecretScanner()` init → compiled regex dict (with schema validation)
2. Each file/git-diff scanned — only `+` lines for git diffs
3. Findings list accumulated → printed (ANSI colors via `Colors` class) and optionally exported as JSON

**`patterns.json` schema:** each key is a rule name mapping to `{"pattern": "<regex>", "severity": "critical|high|medium|low", "description": "..."}`. Invalid regex or missing fields raise `ValueError` (not silently skipped).

**Severity levels:** `critical` (keys/tokens that grant direct access), `high` (tokens with scoped access), `medium` (generic patterns, higher false-positive rate), `low` (not currently used by any rule).

## Important notes

- `scanner.py` and `patterns.json` must be in the same directory — patterns are loaded relative to CWD.
- Only dependency: Python stdlib ≥ 3.9. `requirements.txt` is only for dev tooling (pytest, mypy, ruff).
- Hook script is Python-based (not shell), cross-platform. `os.chmod` skipped on Windows.
- `scan_git_history` has a hard cap of 200 commits; modify `max_commits` parameter to adjust.
- Hidden files are skipped unless filename is `.env`, `.env.local`, or `.env.production` (Windows-compatible via name-based whitelist).
- Color output uses ANSI escape codes. Windows 10+ supports them natively; older versions may need `colorama`.
- The `.pre-commit-config.yaml` references `scripts/precommit_check.py` which does not exist. Use `python scanner.py install-hook` instead.
- Test file is `test_scanner.py` (24 tests). Tests copy `scanner.py` + `secretleak/` + `patterns.json` into temp Git repos for integration tests.
