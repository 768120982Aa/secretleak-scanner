"""工具函数与常量"""
import os
from pathlib import Path


# ── 颜色输出 ─────────────────────────────
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


# ── 文件过滤 ─────────────────────────────
SCANNABLE_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
    ".php", ".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".scala",
    ".env", ".ini", ".cfg", ".conf", ".config",
    ".json", ".yaml", ".yml", ".toml", ".xml",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".sql", ".md", ".rst", ".txt",
}

SCANNABLE_NAMES: set[str] = {
    ".env", ".env.local", ".env.production",
    "Dockerfile", ".dockerignore",
    "Makefile", ".htaccess", ".nginx",
    "requirements.txt",
}

DEFAULT_EXCLUDES: set[str] = {
    ".git", ".svn", ".hg",
    "node_modules", "bower_components",
    "__pycache__", ".pytest_cache", ".tox",
    "venv", ".venv", "env", ".env.local",
    "dist", "build", "out", ".next", ".nuxt",
    "vendor", ".gradle", "target", "bin", "obj",
    ".idea", ".vscode", ".vs",
    "coverage", ".nyc_output",
    ".DS_Store", "Thumbs.db",
}


def should_scan(filepath: Path, excludes: set[str] | None = None) -> bool:
    """判断文件是否应该被扫描"""
    excludes = excludes or DEFAULT_EXCLUDES
    name = filepath.name

    # 排除隐藏文件（但 .env 等例外）
    if name.startswith(".") and name not in {".env", ".env.local", ".env.production"}:
        return False

    # 排除已知不可扫描的目录
    parts = filepath.parts
    if any(part in excludes for part in parts):
        return False

    # 按扩展名或完整文件名过滤（.env 在 Windows 上 suffix 为空，需特判）
    return filepath.suffix.lower() in SCANNABLE_EXTENSIONS or name in SCANNABLE_NAMES
