"""SecretLeak Scanner — 敏感信息泄露扫描器"""
from secretleak.engine import SecretScanner
from secretleak.hooks import install_precommit_hook
from secretleak.utils import Colors, colored, cprint

__version__ = "1.0.1"
__all__ = ["SecretScanner", "install_precommit_hook", "Colors", "colored", "cprint"]
