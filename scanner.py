#!/usr/bin/env python3
"""SecretLeak Scanner — 向后兼容入口，实际逻辑已迁移至 secretleak/ 包"""
from secretleak.cli import main
from secretleak.engine import SecretScanner
from secretleak.hooks import install_precommit_hook

if __name__ == "__main__":
    main()
