# SecretLeak Scanner

**敏感信息泄露扫描器** — 通过正则匹配自动检测代码仓库中的 API 密钥、Token、私钥等敏感信息。

零外部依赖（仅 Python 标准库），支持 Windows / Linux / macOS。

---

## 快速开始

```bash
# 扫描当前目录
python scanner.py scan .

# 扫描指定目录 + Git 历史
python scanner.py scan /path/to/project --git

# 安装 pre-commit 钩子（阻止含密钥的提交）
python scanner.py install-hook

# 查看 JSON 报告
python scanner.py report scan.json
```

也可以通过包入口运行：

```bash
python -m secretleak scan .
```

**要求：** Python >= 3.9，无需安装任何第三方包。

---

## 命令一览

### `scan` — 扫描本地文件/目录

```bash
python scanner.py scan [PATH] [OPTIONS]
```

| 参数 | 说明 |
|------|------|
| `PATH` | 待扫描的目录或文件，默认当前目录 |
| `--exclude, -e DIR [DIR ...]` | 额外排除的目录 |
| `--verbose, -v` | 显示匹配行上下文 |
| `--output, -o FILE` | 导出 JSON 报告 |
| `--git, -g` | 同时扫描 Git 提交历史 |

### `git` — 仅扫描 Git 历史

```bash
python scanner.py git [PATH] [--output report.json]
```

遍历最近 200 条 commit 的 diff 内容，检测历史上提交过的密钥。

### `install-hook` — 安装 pre-commit 钩子

```bash
python scanner.py install-hook [PATH]
```

在 `.git/hooks/pre-commit` 生成一个 Python 脚本，提交时自动扫描暂存文件。检测到密钥则阻止提交。

跨平台兼容：钩子使用 Python 实现，在 Git Bash / WSL / Linux / macOS 下均可用。

### `report` — 查看 JSON 报告

```bash
python scanner.py report scan.json
```

以可读格式打印已有的 JSON 扫描报告。

---

## 检测能力

`patterns.json` 内置 **35 条规则**，覆盖以下类别：

**平台密钥**
- GitHub Token、GitHub OAuth、GitHub Fine-grained PAT
- OpenAI API Key、Anthropic API Key
- AWS Access Key ID、AWS Secret Access Key
- Google Cloud API Key、Google OAuth Access/Refresh Token
- Stripe Publishable/Secret Key
- SendGrid、Mailgun、Mailchimp、Twilio API Key
- Slack Token / Webhook、Discord Token、Telegram Bot Token
- Cloudflare API Key
- Docker Hub Token
- NPM Token、PyPI Token
- PayPal Access Token

**基础设施**
- 数据库连接字符串（MongoDB、PostgreSQL、MySQL、Redis）
- 私钥文件头（PEM / SSH / PGP）
- JWT Token
- HTTP Basic Auth / Bearer Token 头

**通用模式**
- `api_key` / `apikey` 赋值
- `secret` / `password` 赋值
- 硬编码密码

严重级别：`critical` > `high` > `medium` > `low`。

---

## GitHub Actions CI/CD 集成

在仓库中添加 `.github/workflows/secret-scan.yml`：

```yaml
name: SecretLeak Scanner

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # 拉取完整历史，用于 Git 历史扫描

      - name: Checkout SecretLeak Scanner
        uses: actions/checkout@v4
        with:
          repository: 768120982Aa/secretleak-scanner
          path: scanner

      - name: Run scan
        run: |
          python scanner/scanner.py scan . --git --output scan-report.json

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: secretleak-report
          path: scan-report.json
```

**说明：**

- `fetch-depth: 0` — 必须拉取完整 Git 历史，否则 `--git` 扫描无数据
- 方式 A（推荐）：checkout 当前仓库 + checkout scanner 仓库，直接运行
- 方式 B：也可以通过 `curl`/`wget` 直接下载 `scanner.py` 和 `patterns.json`（单文件场景无需完整仓库）

方式 B 最小化示例：

```yaml
- name: Download and run
  run: |
    curl -sOL https://raw.githubusercontent.com/768120982Aa/secretleak-scanner/master/scanner.py
    curl -sOL https://raw.githubusercontent.com/768120982Aa/secretleak-scanner/master/patterns.json
    mkdir -p secretleak
    curl -sL https://api.github.com/repos/768120982Aa/secretleak-scanner/contents/secretleak | \
      python -c "import sys,json,os;[os.makedirs('secretleak', exist_ok=True) or open(f'secretleak/{f[\"name\"]}','wb').write(__import__('urllib.request').request.urlopen(f['download_url']).read()) for f in json.load(sys.stdin)]"
    python scanner.py scan . --git --output report.json
```

---

## 自定义规则

编辑 `patterns.json`，每个规则格式如下：

```json
{
  "规则名称": {
    "pattern": "正则表达式",
    "severity": "critical|high|medium|low",
    "description": "说明"
  }
}
```

- `pattern` — 必填，Python 正则表达式
- `severity` — 可选，默认 `medium`
- `description` — 可选

无效的正则或缺失字段会在加载时报错，不会静默跳过。

---

## 排除文件

以下目录默认跳过：

`.git` `.svn` `node_modules` `__pycache__` `venv` `.venv` `dist` `build` `vendor` `.idea` `.vscode` `target` `bin` `obj` `coverage`

隐藏文件（`.` 开头）默认跳过，但 `.env` / `.env.local` / `.env.production` 例外。

可通过 `--exclude` 参数添加额外排除目录。

---

## 跨平台

| 功能 | Linux | macOS | Windows | WSL |
|------|-------|-------|---------|-----|
| 文件扫描 | 完全支持 | 完全支持 | 完全支持 | 完全支持 |
| Git 历史扫描 | 完全支持 | 完全支持 | 需安装 Git | 完全支持 |
| pre-commit 钩子 | 完全支持 | 完全支持 | Git Bash 下支持 | 完全支持 |
| ANSI 彩色输出 | 完全支持 | 完全支持 | Windows 10+ | 完全支持 |

---

## 项目结构

```
secretleak-scanner/
├── scanner.py              # 向后兼容入口
├── patterns.json           # 检测规则（核心）
├── secretleak/             # 主包
│   ├── cli.py              # CLI 与 argparse
│   ├── engine.py           # 核心扫描引擎
│   ├── git.py              # Git 历史扫描
│   ├── hooks.py            # pre-commit 钩子安装
│   └── utils.py            # 颜色输出 / 文件过滤
├── test_scanner.py         # 测试用例
├── requirements.txt        # 开发依赖（pytest, mypy, ruff）
└── README.md
```

## 开发

```bash
pip install -r requirements.txt   # 安装开发工具
pytest test_scanner.py -v         # 运行测试
ruff check secretleak/            # 代码检查
mypy secretleak/                  # 类型检查
```

### 运行测试

```bash
# Windows / Linux / WSL / macOS 均可
pytest test_scanner.py -v
```

测试覆盖：核心扫描引擎、文件过滤、Git 历史扫描、Hook 安装与提交阻止、CLI 端到端。

---

## License

MIT
