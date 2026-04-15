# 🔍 SecretLeak Scanner

**敏感信息泄露扫描器** — 自动检测代码仓库中的 API 密钥、Token、私钥等机密信息泄露。

支持本地文件扫描、Git 历史扫描、预提交钩子，适用于 GitHub CI/CD 集成。

---

## 功能特性

| 功能 | 说明 |
|------|------|
| 📁 **本地文件扫描** | 递归扫描目录，自动排除 `.git`/`node_modules` 等目录，检测 30+ 种密钥类型 |
| 📜 **Git 历史扫描** | 扫描历史 commit 中遗漏的敏感信息 |
| 🔗 **一键全面扫描** | 同一命令同时扫描本地文件 + Git 历史，输出统一报告 |
| 🪝 **预提交钩子** | 阻止包含密钥的新提交 |
| 📊 **CI/CD 集成** | GitHub Actions 一键集成 |
| 🧩 **可扩展规则** | 通过 `patterns.json` 轻松添加新规则 |
| 📝 **JSON 报告** | 导出标准化 JSON 报告，便于 CI 失败解析 |
| 🎯 **多目录扫描** | 支持指定任意目录路径扫描 |
| 📖 **详细输出** | 支持显示匹配行的上下文代码 |

---

## 支持检测的类型（30+ 种规则）

- AWS / GitHub / Slack / OpenAI / Anthropic API Keys
- TLS/SSH 私钥文件（PEM 格式）
- 数据库连接字符串（MongoDB、PostgreSQL、Redis、MySQL 等）
- JWT Token、Basic Auth 凭证、Bearer Token
- Stripe / SendGrid / Mailgun / Telegram Bot Token
- Google Cloud / Cloudflare / NPM / PyPI Token
- Docker Hub / Twilio / PayPal Access Token
- 通用硬编码密码与 API Key
- …… 持续更新

---

## 安装

### 环境要求

- Python 3.9 或更高版本
- Git（用于 Git 历史扫描和预提交钩子）

### 安装步骤

```bash
# 克隆项目
git clone https://github.com/YOUR_USERNAME/secretleak-scanner.git
cd secretleak-scanner

# 安装依赖（非必须，核心功能只需 Python 标准库）
pip install -r requirements.txt
```

> **注意**：`scanner.py` 核心功能仅依赖 Python 标准库（`re`, `json`, `os`, `subprocess` 等），无需安装额外包即可正常运行。`requirements.txt` 中的包主要用于测试和类型检查。

---

## 目录结构

```
secretleak-scanner/
├── scanner.py              # 核心扫描引擎（CLI 入口，所有命令从这里触发）
├── patterns.json           # 密钥正则规则库（可自行扩展）
├── requirements.txt        # Python 依赖
├── README.md               # 本文件
├── .pre-commit-config.yaml # Pre-commit 框架配置（推荐）
└── scripts/
    └── precommit_check.py # Pre-commit hook 入口脚本
    └── .github/
        └── workflows/
            └── test.yml    # CI 自动测试
```

> **关键文件**：`scanner.py` 和 `patterns.json` 需放在同一目录下使用。

---

## 完整使用指南

### 一、本地文件扫描 `scan`

#### 基本用法

```bash
# 扫描当前目录
python scanner.py scan

# 扫描当前目录（显式指定）
python scanner.py scan .

# 扫描指定目录（相对路径）
python scanner.py scan ./my-project

# 扫描指定目录（绝对路径）
python scanner.py scan C:\Users\76812\Desktop\project
python scanner.py scan /home/user/project
```

#### 常用选项

| 选项 | 说明 |
|------|------|
| `path` | 待扫描的目录或文件路径（默认: `.`，即当前目录） |
| `--exclude` 或 `-e` | 额外排除的目录名称（可指定多个） |
| `--verbose` 或 `-v` | 显示详细上下文（前一行 + 当前行 + 后一行） |
| `--output` 或 `-o` | 导出 JSON 报告路径 |
| `--git` 或 `-g` | **一键同时扫描 Git 历史**（见下文） |

#### 使用示例

```bash
# 示例 1：基本扫描
python scanner.py scan .

# 示例 2：扫描并显示详细上下文
python scanner.py scan . --verbose

# 示例 3：排除特定目录
python scanner.py scan . --exclude node_modules build dist venv

# 示例 4：排除多个目录并导出 JSON 报告
python scanner.py scan . --exclude node_modules build --output scan-report.json

# 示例 5：扫描指定目录
python scanner.py scan C:\Users\76812\Desktop\test-project
```

#### 扫描范围说明

- **自动排除**：`.git`、`node_modules`、`venv`、`__pycache__`、`dist`、`build` 等常见无需扫描的目录
- **扫描对象**：`.py`、`.js`、`.ts`、`.java`、`.go`、`.env`、`.json`、`.yaml`、`.yml`、`.sh`、`.sql` 等代码和配置文件
- **不扫描**：隐藏文件（`.` 开头，`.env` 例外）、二进制文件

---

### 二、Git 历史扫描 `git`

#### 基本用法

```bash
# 扫描当前仓库的 Git 历史（默认最多 200 个 commit）
python scanner.py git .

# 扫描指定 Git 仓库
python scanner.py git /path/to/repo
```

#### 常用选项

| 选项 | 说明 |
|------|------|
| `path` | Git 仓库路径（默认: `.`） |
| `--output` 或 `-o` | 导出 JSON 报告路径 |

#### 使用示例

```bash
# 示例 1：基本扫描
python scanner.py git .

# 示例 2：扫描并导出报告
python scanner.py git . --output git-history-report.json

# 示例 3：扫描其他仓库
python scanner.py git /home/user/another-project
```

---

### 三、一键全面扫描（推荐）`scan --git`

本地文件扫描和 Git 历史扫描可以**一条命令同时完成**，只需在 `scan` 后加 `--git` 或 `-g`：

```bash
# 扫描当前目录的本地文件 + Git 历史
python scanner.py scan . --git

# 扫描指定目录，同时扫本地 + Git 历史，导出统一报告
python scanner.py scan /path/to/project --git --output full-report.json

# 详细模式 + Git 历史扫描
python scanner.py scan . --git --verbose

# 排除特定目录 + Git 历史扫描
python scanner.py scan . --exclude node_modules build --git --output full-report.json
```

**`--git` 做了什么：**

- 先执行本地目录扫描（扫描所有代码文件）
- 再对目标仓库的 `.git/` 历史进行扫描（默认最多 200 个 commit）
- 两种来源的泄露结果**合并展示**，统一输出到同一份报告
- 报告中每个泄露条目会标记来源（`"source": "local"` 或 `"source": "git"`）

---

### 四、查看 JSON 报告 `report`

```bash
# 查看全面扫描报告（包含本地 + Git 历史来源）
python scanner.py report full-report.json

# 查看本地扫描报告
python scanner.py report scan-report.json

# 查看 Git 历史扫描报告
python scanner.py report git-history-report.json
```

JSON 报告格式（全面扫描时）：

```json
{
  "scanned_at": "2026-04-08T12:00:00.000000",
  "files_scanned": 42,
  "lines_scanned": 1234,
  "total_findings": 5,
  "local_findings": 3,
  "git_findings": 2,
  "git_repo": "/path/to/project",
  "findings": [
    {
      "file": "config/.env",
      "type": "AWS Access Key ID",
      "severity": "critical",
      "line": 5,
      "column": 10,
      "matched": "AKIAIOSFODNN7***",
      "full_match": "AKIAIOSFODNN7EXAMPLE",
      "source": "local"
    },
    {
      "file": "git:commit:a1b2c3d4:src/secrets.py",
      "type": "GitHub Token",
      "severity": "critical",
      "line": 12,
      "matched": "ghp_xxxxxxxxxx***",
      "commit": "a1b2c3d4e5f6...",
      "source": "git"
    }
  ]
}
```

---

### 五、预提交钩子 `install-hook`

在 Git 仓库中安装预提交钩子，阻止包含敏感信息的提交。

#### 安装

```bash
# 在当前仓库安装预提交钩子
python scanner.py install-hook

# 在指定仓库安装
python scanner.py install-hook /path/to/repo
```

安装后，每次 `git commit` 时自动运行扫描。检测到泄露则阻断提交并显示警告信息。

#### 卸载

```bash
# 删除预提交钩子
rm .git/hooks/pre-commit
```

#### 工作原理

钩子会在 `git commit` 前执行以下操作：
1. 获取本次即将提交的所有文件
2. 对每个文件运行 `SecretScanner`
3. 发现泄露 → 打印警告并以 exit code 1 退出（阻止提交）
4. 无泄露 → 正常提交

> ⚠️ **Windows 兼容性**：`install-hook` 生成的 Shell 脚本需要在 Git Bash / WSL / Cygwin 环境下运行。如果在 Windows CMD/PowerShell 原生环境下使用，推荐改用下方的 Pre-commit 框架集成。

---

### 六、Pre-commit 框架集成（推荐，跨平台）

如果你的项目使用 [pre-commit](https://pre-commit.com/) 管理 Git 钩子，推荐使用此方式，**兼容 Windows/macOS/Linux 全平台**。

#### 安装步骤

```bash
# 1. 安装 pre-commit（如果你还没有）
pip install pre-commit

# 2. 在项目根目录创建 .pre-commit-config.yaml（已包含在项目中）
# 或手动创建：
# repos:
#   - repo: local
#     hooks:
#       - id: secretleak-scan
#         name: SecretLeak Scanner
#         entry: python scripts/precommit_check.py
#         language: system
#         pass_filenames: true

# 3. 安装钩子
pre-commit install

# 4. 可选：首次运行所有文件的扫描（验证配置）
pre-commit run --all-files secretleak-scan
```

#### 跳过扫描

临时跳过预提交扫描，正常提交：

```bash
git commit --no-verify -m "your commit message"
```

#### 工作原理

1. `pre-commit install` 会在 `.git/hooks/pre-commit` 中调用 pre-commit
2. 每次 `git commit` 时，pre-commit 自动运行 `.pre-commit-config.yaml` 中定义的钩子
3. `secretleak-scan` 钩子调用 `scripts/precommit_check.py`，扫描本次暂存的所有文件
4. 发现泄露 → 打印警告并以 exit code 1 退出（阻止提交）
5. 无泄露 → 正常提交

#### 与 `install-hook` 的区别

| 特性 | `install-hook` (Shell) | Pre-commit 框架 |
|------|------------------------|-----------------|
| 跨平台支持 | 仅 Unix Shell 环境 | ✅ Windows/macOS/Linux |
| 配置方式 | Shell 脚本 | YAML 配置文件 |
| 管理难度 | 需要手动编辑脚本 | 自动管理，版本控制友好 |
| 生态集成 | 独立使用 | 可与其他 pre-commit 钩子共存 |



### 终端输出（彩色）

```
============================================================
  开始扫描目录: /path/to/project
============================================================

  [CRITICAL]  AWS Access Key ID
    📄 config/.env
    📍 第 5 行  列 10
    └ AKIAIOSFODNN7***

  [GIT历史]  [CRITICAL]  GitHub Token
    📄 git:commit:a1b2c3d4:src/secrets.py
    📍 第 12 行  列 5
    🔖 commit: a1b2c3d4
    └ ghp_xxxxxxxxxx***

============================================================
  扫描摘要
============================================================
  📁 本地扫描:   文件 42 个  行数 1234 条
  📜 Git 历史:   1 条泄露
  泄露条数:     2

    CRITICAL    : 2
    HIGH        : 0
    MEDIUM      : 0
    LOW         : 0

  泄露类型 TOP 5:
       1 ×  AWS Access Key ID
       1 ×  GitHub Token

  📊 来源分布:   本地 1 条  |  Git 历史 1 条

  ⚠️  发现高危/严重泄露！请立即轮换相关密钥并撤销旧凭证。
```

### 详细模式（--verbose）

```
============================================================
  开始扫描目录: /path/to/project
============================================================

  [CRITICAL]  AWS Access Key ID
    📄 config/.env
    📍 第 5 行  列 10
    ├ AWS_DEFAULT_REGION=us-east-1
    └ AKIAIOSFODNN7***
    ├ AWS_SECRET_ACCESS_KEY=abcd1234...
```

---

## GitHub Actions CI/CD 集成

### 方式一：在扫描项目中启用 CI（推荐）

如果 `secretleak-scanner` 就是你要扫描的项目，直接 push 即可自动运行测试和扫描。

### 方式二：在目标项目中集成扫描

1. Fork 或克隆目标仓库
2. 将 `scanner.py` 和 `patterns.json` 复制到目标仓库，或作为 submodule 引入
3. 创建 GitHub Actions workflow

#### 完整 workflow 示例（使用一键全面扫描）

在目标仓库创建 `.github/workflows/secret-scan.yml`：

```yaml
name: Secret Leak Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 全量 clone 以扫描完整 Git 历史

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Download scanner
        run: |
          # 方式 A：作为 submodule
          # git submodule update --init --recursive

          # 方式 B：直接下载（适合快速集成）
          curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/secretleak-scanner/main/scanner.py -o scanner.py
          curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/secretleak-scanner/main/patterns.json -o patterns.json

      - name: Run full scan (local files + Git history)
        run: |
          python scanner.py scan . --git --exclude node_modules build --output full-report.json || true

      - name: Upload scan report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: secret-scan-report
          path: full-report.json

      - name: Fail on critical findings
        run: |
          if [ -f full-report.json ] && grep -q '"severity": "critical"' full-report.json; then
            echo "::error::Critical secrets detected! Please review the report."
            exit 1
          fi
```

> 💡 **提示**：使用 `scan --git` 一条命令即可完成全面扫描，无需分别执行 `scan` 和 `git` 两个步骤。

### GitLab CI 示例

创建 `.gitlab-ci.yml`：

```yaml
secret-scan:
  stage: test
  image: python:3.10-slim
  script:
    - pip install -q pytest
    - curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/secretleak-scanner/main/scanner.py -o scanner.py
    - curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/secretleak-scanner/main/patterns.json -o patterns.json
    # 一键全面扫描：本地文件 + Git 历史
    - python scanner.py scan . --git --exclude node_modules build --output full-report.json || true
  artifacts:
    when: always
    paths:
      - full-report.json
```

---

## patterns.json 规则扩展

### 规则格式

```json
{
  "规则名称": {
    "pattern": "正则表达式",
    "severity": "critical | high | medium | low",
    "description": "该规则的说明"
  }
}
```

### 危险等级说明

| 等级 | 说明 |
|------|------|
| `critical` 🔴 | 直接导致安全事件（如私钥、支付密钥） |
| `high` 🔴 | 可导致未授权访问（如 GitHub Token、Slack Token） |
| `medium` 🟡 | 潜在风险（如通用 API Key） |
| `low` 🟢 | 误报率较高，需人工复核 |

### 添加自定义规则示例

```json
{
  "Custom API Token": {
    "pattern": "custom_[a-zA-Z0-9]{32}",
    "severity": "high",
    "description": "自定义 API Token 格式"
  }
}
```

> 将自定义规则添加到 `patterns.json` 后，重启扫描即可生效。

---

## 常见问题

### Q1：扫描到误报怎么办？

**方法一**：在 `patterns.json` 中调整正则表达式（提高精确度）

**方法二**：将可疑文件移入排除目录（`--exclude`）

**方法三**：将测试用的假密钥文件移出代码仓库（如 `tests/fixtures/`），不要提交

**方法四**：使用白名单文件 `.secretsignore`（当前代码暂不支持，可自行扩展）

---

### Q2：Git 历史扫描太慢怎么办？

- 默认限制 200 个 commit，大型仓库可修改源码 `scanner.py` 中 `scan_git_history()` 的 `max_commits` 参数
- 或者只扫描近期的 commit：
  ```bash
  git clone --depth 100 https://github.com/xxx/xxx.git
  ```
- 使用 `git log -n 500 --format=%H | head -500 | xargs git show ...` 可手动控制范围

---

### Q3：支持 Windows 吗？

支持。但预提交钩子需要 Git Bash / WSL 环境。在纯 Windows cmd/PowerShell 下 `install-hook` 生成的 shell 脚本无法执行。

**Windows 推荐方案**：
- 使用 PowerShell 调用 `python scanner.py scan`
- CI/CD 使用 GitHub Actions（Linux 环境）则完全支持

---

### Q4：为什么 `.env.local` 文件没有被扫描？

`.env.local` 以 `.` 开头，被 `should_scan()` 方法的第一条规则跳过：

```python
if name.startswith(".") and name not in {".env", ".env.local", ".env.production"}:
    return False
```

注意：`.env.local` 目前**不在白名单内**（这是当前设计的限制），如果需要扫描此类文件，请将其改名或直接用文件路径传入 `scan` 命令。

---

### Q5：如何只扫描 Git 历史而不扫描本地文件？

使用独立的 `git` 子命令：

```bash
python scanner.py git /path/to/repo
```

这与 `scan --git` 不同：`scan --git` 会同时扫描本地文件和 Git 历史，而 `git` 子命令只扫 Git 历史。

---

### Q6：`scan --git` 和分别运行 `scan` + `git` 有什么区别？

| | `scan` + `git` | `scan --git` |
|---|---|---|
| 命令数量 | 两条 | 一条 |
| 报告输出 | 两个独立 JSON 文件 | 统一 JSON 文件 |
| 本地 + Git 汇总 | 需手动合并 | 自动合并 |
| 摘要展示 | 分开显示 | 统一汇总 |

功能上完全等价，推荐使用 `scan --git` 一条命令搞定。

---

## 故障排除

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `FileNotFoundError: patterns.json` | `patterns.json` 不在当前目录 | 确认 `scanner.py` 和 `patterns.json` 在同一目录 |
| `git` 命令执行失败 | 目录不是 Git 仓库 | 确保目标目录包含 `.git` 文件夹 |
| 扫描结果为空 | 文件格式不匹配 | 检查 `should_scan()` 中的扩展名列表是否包含你的文件类型 |
| 预提交钩子不生效 | 钩子文件无执行权限 | 检查 `.git/hooks/pre-commit` 是否有执行权限（`chmod +x`） |
| 中文路径乱码 | Windows 路径编码问题 | 使用英文路径或在代码中指定 `encoding="utf-8"` |
| `--git` 提示不是 Git 仓库 | 指定目录没有 `.git` | 检查路径是否正确，或该目录本就不是 Git 仓库 |

---

## 项目结构

```
secretleak-scanner/
├── scanner.py          # 核心扫描引擎（CLI 入口，所有命令从这里触发）
├── patterns.json       # 密钥正则规则库（30+ 条规则）
├── requirements.txt    # Python 依赖
├── README.md           # 本文件
└── .github/
    └── workflows/
        └── test.yml    # CI 自动测试
```

---

## 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支：`git checkout -b feature/new-pattern`
3. 在 `patterns.json` 中添加新规则（如有需要）
4. 运行测试：`python scanner.py scan .`
5. 提交并 Push：`git push origin feature/new-pattern`
6. 提交 Pull Request

---

## License

MIT License — 可免费使用于个人和商业项目。
