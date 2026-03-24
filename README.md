# 🔍 SecretLeak Scanner

**敏感信息泄露扫描器** — 自动检测代码仓库中的 API 密钥、Token、私钥等机密信息泄露。

支持本地文件扫描、Git 历史扫描、预提交钩子，适用于 GitHub CI/CD 集成。

---

## 功能特性

| 功能 | 说明 |
|------|------|
| 📁 **本地扫描** | 递归扫描目录，检测 30+ 种密钥类型 |
| 📜 **Git 历史扫描** | 扫描历史 commit 中遗漏的敏感信息 |
| 🪝 **预提交钩子** | 阻止包含密钥的新提交 |
| 📊 **CI/CD 集成** | GitHub Actions 一键集成 |
| 🧩 **可扩展规则** | 通过 `patterns.json` 轻松添加新规则 |
| 📝 **JSON 报告** | 导出标准化 JSON 报告，便于 CI 失败解析 |

---

## 支持检测的类型

- AWS / GitHub / Slack / OpenAI / Anthropic API Keys
- TLS/SSH 私钥文件
- 数据库连接字符串（MongoDB、PostgreSQL、Redis 等）
- JWT Token、Basic Auth 凭证
- Stripe / SendGrid / Mailgun / Telegram Bot Token
- Google Cloud / Cloudflare / NPM / PyPI Token
- 通用硬编码密码与 API Key
- …… 共 **30+** 种规则，持续更新

---

## 安装

```bash
# 克隆项目
git clone https://github.com/YOUR_USERNAME/secretleak-scanner.git
cd secretleak-scanner

# 安装依赖
pip install -r requirements.txt
```

---

## 快速开始

### 扫描本地目录

```bash
# 基本扫描（当前目录）
python scanner.py scan .

# 详细模式（显示上下文）
python scanner.py scan . --verbose

# 排除特定目录
python scanner.py scan . --exclude node_modules build dist

# 导出 JSON 报告
python scanner.py scan . --output report.json
```

### 扫描 Git 历史

```bash
# 扫描仓库所有历史（默认限制 200 个 commit）
python scanner.py git .

# 导出报告
python scanner.py git . --output git-history-report.json
```

### 查看 JSON 报告

```bash
python scanner.py report report.json
```

---

## 预提交钩子

在 Git 仓库中安装预提交钩子，阻止包含敏感信息的提交：

```bash
python scanner.py install-hook
```

钩子会在每次 `git commit` 前自动运行扫描，发现泄露则阻断提交。

---

## GitHub Actions CI 集成

在仓库中创建 `.github/workflows/secret-scan.yml`：

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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 全量 clone 以扫描完整历史

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          pip install -r scanner/requirements.txt

      - name: Scan local files
        run: |
          python scanner/scanner.py scan . --output scan-report.json || true

      - name: Scan Git history
        run: |
          python scanner/scanner.py git . --output git-report.json || true

      - name: Upload reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: secret-scan-reports
          path: "*.json"
```

---

## patterns.json 规则说明

规则文件格式如下：

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

| 等级 | 颜色 | 说明 |
|------|------|------|
| `critical` | 🔴 | 直接导致安全事件（如私钥、支付密钥） |
| `high` | 🔴 | 可导致未授权访问（如 GitHub Token、Slack Token） |
| `medium` | 🟡 | 潜在风险（如通用 API Key） |
| `low` | 🟢 | 误报率较高，需人工复核 |

---

## 项目结构

```
secretleak-scanner/
├── scanner.py          # 核心扫描引擎（CLI 入口）
├── patterns.json       # 密钥正则规则库
├── requirements.txt    # Python 依赖
├── README.md           # 本文件
└── .github/
    └── workflows/
        └── test.yml   # CI 自动测试
```

---

## 自行部署预提交钩子（高级）

### 手动安装

```bash
# 在仓库根目录运行
./scanner.py install-hook
```

### 卸载

```bash
rm .git/hooks/pre-commit
```

---

## 常见问题

**Q: 扫描到误报怎么办？**
A: 在 `.gitignore` 或排除目录中过滤，或在 `patterns.json` 中调整正则表达式。

**Q: Git 历史扫描太慢怎么办？**
A: 减少扫描 commit 范围：`git log -n 100 --format=%H | xargs git show ...`

**Q: 支持 Windows 吗？**
A: 支持，但预提交钩子需要 Git Bash / WSL 环境。

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
