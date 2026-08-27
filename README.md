
<h1 align="center">Pwnagent Sandbox</h1>

<p align="center">
  <b>Autonomous AI Penetration Testing Agent + Dockerized Offensive Security Sandbox</b>
</p>

---

## What is Pwnagent Sandbox?

Pwnagent Sandbox is the open-source runtime environment for **pwnagent.exe** — an autonomous AI penetration testing agent. The sandbox provides a fully equipped, Kali Linux-based Docker container with pre-installed offensive security tools, an HTTP interception proxy (Caido), a headless browser, and a Python exploit runtime. When **pwnagent.exe** connects to the sandbox, it orchestrates multi-agent security assessments that discover, validate, and report real vulnerabilities with working proofs-of-concept.

**pwnagent.exe** is the compiled CLI binary (built via PyInstaller from this repository). It handles LLM orchestration, the TUI/CLI interface, scan lifecycle, and communicates with the sandbox container over the Docker API and Caido SDK.

---

## Features

### AI-Powered Agent Orchestration
- **Multi-agent graph** — a root agent spawns specialized child agents for recon, exploitation, and post-exploitation that collaborate and share discoveries in real time.
- **Resumable scans** — interrupted scans can be resumed from the exact agent state with `--resume <run-name>`.
- **Budget controls** — set a hard USD cap on LLM spend per scan with `--max-budget-usd`.

### Offensive Security Toolkit (inside the sandbox)
- **Network scanning** — Nmap, Naabu, Subfinder, httpx, Katana
- **Vulnerability scanning** — Nuclei (with auto-updated templates), SQLMap, Wapiti, ZAP, Trivy, Semgrep, Bandit
- **Web exploitation** — Chromium-based headless browser (agent-browser), FFuf, Arjun, Dirsearch, wafw00f
- **HTTP interception proxy** — Caido (auto-started, full request/response capture and manipulation)
- **Secret scanning** — TruffleHog, Gitleaks
- **Code analysis** — ast-grep, tree-sitter (Java, JS, Python, Go, Bash, JSON, YAML, TypeScript), ESLint, JSHint
- **JWT & auth testing** — jwt_tool, JS-Snooper, jsniper
- **Exploit development** — Python venv sandbox, GDB, full GCC toolchain

### Comprehensive Vulnerability Coverage
Covers the OWASP Top 10 and beyond with built-in skill files for:

| Category | Vulnerabilities |
|---|---|
| **Injection** | SQL injection, NoSQL injection, SSTI, OS command injection, XXE |
| **Broken Access Control** | IDOR, mass assignment, broken function-level authorization |
| **Authentication** | JWT attacks, weak passwords, OAuth flaws, Auth0 misconfigurations |
| **Client-Side** | XSS (stored/reflected/DOM), CSRF, prototype pollution, open redirect |
| **Server-Side** | SSRF, RCE, insecure deserialization, path traversal/LFI/RFI |
| **Business Logic** | Race conditions, payment manipulation, workflow bypass |
| **Infrastructure** | Subdomain takeover, HTTP request smuggling, header injection |
| **Cloud & DevOps** | AWS, GCP, Kubernetes misconfigurations |
| **Supply Chain** | Dependency CVE scanning, Nuclei CVE templates |
| **AI/LLM** | Prompt injection in LLM-powered features |

### Framework-Aware Scanning
Built-in skills for Django, FastAPI, NestJS, Next.js, GraphQL, Firebase/Firestore, and Supabase.

### Scan Modes
- **quick** — fast CI/CD checks, scoped to changed files in PRs
- **standard** — routine white-box source-aware testing
- **deep** — thorough security review (default)

### Multi-Provider LLM Support
Works with any LLM provider via LiteLLM:
- OpenAI (GPT-5.x series)
- Anthropic (Claude Opus, Sonnet, Fable)
- Google (Gemini 3.x via Vertex AI)
- DeepSeek (v4 series)
- Alibaba (Qwen 3.x via DashScope)
- Moonshot (Kimi K2.x)
- Azure, Bedrock, OpenRouter, Ollama, LM Studio, and any OpenAI-compatible endpoint

### Reporting & CI/CD
- Real-time vulnerability display with CVSS scoring
- Executive summary report on scan completion
- Non-interactive mode (`-n`) for headless/CI environments with non-zero exit on findings
- GitHub Actions workflow included for PR-level security gating

---

## Architecture

```
+------------------+          Docker API / SDK          +----------------------------+
|                  | -------------------------------------> |                            |
|  pwnagent.exe    |          Caido SDK (GraphQL)       |   Sandbox Container        |
|  (Host Machine)  | -------------------------------------> |   (Kali Linux)             |
|                  |                                    |                            |
|  - LLM client    |                                    |   - Caido proxy (port 48080)|
|  - Agent graph   |                                    |   - Nmap, Nuclei, SQLMap    |
|  - TUI / CLI     |                                    |   - Headless Chromium       |
|  - Report writer |                                    |   - Python exploit venv     |
|  - Scan lifecycle|                                    |   - 40+ security tools      |
+------------------+                                    +----------------------------+
        |                                                           |
        |  LLM API (OpenAI / Anthropic / etc.)                     |  Targets
        v                                                           v
  +-----------+                                           +------------------+
  | LLM       |                                           | Web apps, repos, |
  | Provider  |                                           | IPs, domains     |
  +-----------+                                           +------------------+
```

---

## Requirements

### System Requirements
| Requirement | Details |
|---|---|
| **OS** | Windows 10/11, macOS (Intel or Apple Silicon), or Linux (x86_64) |
| **Docker** | Docker Desktop or Docker Engine — must be running |
| **RAM** | 8 GB minimum (16 GB recommended for deep scans) |
| **Disk** | ~5 GB for the sandbox Docker image |
| **Network** | Internet access for LLM API calls and pulling the sandbox image |

### Software Requirements
| Component | Purpose |
|---|---|
| **pwnagent.exe** | The compiled agent binary (see [Building from Source](#building-from-source)) |
| **Docker** | Hosts the sandbox container with all pentesting tools |
| **LLM API Key** | From any supported provider (OpenAI, Anthropic, Google, etc.) |

### Environment Variables

**Required:**

| Variable | Description | Example |
|---|---|---|
| `PWNAGENT_LLM` | LLM model identifier in `provider/model` format | `openai/gpt-5.4` |

**Optional:**

| Variable | Description | Default |
|---|---|---|
| `LLM_API_KEY` | API key for the LLM provider (not needed for local models, Vertex AI, AWS) | — |
| `LLM_API_BASE` | Custom API base URL for local models (Ollama, LM Studio) | — |
| `LLM_TIMEOUT` | LLM request timeout in seconds | `300` |
| `PERPLEXITY_API_KEY` | Enables real-time web search during scans | — |
| `GITHUB_TOKEN` | For private repository access | — |
| `PWNAGENT_REASONING_EFFORT` | Thinking depth: `none`, `minimal`, `low`, `medium`, `high`, `xhigh` | `high` |
| `PWNAGENT_IMAGE` | Custom sandbox Docker image | `ghcr.io/punitdarji/pwnagent-sandbox:1.0.0` |
| `PWNAGENT_RUNTIME_BACKEND` | Container backend | `docker` |
| `PWNAGENT_MAX_LOCAL_COPY_MB` | Max local target size before requiring `--mount` | `1024` |
| `PWNAGENT_TELEMETRY` | Enable/disable telemetry | `true` |

---

## Installation

### Option 1: Download Pre-built Binary

Download the binary for your platform from the [Releases](https://github.com/punitdarji/pwnagent/releases) page.

#### Windows

1. Download `pwnagent-<version>-windows-x86_64.zip` from Releases.
2. Extract the ZIP — you'll get `pwnagent.exe`.
3. Move `pwnagent.exe` to a folder in your PATH, or run it directly:

```powershell
# Option A: Run from the current directory
.\pwnagent.exe --target https://example.com

# Option B: Add to PATH permanently (run PowerShell as Administrator)
New-Item -ItemType Directory -Force -Path "C:\Tools\pwnagent"
Move-Item .\pwnagent.exe "C:\Tools\pwnagent\pwnagent.exe"
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\pwnagent", "Machine")
# Restart your terminal, then use from anywhere:
pwnagent --target https://example.com
```

4. Set your environment variables:

```powershell
# Set for current session
$env:PWNAGENT_LLM = "openai/gpt-5.4"
$env:LLM_API_KEY = "sk-..."

# Or set permanently (persists across terminal sessions)
[Environment]::SetEnvironmentVariable("PWNAGENT_LLM", "openai/gpt-5.4", "User")
[Environment]::SetEnvironmentVariable("LLM_API_KEY", "sk-...", "User")
```

> **Windows prerequisite:** [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/) must be installed and running. Make sure WSL 2 backend is enabled in Docker Desktop settings.

#### macOS

```bash
# Apple Silicon (M1/M2/M3/M4)
curl -LO https://github.com/punitdarji/pwnagent/releases/latest/download/pwnagent-<version>-macos-arm64.tar.gz
tar -xzf pwnagent-*-macos-arm64.tar.gz
chmod +x pwnagent-*-macos-arm64
sudo mv pwnagent-*-macos-arm64 /usr/local/bin/pwnagent

# Intel Mac
curl -LO https://github.com/punitdarji/pwnagent/releases/latest/download/pwnagent-<version>-macos-x86_64.tar.gz
tar -xzf pwnagent-*-macos-x86_64.tar.gz
chmod +x pwnagent-*-macos-x86_64
sudo mv pwnagent-*-macos-x86_64 /usr/local/bin/pwnagent

# Or use the install script (auto-detects architecture)
curl -sSL https://pwnagent.ai/install | bash
```

#### Linux

```bash
curl -LO https://github.com/punitdarji/pwnagent/releases/latest/download/pwnagent-<version>-linux-x86_64.tar.gz
tar -xzf pwnagent-*-linux-x86_64.tar.gz
chmod +x pwnagent-*-linux-x86_64
sudo mv pwnagent-*-linux-x86_64 /usr/local/bin/pwnagent

# Or use the install script
curl -sSL https://pwnagent.ai/install | bash
```

### Option 2: Install via pip/pipx

```bash
pipx install pwnagent-agent

# With optional provider extras
pipx install "pwnagent-agent[bedrock]"   # AWS Bedrock
pipx install "pwnagent-agent[vertex]"    # Google Vertex AI
```

On Windows (if pipx is installed via `pip install pipx` or `scoop install pipx`):

```powershell
pipx install pwnagent-agent
```

### Option 3: Build from Source

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

#### Windows

```powershell
git clone https://github.com/punitdarji/pwnagent.git
cd pwnagent

# Install uv if not already installed
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Install dependencies and build
uv sync --frozen
uv run pyinstaller pwnagent.spec --noconfirm

# Binary is at dist\pwnagent.exe
```

#### macOS / Linux

```bash
git clone https://github.com/punitdarji/pwnagent.git
cd pwnagent

# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies and build
uv sync --frozen
uv run pyinstaller pwnagent.spec --noconfirm

# Binary is at dist/pwnagent
```

### Docker Image (First Run)

On first launch, pwnagent automatically pulls the sandbox image (`ghcr.io/punitdarji/pwnagent-sandbox:1.0.0`). This is a one-time ~5 GB download. No manual Docker setup is needed beyond having Docker running.

**Windows users:** Make sure Docker Desktop is running (look for the whale icon in the system tray). If you see a "Docker daemon is not running" error, open Docker Desktop and wait for it to finish starting.

---

## Connecting pwnagent.exe with the Sandbox

The connection between **pwnagent.exe** and the sandbox is fully automatic. Here is what happens under the hood:

1. **pwnagent.exe** checks that Docker is installed and running.
2. It pulls the sandbox image if not already present locally.
3. It creates a Docker container from the image with:
   - The Caido HTTP interception proxy auto-started on port 48080
   - System-wide proxy configuration inside the container
   - CA certificates installed and trusted (for HTTPS interception)
   - A `/workspace` directory for target code and scan artifacts
4. **pwnagent.exe** connects to the container via the Docker SDK and Caido GraphQL API.
5. The root AI agent is initialized with the scan configuration, then spawns child agents as needed.
6. All tool execution (Nmap scans, Nuclei templates, browser actions, exploit scripts) runs inside the sandbox.
7. Findings are streamed back to **pwnagent.exe** in real time and displayed in the TUI or CLI.

### What You Need to Do

**Linux / macOS:**

```bash
# 1. Make sure Docker is running
docker info

# 2. Set your LLM provider
export PWNAGENT_LLM="openai/gpt-5.4"
export LLM_API_KEY="sk-..."

# 3. Run a scan — the sandbox connection is automatic
pwnagent --target https://your-app.com
```

**Windows (PowerShell):**

```powershell
# 1. Make sure Docker Desktop is running
docker info

# 2. Set your LLM provider
$env:PWNAGENT_LLM = "openai/gpt-5.4"
$env:LLM_API_KEY = "sk-..."

# 3. Run a scan — the sandbox connection is automatic
pwnagent.exe --target https://your-app.com
```

**Windows (Command Prompt):**

```cmd
:: 1. Make sure Docker Desktop is running
docker info

:: 2. Set your LLM provider
set PWNAGENT_LLM=openai/gpt-5.4
set LLM_API_KEY=sk-...

:: 3. Run a scan
pwnagent.exe --target https://your-app.com
```

That's it. No manual container management, no port mapping, no volume mounts (unless you want `--mount` for large repos).

---

## Usage

### Basic Scans

```bash
# Web application penetration test
pwnagent --target https://example.com

# GitHub repository analysis
pwnagent --target https://github.com/org/repo

# Local codebase (white-box)
pwnagent --target ./my-project

# IP address / domain
pwnagent --target 192.168.1.42
pwnagent --target example.com
```

### Advanced Usage

```bash
# Multi-target (source + deployed app)
pwnagent -t https://github.com/org/app -t https://app.example.com

# Targets from file
pwnagent --target-list ./targets.txt

# Authenticated testing with custom instructions
pwnagent --target https://app.com --instruction "Use credentials admin:pass123. Focus on IDOR and auth bypass."

# Instructions from file
pwnagent --target https://app.com --instruction-file ./scope.md

# Large repos — bind-mount instead of copying
pwnagent --mount ./huge-monorepo

# Quick CI scan scoped to changed files
pwnagent -n -t ./ --scan-mode quick --scope-mode diff --diff-base origin/main

# Set a budget cap
pwnagent --target https://app.com --max-budget-usd 10.00

# Resume an interrupted scan
pwnagent --resume my-scan-2025-08-20
```

### Non-Interactive / CI Mode

```bash
# Headless mode — prints findings to stdout, exits with code 2 if vulns found
pwnagent -n --target https://your-app.com
```

### GitHub Actions Integration

```yaml
name: pwnagent-security-scan

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Pwnagent
        run: curl -sSL https://pwnagent.ai/install | bash

      - name: Run Pwnagent
        env:
          PWNAGENT_LLM: ${{ secrets.PWNAGENT_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: pwnagent -n -t ./ --scan-mode quick
```

---

## Configuration

Pwnagent auto-saves configuration to `~/.pwnagent/cli-config.json` after the first run. You can also provide a custom config file:

```bash
pwnagent --config ./my-config.json --target https://app.com
```

### Recommended Models

| Provider | Model | ID |
|---|---|---|
| OpenAI | GPT-5.4 | `openai/gpt-5.4` |
| Anthropic | Claude Sonnet 4.6 | `anthropic/claude-sonnet-4-6` |
| Google | Gemini 3 Pro | `vertex_ai/gemini-3-pro-preview` |
| DeepSeek | DeepSeek V4 Pro | `deepseek/deepseek-v4-pro` |
| Moonshot | Kimi K2.7 Code | `moonshot/kimi-k2.7-code` |

For the full list of supported providers and models, see the [LLM Providers documentation](https://docs.pwnagent.ai/llm-providers/overview).

---

## Project Structure

```
pwnagent-sandbox/
├── pwnagent/
│   ├── agents/           # Agent factory, system prompt templates (Jinja2)
│   ├── config/           # Settings, LLM model configuration, provider routing
│   ├── core/             # Scan runner, agent coordinator, execution loop, sessions
│   ├── integrations/     # MCP server integration
│   ├── interface/        # CLI (Rich), TUI (Textual), argument parsing
│   ├── report/           # Vulnerability deduplication, report state, writer
│   ├── runtime/          # Docker client, Caido bootstrap, session manager
│   ├── skills/           # 55+ Markdown skill files (vulns, frameworks, tools, cloud)
│   ├── telemetry/        # PostHog + Scarf telemetry
│   └── tools/            # Agent tool implementations
│       ├── agents_graph/ # Multi-agent spawn/coordination tools
│       ├── cve_scanner/  # CVE scanning tool
│       ├── finish/       # Scan lifecycle tool
│       ├── notes/        # Agent note-taking tools
│       ├── proxy/        # Caido proxy interaction tools
│       ├── python/       # In-sandbox Python execution tool
│       ├── reporting/    # Vulnerability reporting tool
│       ├── thinking/     # Chain-of-thought reasoning tool
│       ├── todo/         # Task tracking tools
│       └── web_search/   # Perplexity web search tool
├── containers/
│   ├── Dockerfile        # Kali-based sandbox image with 40+ security tools
│   └── docker-entrypoint.sh  # Caido startup, proxy config, CA trust
├── docs/                 # Mintlify documentation source
├── benchmarks/           # Performance benchmarks
├── .github/
│   └── workflows/
│       └── build-release.yml  # CI: build binaries for Win/Mac/Linux + GitHub Release
├── pwnagent.spec         # PyInstaller spec for building pwnagent.exe
├── Makefile              # Dev commands: format, lint, type-check, security
└── LICENSE               # Apache 2.0
```

---

## Building the Sandbox Image Locally

If you want to build the Docker sandbox image yourself instead of pulling from the registry:

```bash
docker build -t pwnagent-sandbox:local -f containers/Dockerfile .

# Tell pwnagent to use your local image
export PWNAGENT_IMAGE="pwnagent-sandbox:local"
pwnagent --target https://app.com
```

---

## Development

```bash
# Set up the development environment
make setup-dev

# Run all quality checks
make check-all

# Individual checks
make format       # Format with ruff
make lint         # Lint with ruff
make type-check   # mypy + pyright
make security     # bandit security scan

# Clean build artifacts
make clean
```

---

## Troubleshooting

### General

| Issue | Solution |
|---|---|
| `Docker not installed` | Install Docker Desktop and ensure the `docker` command is in your PATH |
| `Docker daemon not running` | Start Docker Desktop or run `sudo systemctl start docker` (Linux) |
| `LLM CONNECTION FAILED` | Check that `PWNAGENT_LLM` and `LLM_API_KEY` are set correctly |
| `Unknown model name` | Use the `provider/model` format, e.g. `openai/gpt-5.4` not just `gpt-5.4` |
| `Local target too large` | Use `--mount ./path` instead of `--target ./path` for large repos |
| `Missing boto3` | Install Bedrock support: `pipx install "pwnagent-agent[bedrock]"` |
| `Missing google-auth` | Install Vertex AI support: `pipx install "pwnagent-agent[vertex]"` |
| Scan interrupted | Resume with `pwnagent --resume <run-name>` |

### Windows-Specific

| Issue | Solution |
|---|---|
| `docker: command not found` | Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/). After installation, restart your terminal. |
| Docker Desktop won't start | Enable WSL 2 in Windows Features (`wsl --install`), then restart your PC. In Docker Desktop settings, ensure "Use the WSL 2 based engine" is checked. |
| `pwnagent.exe` not recognized | Either run from the directory where the `.exe` is located (`.\pwnagent.exe`) or add its folder to the system PATH (see [Windows installation](#windows)). |
| Environment variables not persisting | Use `[Environment]::SetEnvironmentVariable("PWNAGENT_LLM", "openai/gpt-5.4", "User")` in PowerShell to set permanently. Variables set with `$env:` or `set` only last for the current session. |
| Antivirus blocks `pwnagent.exe` | PyInstaller binaries can trigger false positives. Add `pwnagent.exe` to your antivirus exclusion list, or build from source to avoid this. |
| `WindowsSelectorEventLoopPolicy` error | This is handled automatically. If you see async errors, make sure you're using Python 3.12+ when building from source. |
| Sandbox image pull is slow | The first pull downloads ~5 GB. On WSL 2, Docker stores images in the WSL filesystem. Ensure you have enough disk space on your WSL virtual disk. |
| Path issues with `--target .\my-project` | Use forward slashes (`--target ./my-project`) or quote the path (`--target ".\my-project"`). |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

> **WARNING:** Only test applications and systems you own or have explicit written authorization to test. You are solely responsible for using Pwnagent ethically and legally. Unauthorized penetration testing is illegal.
