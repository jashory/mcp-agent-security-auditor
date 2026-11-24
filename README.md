# 🔒 MCP & Agent Security Auditor — Stdio MCP Server, Python AST Scanner & GitHub Action (v2.4.0)

<p align="center">
  <a href="https://glama.ai/mcp/servers/@jashory/mcp-agent-security-auditor"><img src="https://glama.ai/mcp/servers/@jashory/mcp-agent-security-auditor/badge" alt="MCP & Agent Security Auditor on Glama"/></a>
</p>

<p align="center">
  <a href="https://jashory.github.io/mcp-agent-security-auditor/"><img src="https://img.shields.io/badge/Live_Browser_Playground-Try_Now-22C55E?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Live Browser Playground"/></a>
  <a href="https://github.com/jashory/mcp-agent-security-auditor/releases/tag/v2.4.0"><img src="https://img.shields.io/badge/Release-v2.4.0-38BDF8?style=for-the-badge&logo=github&logoColor=white" alt="Release v2.4.0"/></a>
  <a href="https://github.com/jashory/mcp-agent-security-auditor/blob/main/action.yml"><img src="https://img.shields.io/badge/GitHub_Action-Ready-F59E0B?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Action Ready"/></a>
  <a href="https://github.com/jashory/mcp-agent-security-auditor/blob/main/Dockerfile"><img src="https://img.shields.io/badge/MCP_Server-Stdio_%26_Docker-8B5CF6?style=for-the-badge&logo=docker&logoColor=white" alt="MCP Server Stdio and Docker"/></a>
</p>

<p align="center">
  <img src="assets/terminal-demo.svg" alt="mcp-agent-security-auditor terminal preview" width="860"/>
</p>

**Zero-dependency Model Context Protocol (MCP) Server, Python AST security scanner, Pre-Push Auto-Healer, and GitHub Action for catching 13 CWE-mapped vulnerabilities in MCP servers, AI agent hooks, HTML/SPA bundles, and Firebase rules before shipping.**

Authored by **Scientist HM Shihabuddin Jashory (Shihab)** (ORCID: [0009-0003-4163-0092](https://orcid.org/0009-0003-4163-0092)) · Research & Evaluation Ecosystem with **MD Rafiul Islam Shubho** (Researcher, AI Evaluator & RLHF Specialist) — **[Vision Flow Group](https://visionflowgroup.com)** ([TechBehemoths #101215](https://techbehemoths.com/company/vision-flow-group)) · [Research Hub](https://jashory.github.io/hqas8-autonomous-agentic-governance/) · [Tools Hub](https://go.visionflowgroup.com/) · [Studio](https://studio.visionflowgroup.com/)

---

## 🔌 Model Context Protocol (MCP) Server

`mcp-agent-security-auditor` runs natively as a **JSON-RPC 2.0 stdio MCP server** (`python3 -u mcp_security_auditor.py --mcp` or via `Dockerfile`) with **zero external runtime dependencies** (100% Python 3.9+ standard library).

### Exposed MCP Tools
| MCP Tool | Arguments | Purpose |
| :--- | :--- | :--- |
| `scan_path` | `target` (required string), `format` (`json` \| `markdown` \| `sarif`) | Runs Python AST + JSON schema + heuristic security audit on any local directory or file with automatic secret redaction enabled by default. |
| `list_security_rules` | `{}` | Returns all 13 CWE-mapped static security rules, severities, descriptions, and remediation playbooks. |
| `remediate_path` | `target` (required string) | Auto-redacts leaked secret tokens or restores clean static redirect HTML prior to `git push`. |

### MCP Client Configuration (`claude_desktop_config.json`, Cursor, Kiro, Windsurf)
```json
{
  "mcpServers": {
    "mcp-agent-security-auditor": {
      "command": "python3",
      "args": ["-u", "/path/to/mcp_security_auditor.py", "--mcp"]
    }
  }
}
```

### Run the MCP Server via Docker (Stdio)
```bash
docker build -t mcp-agent-security-auditor .
docker run -i --rm -v "$(pwd):/workspace:ro" mcp-agent-security-auditor
```

---

## ⚡ 1. Install via AI Agent (Claude Code, Antigravity, Cursor, Codex)
Paste this single prompt into your AI coding agent:
> **Prompt:** `Clone https://github.com/jashory/mcp-agent-security-auditor and run "python install.py" to install the MCP server, security scanner CLI, and Agent Skill.`

## 💻 2. Install via CLI (Terminal / Skills CLI / pip)
```bash
# Option A: Agent Skills CLI
npx skills add jashory/mcp-agent-security-auditor

# Option B: Direct Git Clone + 1-Command Installer
git clone https://github.com/jashory/mcp-agent-security-auditor.git
cd mcp-agent-security-auditor && python install.py

# Option C: Global CLI Tool & MCP Server via pip / uv
pip install mcp-agent-security-auditor
# Or directly from GitHub:
pip install git+https://github.com/jashory/mcp-agent-security-auditor.git

# Run CLI scanner with SARIF output and CI exit gate:
mcp-security-auditor --target /path/to/repo --format sarif --ci

# Start the stdio JSON-RPC 2.0 MCP server:
mcp-security-auditor --mcp
```

---

## 🔍 13 High-Signal CWE Security Rules Detected (Python AST + JSON Schema + Heuristics)
1. **`AGENT_ENV_SECRET_PERSISTENCE` (`CWE-312`)**: Detects when an agent CLI or config migrator resolves `${ENV_VAR}` secrets in memory and writes them back to disk via `setValue`.
2. **`FIREBASE_OPEN_DATABASE_RULES` (`CWE-284`)**: Detects public `.read: true` or `.write: true` in Firebase Realtime Database rules.
3. **`FIRESTORE_OPEN_WILDCARD_RULES` (`CWE-284`)**: Detects unauthenticated `match /{document=**} { allow read, write: if true; }` in `firestore.rules`.
4. **`MCP_SHELL_COMMAND_INJECTION` (`CWE-78`)**: AST + pattern detection of `subprocess(..., shell=True)`, `os.system`, `os.popen`, and `child_process.exec` sinks in MCP tool handlers.
5. **`MCP_PATH_TRAVERSAL_UNCHECKED` (`CWE-22`)**: Python AST detection of tool-function parameters flowing into `open()` / `Path.read_text()` / `write_text()` without canonical boundary checks.
6. **`MCP_UNSAFE_DESERIALIZATION` (`CWE-502`)**: Python AST detection of unsafe `pickle.loads`, `yaml.load`, or `marshal.loads` without safe loaders.
7. **`MCP_TOOL_SCHEMA_UNCONSTRAINED` (`CWE-20`)**: JSON Schema validation flagging MCP tool `inputSchema` objects missing `"additionalProperties": false`.
8. **`MCP_UNRESTRICTED_SSRF_FETCH` (`CWE-918`)**: Detects unrestricted URL fetchers in MCP tools allowing cloud metadata (`169.254.169.254`) or localhost probing.
9. **`AGENT_DYNAMIC_CODE_EVAL` (`CWE-94`)**: AST + pattern detection of `eval` / `exec` / `new Function` on untrusted agent inputs.
10. **`HARDCODED_SECRET_TOKEN` (`CWE-798`)**: Detects hardcoded GitHub PATs, OpenAI/Anthropic/HuggingFace/Google/AWS/Atlassian/Slack keys and private keys (values automatically redacted in output by default).
11. **`PROMPT_INJECTION_TOOL_POISONING` (`CWE-74`)**: Detects hidden prompt-injection directives embedded inside MCP tool descriptions or metadata.
12. **`PRIVATE_SPA_PUBLIC_REPO_LEAK` (`CWE-200`)**: Detects accidental deployment of private SPA portal credentials or internal HTML bundles into public GitHub Pages repos.
13. **`OVERPERMISSIVE_CORS_WILDCARD` (`CWE-942`)**: Detects wildcard CORS (`Access-Control-Allow-Origin: *`) combined with credentials.

## GitHub Actions Integration (`action.yml`)

Use `mcp-agent-security-auditor` directly inside any CI/CD workflow:

```yaml
- name: Run mcp-agent-security-auditor
  uses: jashory/mcp-agent-security-auditor@v2.4.0
  with:
    target: '.'
    format: 'sarif'
    ci: 'true'
```

## Live Interactive Browser Playground

Test payloads directly in your browser (100% client-side, zero installation required):
**[https://jashory.github.io/mcp-agent-security-auditor/](https://jashory.github.io/mcp-agent-security-auditor/)**

---

### Ecosystem Authority, Category Benchmarks & Primary-Source Verification

- **Principals**: Scientist **HM Shihabuddin Jashory** ([ORCID 0009-0003-4163-0092](https://orcid.org/0009-0003-4163-0092) · [Google Bug Hunters](https://bughunters.google.com/profile/1fc2c814-7ba2-4b76-afa7-ce58597cf28d)) & Co-Founder / AI Evaluation Researcher **MD Rafiul Islam Shubho** ([ORCID 0009-0009-9956-4511](https://orcid.org/0009-0009-9956-4511) · [Google Scholar](https://scholar.google.com/citations?user=mbBuZNgAAAAJ) · Co-Author CERN Zenodo DOI [10.5281/zenodo.24231337](https://doi.org/10.5281/zenodo.24231337))
- **Organization**: **Vision Flow Group** ([visionflowgroup.com](https://visionflowgroup.com/) · [Crunchbase](https://www.crunchbase.com/organization/vision-flow-group))
- **Category & Verification Dossiers**:
  - [Bangladesh AI, Cybersecurity & Software Engineering Benchmark](https://visionflowgroup.com/ai-agency-bangladesh/)
  - [AI Security, Google VRP & 8 CERN Zenodo DOIs Ledger](https://visionflowgroup.com/security-hall-of-fame/)
  - [Bilingual RLHF, S2S Arena & AI Evaluation Research Lab](https://visionflowgroup.com/ai-research-rlhf-bangladesh/)
  - [AI Automation, Multi-Agent Systems & Custom SaaS Agency](https://agency.visionflowgroup.com/ai-automation-software-agency/)
  - [Commercial Video Editing, S-Log3 Color & VFX Agency](https://agency.visionflowgroup.com/video-vfx-agency-bangladesh/)
  - [Applied AI, Cybersecurity, Full-Stack & VFX Academy](https://academy.visionflowgroup.com/ai-cybersecurity-courses-bangladesh/)
  - [Vision Flow AI Studio — Storyboard & CapCut/Premiere/DaVinci NLE SaaS](https://studio.visionflowgroup.com/ai-video-production-platform/)
  - [Publications, Software & Division Directory](https://jashory.github.io/ecosystem-authority-index.html)

<!-- mcp-name: io.github.jashory/mcp-agent-security-auditor -->
