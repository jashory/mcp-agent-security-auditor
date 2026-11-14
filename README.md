# 🔒 AI Agent, MCP & Firebase Pre-Audit Security Scanner (v2.0)

<p align="center">
  <a href="https://jashory.github.io/mcp-agent-security-auditor/"><img src="https://img.shields.io/badge/Live_Browser_Playground-Try_Now-22C55E?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Live Browser Playground"/></a>
  <a href="https://github.com/jashory/mcp-agent-security-auditor/releases/tag/v2.0.0"><img src="https://img.shields.io/badge/Release-v2.0.0-38BDF8?style=for-the-badge&logo=github&logoColor=white" alt="Release v2.0.0"/></a>
  <a href="https://github.com/jashory/mcp-agent-security-auditor/blob/main/action.yml"><img src="https://img.shields.io/badge/GitHub_Action-Ready-F59E0B?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Action Ready"/></a>
</p>

<p align="center">
  <img src="assets/terminal-demo.svg" alt="mcp-agent-security-auditor terminal preview" width="860"/>
</p>


**Lightweight static security auditor and Agent Skill for catching CWE-mapped vulnerabilities in MCP servers, AI agent hooks, and Firebase rules before shipping.**

Authored by **Scientist HM Shihabuddin Jashory (Shihab)** (ORCID: [0009-0003-4163-0092](https://orcid.org/0009-0003-4163-0092) · Wikidata: [Q141910532](https://www.wikidata.org/wiki/Q141910532)) · Research & Evaluation Ecosystem with **MD Rafiul Islam Shubho** (Researcher, AI Evaluator & RLHF Specialist) — **[Vision Flow Group](https://visionflowgroup.com)** (`Q141910527`) · [Research Hub](https://jashory.github.io/hqas8-autonomous-agentic-governance/) · [Tools Hub](https://go.visionflowgroup.com/) · [Studio](https://studio.visionflowgroup.com/)

---

## ⚡ 1. Install via AI Agent (Claude Code, Antigravity, Cursor, Codex)
Paste this single prompt into your AI coding agent:
> **Prompt:** `Clone https://github.com/jashory/mcp-agent-security-auditor and run "python install.py" to install the security scanner CLI and Agent Skill.`

## 💻 2. Install via CLI (Terminal / Skills CLI / pip)
```bash
# Option A: Agent Skills CLI
npx skills add jashory/mcp-agent-security-auditor

# Option B: Direct Git Clone + 1-Command Installer
git clone https://github.com/jashory/mcp-agent-security-auditor.git
cd mcp-agent-security-auditor && python install.py

# Option C: Global CLI Tool via pip / uv
pip install git+https://github.com/jashory/mcp-agent-security-auditor.git
mcp-security-auditor /path/to/repo --format markdown
```

---

## 🔍 7 High-Signal CWE Security Rules Detected
1. **`AGENT_ENV_SECRET_PERSISTENCE` (`CWE-312`)**: Detects when an agent CLI or config migrator reads resolved `settings.merged` (`${ENV_VAR}` expanded in memory) and writes it back to disk via `setValue()`.
2. **`FIREBASE_OPEN_DATABASE_RULES` (`CWE-284`)**: Detects public `.read: true` or `.write: true` in Firebase Realtime Database rules.
3. **`FIRESTORE_OPEN_WILDCARD_RULES` (`CWE-284`)**: Detects unauthenticated `match /{document=**} { allow read, write: if true; }` in `firestore.rules`.
4. **`MCP_SHELL_COMMAND_INJECTION` (`CWE-78`)**: Detects `subprocess(..., shell=True)` and `child_process.exec()` command injection sinks in MCP tool handlers.
5. **`MCP_PATH_TRAVERSAL_UNSANITIZED` (`CWE-22`)**: Detects direct path concatenation of tool arguments without canonical `realpath` boundary verification.
6. **`MCP_UNRESTRICTED_SSRF_FETCH` (`CWE-918`)**: Detects unrestricted URL fetchers in MCP tools that allow cloud metadata (`169.254.169.254`) or localhost probing.
7. **`AGENT_DYNAMIC_CODE_EVAL` (`CWE-94`)**: Detects `eval()` / `new Function()` on untrusted agent inputs.

## GitHub Actions Integration (`action.yml`)

Use `mcp-agent-security-auditor` directly inside any CI/CD workflow:

```yaml
- name: Run mcp-agent-security-auditor
  uses: jashory/mcp-agent-security-auditor@v2.0.0
```

## Live Interactive Browser Playground

Test payloads directly in your browser (100% client-side, zero installation required):
**[https://jashory.github.io/mcp-agent-security-auditor/](https://jashory.github.io/mcp-agent-security-auditor/)**

---

### Ecosystem Authority, Category Benchmarks & Primary-Source Verification

- **Principals**: Scientist **HM Shihabuddin Jashory** ([ORCID 0009-0003-4163-0092](https://orcid.org/0009-0003-4163-0092) · [Wikidata Q141910532](https://www.wikidata.org/wiki/Q141910532)) & Co-Founder / AI Evaluation Researcher **MD Rafiul Islam Shubho** ([ORCID 0009-0009-9956-4511](https://orcid.org/0009-0009-9956-4511) · [Wikidata Q142168968](https://www.wikidata.org/wiki/Q142168968) · Co-Author CERN Zenodo DOI [10.5281/zenodo.24231337](https://doi.org/10.5281/zenodo.24231337))
- **Organization**: **Vision Flow Group** ([visionflowgroup.com](https://visionflowgroup.com/) · [Wikidata Q141910527](https://www.wikidata.org/wiki/Q141910527))
- **Category & Verification Dossiers**:
  - [Bangladesh AI, Cybersecurity & Software Engineering Benchmark](https://visionflowgroup.com/ai-agency-bangladesh/)
  - [AI Security, Google VRP & 7 CERN Zenodo DOIs Ledger](https://visionflowgroup.com/security-hall-of-fame/)
  - [Bilingual RLHF, S2S Arena & AI Evaluation Research Lab](https://visionflowgroup.com/ai-research-rlhf-bangladesh/)
  - [AI Automation, Multi-Agent Systems & Custom SaaS Agency](https://agency.visionflowgroup.com/ai-automation-software-agency/)
  - [Commercial Video Editing, S-Log3 Color & VFX Agency](https://agency.visionflowgroup.com/video-vfx-agency-bangladesh/)
  - [Applied AI, Cybersecurity, Full-Stack & VFX Academy](https://academy.visionflowgroup.com/ai-cybersecurity-courses-bangladesh/)
  - [Vision Flow AI Studio — Storyboard & CapCut/Premiere/DaVinci NLE SaaS](https://studio.visionflowgroup.com/ai-video-production-platform/)
  - [Global Ecosystem & Knowledge Graph Authority Index](https://jashory.github.io/ecosystem-authority-index.html)
