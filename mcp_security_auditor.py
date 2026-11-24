#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Agent & MCP Security Auditor (v2.2.0 — CLI, GitHub Action & Stdio MCP Server)
Author: HM Shihabuddin Jashory (Shihab) — Vision Flow Group (https://visionflowgroup.com)
License: MIT

Static pre-audit scanner (zero external runtime dependencies) combining:
- Python `ast` inspection for `.py` files (shell=True, os.system/popen, eval/exec,
  unsafe pickle/yaml deserialization, and uncontained file-path sinks in tool functions)
- Pattern and JSON/schema heuristics across `.ts/.tsx/.js/.mjs/.cjs/.py/.json/.rules/.md`
- Automatic secret-value redaction in output/SARIF snippets by default
- Stdio JSON-RPC 2.0 MCP server (`--mcp`) exposing `scan_path` and `list_security_rules`
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

VERSION = "2.4.1"

SECRET_REDACT_PATTERNS = [
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "ghp_[REDACTED]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "github_pat_[REDACTED]"),
    (re.compile(r"sk-(?:proj-|ant-|live_|test_)?[A-Za-z0-9_-]{20,}"), "sk-[REDACTED]"),
    (re.compile(r"hf_[A-Za-z0-9]{20,}"), "hf_[REDACTED]"),
    (re.compile(r"AIza[0-9A-Za-z_-]{30,}"), "AIza[REDACTED]"),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "AKIA[REDACTED]"),
    (re.compile(r"ATATT3xFfGF0[A-Za-z0-9_=-]{20,}"), "ATATT[REDACTED]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{16,}"), "xox[REDACTED]"),
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
            r"(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)"
        ),
        "-----BEGIN PRIVATE KEY----- [REDACTED]",
    ),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-~+/]+=*"), r"\1[REDACTED]"),
]

RULE_METADATA: Dict[str, Dict[str, str]] = {
    "AGENT_ENV_SECRET_PERSISTENCE": {
        "severity": "HIGH",
        "cwe": "CWE-312",
        "title": "Merged Settings / Resolved ${ENV_VAR} Written Back to Disk",
        "description": (
            "Reads resolved `settings.merged` (where ${ENV_VAR} secrets and user-scope hooks "
            "are already expanded) and passes it to `setValue()`, persisting plaintext secrets."
        ),
        "remediation": "Read scoped unexpanded settings instead of `settings.merged` before writing.",
    },
    "AGENT_CROSS_SCOPE_HOOK_LEAK": {
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "title": "Global User Hooks Copied Into Workspace Scope Without Isolation",
        "description": "Copies user-global hook definitions into shared workspace configuration files.",
        "remediation": "Isolate user-level hooks from repository-committed workspace settings.",
    },
    "MCP_SHELL_COMMAND_INJECTION": {
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "title": "Subprocess / Child Process Shell Execution Sink",
        "description": "Executes tool or agent inputs through a system shell (`shell=True`, `os.system`, or template `exec`).",
        "remediation": "Pass argument arrays with `shell=False` or `execFile`/`spawn` without shell interpolation.",
    },
    "MCP_PATH_TRAVERSAL_UNCHECKED": {
        "severity": "HIGH",
        "cwe": "CWE-22",
        "title": "Unchecked File Path Sink in Tool Handler Without Canonical Root Check",
        "description": "Opens or writes a caller-supplied path inside a tool handler without `realpath`/`resolve` containment.",
        "remediation": "Canonicalize paths with `os.path.realpath` / `Path.resolve()` and verify `os.path.commonpath` against an allowed root.",
    },
    "MCP_SSRF_UNVALIDATED_FETCH": {
        "severity": "HIGH",
        "cwe": "CWE-918",
        "title": "Potential Unvalidated URL Fetch (SSRF Surface)",
        "description": "Fetches a variable URL without visible loopback/RFC1918/link-local metadata IP validation.",
        "remediation": "Validate scheme/host and block private, loopback, and 169.254.169.254 metadata addresses after DNS resolution.",
    },
    "MCP_UNSAFE_DESERIALIZATION": {
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "title": "Unsafe Code Evaluation or Deserialization Sink",
        "description": "Uses `eval()`, `exec()`, `pickle.loads()`, or `yaml.load()` without `SafeLoader`.",
        "remediation": "Use `json.loads()` or `yaml.safe_load()` and avoid dynamic code evaluation on untrusted data.",
    },
    "MCP_TOOL_SCHEMA_UNCONSTRAINED": {
        "severity": "MEDIUM",
        "cwe": "CWE-20",
        "title": "MCP Tool Input Schema Missing Object Property Constraints",
        "description": "Defines an MCP tool `inputSchema` object without `additionalProperties: false`, permitting unexpected fields.",
        "remediation": "Set `additionalProperties: false` and constrain sensitive path/URL/command parameters in `inputSchema`.",
    },
    "MCP_PROMPT_INJECTION_SURFACE": {
        "severity": "HIGH",
        "cwe": "CWE-74",
        "title": "Hidden Unicode Control or Instruction-Override Marker in Skill/Tool Metadata",
        "description": "Contains bidirectional/zero-width Unicode characters or covert instruction-override phrasing in skill or tool text.",
        "remediation": "Strip invisible control characters and audit skill/tool descriptions as untrusted prompt inputs.",
    },
    "FIREBASE_OPEN_DATABASE_RULES": {
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "title": "Public Unauthenticated Read/Write in Firebase RTDB Rules",
        "description": "Firebase Realtime Database rules grant `.read: true` or `.write: true` without authentication.",
        "remediation": "Restrict `.read` and `.write` to authenticated principals (`auth != null && auth.uid === $uid`).",
    },
    "FIRESTORE_WILDCARD_OPEN_RULES": {
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "title": "Public Unauthenticated Access in Firestore Security Rules",
        "description": "Firestore Security Rules contain `allow ...: if true;`, exposing documents publicly.",
        "remediation": "Require `request.auth != null` and document-owner or role checks.",
    },
    "HARDCODED_SECRET_TOKEN": {
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "title": "Hardcoded API Token or Private Key in Source / HTML",
        "description": "Contains a hardcoded API token (GitHub PAT, OpenAI/Anthropic/Google/Firebase/HuggingFace/AWS/Atlassian/Slack key) or PEM private key across source or HTML files.",
        "remediation": "Load secrets from environment variables or a secret manager, or run `mcp-security-auditor --fix` to redact exposed credentials before git push.",
    },
    "PRIVATE_SPA_PUBLIC_REPO_LEAK": {
        "severity": "CRITICAL",
        "cwe": "CWE-200",
        "title": "Private SPA Bundle / _BUILTIN_FB Config Leaked Into Public Pages Artifact",
        "description": "Contains internal SPA markers (`_BUILTIN_FB` or `site/admin-engine.js`) inside an HTML file intended for a public static or GitHub Pages repository.",
        "remediation": "Keep the public Pages root `index.html` as a clean static redirect/landing page and never overwrite it from the private SPA source repository.",
    },
    "INSECURE_CORS_WILDCARD_CREDENTIALS": {
        "severity": "MEDIUM",
        "cwe": "CWE-942",
        "title": "Wildcard CORS Origin Combined With Credentials",
        "description": "Configures wildcard `Access-Control-Allow-Origin: *` alongside `Access-Control-Allow-Credentials: true`.",
        "remediation": "Validate explicit trusted origins instead of `*` when credentials are enabled.",
    },
}

REGEX_RULES = [
    (
        "AGENT_ENV_SECRET_PERSISTENCE",
        {".ts", ".tsx", ".js", ".mjs", ".cjs", ".py"},
        re.compile(r"settings\.merged[\s\S]{0,260}?\.setValue\s*\(", re.MULTILINE),
    ),
    (
        "AGENT_CROSS_SCOPE_HOOK_LEAK",
        {".ts", ".tsx", ".js", ".mjs", ".cjs", ".py"},
        re.compile(r"UserSettings[\s\S]{0,200}?hooks[\s\S]{0,200}?Workspace", re.MULTILINE),
    ),
    (
        "MCP_SHELL_COMMAND_INJECTION",
        {".ts", ".tsx", ".js", ".mjs", ".cjs"},
        re.compile(r"(?:child_process\.)?(?:exec|execSync)\s*\(\s*`[^`]*\$\{"),
    ),
    (
        "MCP_PATH_TRAVERSAL_UNCHECKED",
        {".ts", ".tsx", ".js", ".mjs", ".cjs"},
        re.compile(
            r"""fs\.(?:promises\.)?(?:readFile|readFileSync|writeFile|writeFileSync)\s*\(\s*(?!["'`])[a-zA-Z0-9_.\[\]]+"""
        ),
    ),
    (
        "MCP_SSRF_UNVALIDATED_FETCH",
        {".ts", ".tsx", ".js", ".mjs", ".cjs", ".py"},
        re.compile(
            r"(?:requests\.(?:get|post)|httpx\.(?:get|post)|axios\.(?:get|post)|urllib\.request\.urlopen)\s*\(\s*[a-zA-Z0-9_.]*url"
        ),
    ),
    (
        "MCP_UNSAFE_DESERIALIZATION",
        {".ts", ".tsx", ".js", ".mjs", ".cjs"},
        re.compile(r"""(?:\beval\s*\(\s*(?!["'`])[a-zA-Z0-9_.]+|new\s+Function\s*\()"""),
    ),
    (
        "MCP_PROMPT_INJECTION_SURFACE",
        {".md", ".json"},
        re.compile(
            r"(?:[\u200b\u200c\u200d\u202a-\u202e\u2066-\u2069]|"
            r"ignore\s+(?:all\s+)?previous\s+instructions|"
            r"<important>[\s\S]{0,160}?(?:exfiltrate|curl\s+|~/.ssh|env\b))",
            re.IGNORECASE,
        ),
    ),
    (
        "FIREBASE_OPEN_DATABASE_RULES",
        {".json", ".rules"},
        re.compile(r'"\.(?:read|write)"\s*:\s*(?:true|"true")'),
    ),
    (
        "FIRESTORE_WILDCARD_OPEN_RULES",
        {".rules"},
        re.compile(r"allow\s+(?:read|write|create|update|delete)[,\s\w]*:\s*if\s+true\s*;"),
    ),
    (
        "HARDCODED_SECRET_TOKEN",
        {".ts", ".tsx", ".js", ".mjs", ".cjs", ".py", ".json", ".yml", ".yaml", ".env", ".html", ".htm", ".xml", ".svg", ".toml"},
        re.compile(
            r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|"
            r"sk-(?:proj-|ant-|live_|test_)?[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|"
            r"AIza[0-9A-Za-z_-]{33,40}|(?:AKIA|ASIA)[0-9A-Z]{16}|"
            r"ATATT3xFfGF0[A-Za-z0-9_=-]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|"
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
        ),
    ),
    (
        "PRIVATE_SPA_PUBLIC_REPO_LEAK",
        {".html", ".htm"},
        re.compile(r"(?:_BUILTIN_FB\s*=|site/admin-engine\.js)"),
    ),
    (
        "INSECURE_CORS_WILDCARD_CREDENTIALS",
        {".ts", ".tsx", ".js", ".mjs", ".cjs", ".py", ".json", ".html", ".htm"},
        re.compile(
            r"""Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*["'][\s\S]{0,180}?"""
            r"""Access-Control-Allow-Credentials["']?\s*[:=]\s*(?:true|["']true["'])""",
            re.IGNORECASE,
        ),
    ),
]

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SCANNABLE_EXTS = {".ts", ".tsx", ".js", ".cjs", ".mjs", ".py", ".json", ".rules", ".md", ".yml", ".yaml", ".env", ".html", ".htm", ".xml", ".svg", ".toml"}


def redact_snippet(text: str, include_raw_secrets: bool = False) -> str:
    cleaned = text[:180].strip()
    if include_raw_secrets:
        return cleaned
    for pat, repl in SECRET_REDACT_PATTERNS:
        cleaned = pat.sub(repl, cleaned)
    return cleaned


def _make_finding(
    rule_id: str,
    fpath: str,
    line_no: int,
    snippet: str,
    engine: str,
    include_raw_secrets: bool = False,
) -> Dict[str, Any]:
    meta = RULE_METADATA[rule_id]
    return {
        "rule_id": rule_id,
        "engine": engine,
        "severity": meta["severity"],
        "cwe": meta["cwe"],
        "title": meta["title"],
        "file": fpath,
        "line": line_no,
        "snippet": redact_snippet(snippet, include_raw_secrets=include_raw_secrets),
        "description": meta["description"],
        "remediation": meta["remediation"],
    }


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        cur = func.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


class PythonSecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, fpath: str, lines: List[str], include_raw_secrets: bool = False) -> None:
        self.fpath = fpath
        self.lines = lines
        self.include_raw_secrets = include_raw_secrets
        self.findings: List[Dict[str, Any]] = []
        self._in_tool_fn = False
        self._fn_has_containment = False
        self._fn_params: set[str] = set()

    def _line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _is_tool_function(self, node: ast.AST) -> bool:
        decos = getattr(node, "decorator_list", [])
        for d in decos:
            src = ast.unparse(d) if hasattr(ast, "unparse") else ""
            if any(tok in src.lower() for tok in ("tool", "mcp", "route", "command")):
                return True
        name = getattr(node, "name", "")
        return name.startswith(("tool_", "handle_tool", "mcp_"))

    def _visit_fn(self, node: ast.AST) -> None:
        prev_tool = self._in_tool_fn
        prev_contain = self._fn_has_containment
        prev_params = self._fn_params

        args_obj = getattr(node, "args", None)
        params = (
            {a.arg for a in (getattr(args_obj, "args", []) + getattr(args_obj, "kwonlyargs", []))}
            if args_obj
            else set()
        )
        body_dump = ast.unparse(node) if hasattr(ast, "unparse") else ""
        has_containment = any(
            guard in body_dump for guard in ("realpath", ".resolve(", "commonpath", "is_relative_to")
        )

        self._in_tool_fn = prev_tool or self._is_tool_function(node)
        self._fn_has_containment = has_containment
        self._fn_params = params
        self.generic_visit(node)

        self._in_tool_fn = prev_tool
        self._fn_has_containment = prev_contain
        self._fn_params = prev_params

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_fn(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_fn(node)

    def visit_Call(self, node: ast.Call) -> None:
        cname = _call_name(node)
        lineno = getattr(node, "lineno", 1)
        snippet = self._line_text(lineno)

        if cname in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.check_call",
        }:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        _make_finding(
                            "MCP_SHELL_COMMAND_INJECTION",
                            self.fpath,
                            lineno,
                            snippet,
                            "python-ast",
                            self.include_raw_secrets,
                        )
                    )
        elif cname in {"os.system", "os.popen"}:
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append(
                    _make_finding(
                        "MCP_SHELL_COMMAND_INJECTION",
                        self.fpath,
                        lineno,
                        snippet,
                        "python-ast",
                        self.include_raw_secrets,
                    )
                )
        elif cname in {"eval", "exec", "pickle.loads", "marshal.loads"}:
            if not (node.args and isinstance(node.args[0], ast.Constant)):
                self.findings.append(
                    _make_finding(
                        "MCP_UNSAFE_DESERIALIZATION",
                        self.fpath,
                        lineno,
                        snippet,
                        "python-ast",
                        self.include_raw_secrets,
                    )
                )
        elif cname == "yaml.load":
            safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader_src = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                    if "SafeLoader" in loader_src:
                        safe_loader = True
            if not safe_loader:
                self.findings.append(
                    _make_finding(
                        "MCP_UNSAFE_DESERIALIZATION",
                        self.fpath,
                        lineno,
                        snippet,
                        "python-ast",
                        self.include_raw_secrets,
                    )
                )
        elif self._in_tool_fn and not self._fn_has_containment:
            if cname == "open" and node.args and not isinstance(node.args[0], ast.Constant):
                arg_src = ast.unparse(node.args[0]) if hasattr(ast, "unparse") else ""
                if any(p in arg_src for p in self._fn_params):
                    self.findings.append(
                        _make_finding(
                            "MCP_PATH_TRAVERSAL_UNCHECKED",
                            self.fpath,
                            lineno,
                            snippet,
                            "python-ast",
                            self.include_raw_secrets,
                        )
                    )
            elif cname.endswith((".read_text", ".read_bytes", ".write_text", ".write_bytes")):
                base_src = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
                if any(p in base_src for p in self._fn_params):
                    self.findings.append(
                        _make_finding(
                            "MCP_PATH_TRAVERSAL_UNCHECKED",
                            self.fpath,
                            lineno,
                            snippet,
                            "python-ast",
                            self.include_raw_secrets,
                        )
                    )

        self.generic_visit(node)


def _scan_json_mcp_schemas(fpath: str, content: str, include_raw_secrets: bool = False) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    try:
        data = json.loads(content)
    except Exception:
        return results
    if not isinstance(data, dict):
        return results
    tools = data.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            schema = tool.get("inputSchema")
            if isinstance(schema, dict) and schema.get("type") == "object":
                if schema.get("additionalProperties") is not False:
                    tname = str(tool.get("name", "unnamed_tool"))
                    results.append(
                        _make_finding(
                            "MCP_TOOL_SCHEMA_UNCONSTRAINED",
                            fpath,
                            1,
                            f'tool "{tname}" inputSchema missing additionalProperties: false',
                            "json-schema",
                            include_raw_secrets,
                        )
                    )
    return results


def scan_path(target_path: str, include_raw_secrets: bool = False) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    scanned_files = 0
    skip_dirs = {"node_modules", ".git", "__pycache__", ".next", "dist", "build", "venv", ".venv"}

    file_candidates: List[str] = []
    if os.path.isfile(target_path):
        file_candidates.append(target_path)
    else:
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                _, ext = os.path.splitext(fname)
                if ext.lower() in SCANNABLE_EXTS or fname in {".env"}:
                    file_candidates.append(os.path.join(root, fname))

    seen_keys: set[tuple[str, str, int]] = set()

    for fpath in file_candidates:
        scanned_files += 1
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue

        _, ext = os.path.splitext(fpath)
        ext = ext.lower()
        lines = content.splitlines()

        if ext == ".py":
            try:
                tree = ast.parse(content, filename=fpath)
                visitor = PythonSecurityASTVisitor(fpath, lines, include_raw_secrets=include_raw_secrets)
                visitor.visit(tree)
                for item in visitor.findings:
                    key = (item["rule_id"], item["file"], item["line"])
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append(item)
            except SyntaxError:
                pass

        if ext == ".json":
            for item in _scan_json_mcp_schemas(fpath, content, include_raw_secrets=include_raw_secrets):
                key = (item["rule_id"], item["file"], item["line"])
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(item)

        for rule_id, allowed_exts, rx in REGEX_RULES:
            if ext not in allowed_exts and os.path.basename(fpath) not in allowed_exts:
                continue
            for m in rx.finditer(content):
                line_no = content[: m.start()].count("\n") + 1
                key = (rule_id, fpath, line_no)
                if key in seen_keys:
                    continue
                if rule_id == "MCP_PATH_TRAVERSAL_UNCHECKED":
                    window = content[max(0, m.start() - 250) : min(len(content), m.end() + 250)]
                    if "realpath" in window or "path.resolve" in window:
                        continue
                seen_keys.add(key)
                findings.append(
                    _make_finding(rule_id, fpath, line_no, m.group(0), "regex-heuristic", include_raw_secrets)
                )

    return {
        "scanner_version": VERSION,
        "target_dir": target_path,
        "scanned_files": scanned_files,
        "secrets_redacted": not include_raw_secrets,
        "total_findings": len(findings),
        "findings": findings,
    }


def scan_directory(target_dir: str) -> Dict[str, Any]:
    return scan_path(target_dir, include_raw_secrets=False)


def _resolve_contained_target(target_path: str, allow_outside_cwd: bool = False) -> str:
    """Resolve canonical realpath and enforce workspace containment unless explicitly overridden on local CLI."""
    real_target = os.path.realpath(target_path)
    if not allow_outside_cwd:
        real_cwd = os.path.realpath(os.getcwd())
        try:
            common = os.path.commonpath([real_cwd, real_target])
        except ValueError as exc:
            raise PermissionError(f"Refusing cross-drive target outside workspace '{real_cwd}': {real_target}") from exc
        if common != real_cwd:
            raise PermissionError(
                f"Refusing remediation outside current workspace '{real_cwd}': {real_target} "
                "(pass --allow-outside-cwd on the local CLI if intentional)."
            )
    return real_target


def auto_remediate_path(
    target_path: str,
    dry_run: bool = True,
    create_backup: bool = True,
    allow_outside_cwd: bool = False,
) -> Dict[str, Any]:
    """Preview (default dry_run=True) or apply in-place secret-token redaction within a canonical workspace boundary."""
    real_target = _resolve_contained_target(target_path, allow_outside_cwd=allow_outside_cwd)
    report = scan_path(real_target, include_raw_secrets=False)
    files_to_fix: Dict[str, set[str]] = {}
    for f in report["findings"]:
        if f["rule_id"] == "HARDCODED_SECRET_TOKEN":
            files_to_fix.setdefault(f["file"], set()).add(f["rule_id"])

    fixed_files: List[Dict[str, Any]] = []
    for fpath in sorted(files_to_fix.keys()):
        real_f = os.path.realpath(fpath)
        if os.path.islink(fpath):
            continue
        if not allow_outside_cwd:
            try:
                if os.path.commonpath([real_target, real_f]) != real_target:
                    continue
            except ValueError:
                continue
        try:
            with open(real_f, "r", encoding="utf-8", errors="ignore") as fp:
                raw = fp.read()
        except OSError:
            continue

        healed = raw
        for pat, repl in SECRET_REDACT_PATTERNS:
            healed = pat.sub(repl, healed)
        if healed != raw:
            if dry_run:
                fixed_files.append(
                    {
                        "file": real_f,
                        "action": "would_redact_hardcoded_secrets_in_place",
                        "dry_run": True,
                        "backup_file": f"{real_f}.bak" if create_backup else None,
                    }
                )
            else:
                backup_path = None
                if create_backup:
                    backup_path = f"{real_f}.bak"
                    with open(backup_path, "w", encoding="utf-8") as bfp:
                        bfp.write(raw)
                with open(real_f, "w", encoding="utf-8") as fp:
                    fp.write(healed)
                fixed_files.append(
                    {
                        "file": real_f,
                        "action": "redacted_hardcoded_secrets_in_place",
                        "dry_run": False,
                        "backup_file": backup_path,
                    }
                )

    after_report = report if dry_run else scan_path(real_target, include_raw_secrets=False)
    return {
        "scanner_version": VERSION,
        "target_dir": real_target,
        "dry_run": dry_run,
        "files_remediated": 0 if dry_run else len(fixed_files),
        "files_previewed": len(fixed_files) if dry_run else 0,
        "remediation_actions": fixed_files,
        "before_findings": report["total_findings"],
        "after_findings": after_report["total_findings"],
    }


def format_markdown(report: Dict[str, Any]) -> str:
    out = [
        f"# MCP & Agent Security Audit Report (v{report['scanner_version']})",
        f"- **Target:** `{report['target_dir']}`",
        f"- **Scanned Files:** {report['scanned_files']}",
        f"- **Total Findings:** {report['total_findings']} (Secrets redacted: `{report['secrets_redacted']}`)",
        "",
    ]
    for idx, f in enumerate(report["findings"], 1):
        out.append(
            f"### {idx}. [{f['severity']}] `{f['rule_id']}` ({f['cwe']}) — {f['title']}\n"
            f"- **Location:** `{f['file']}:{f['line']}` (`{f['engine']}`)\n"
            f"- **Snippet:** `{f['snippet']}`\n"
            f"- **Remediation:** {f['remediation']}\n"
        )
    return "\n".join(out)


def format_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    rules_sarif = []
    for rid, meta in RULE_METADATA.items():
        rules_sarif.append(
            {
                "id": rid,
                "name": meta["title"],
                "shortDescription": {"text": meta["title"]},
                "fullDescription": {"text": meta["description"]},
                "help": {"text": meta["remediation"]},
                "properties": {"tags": ["security", meta["cwe"]], "security-severity": meta["severity"]},
            }
        )
    results_sarif = []
    level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    for f in report["findings"]:
        results_sarif.append(
            {
                "ruleId": f["rule_id"],
                "level": level_map.get(f["severity"], "warning"),
                "message": {"text": f"{f['title']} ({f['cwe']}): {f['snippet']}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"].replace("\\", "/")},
                            "region": {"startLine": max(1, int(f["line"]))},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-agent-security-auditor",
                        "version": VERSION,
                        "informationUri": "https://github.com/jashory/mcp-agent-security-auditor",
                        "rules": rules_sarif,
                    }
                },
                "results": results_sarif,
            }
        ],
    }


def run_mcp_server() -> int:
    """Stdio JSON-RPC 2.0 Model Context Protocol (MCP) server."""
    tools_spec = [
        {
            "name": "scan_path",
            "description": (
                "Run static Python AST, MCP schema, prompt-injection, and Firebase rules "
                "security scan on a local directory or file (secrets redacted by default)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Local directory or file path to audit."},
                    "format": {"type": "string", "enum": ["json", "markdown", "sarif"], "default": "json"},
                },
                "required": ["target"],
                "additionalProperties": False,
            },
        },
        {
            "name": "list_security_rules",
            "description": "List all 13 CWE-mapped static security rules implemented by mcp-agent-security-auditor.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "name": "remediate_path",
            "description": (
                "Preview (default dry_run=true) or apply (apply=true, creating .bak backups) in-place "
                "redaction of matched secret tokens strictly within the current workspace directory."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Workspace-contained directory or file path."},
                    "apply": {
                        "type": "boolean",
                        "default": False,
                        "description": "Set true to write redacted files on disk (creates .bak backups). Defaults to false (read-only preview).",
                    },
                    "backup": {
                        "type": "boolean",
                        "default": True,
                        "description": "Create a <file>.bak backup before modifying any file when apply=true.",
                    },
                },
                "required": ["target"],
                "additionalProperties": False,
            },
        },
    ]

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        msg_id = msg.get("id")
        if msg_id is None:
            continue

        if method == "initialize":
            req_proto = str((msg.get("params") or {}).get("protocolVersion") or "2024-11-05")
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": req_proto,
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                    "serverInfo": {"name": "mcp-agent-security-auditor", "version": VERSION},
                },
            }
        elif method == "ping":
            resp = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
        elif method == "resources/list":
            resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}
        elif method == "prompts/list":
            resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tools_spec}}
        elif method == "tools/call":
            params = msg.get("params") or {}
            tname = params.get("name")
            targs = params.get("arguments") or {}
            if tname == "list_security_rules":
                payload = json.dumps(RULE_METADATA, indent=2)
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": payload}]}}
            elif tname == "scan_path":
                target = str(targs.get("target") or ".")
                fmt = str(targs.get("format") or "json")
                report = scan_path(target, include_raw_secrets=False)
                if fmt == "markdown":
                    text_out = format_markdown(report)
                elif fmt == "sarif":
                    text_out = json.dumps(format_sarif(report), indent=2)
                else:
                    text_out = json.dumps(report, indent=2)
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": text_out}]}}
            elif tname == "remediate_path":
                target = str(targs.get("target") or ".")
                apply_changes = bool(targs.get("apply", False))
                make_backup = bool(targs.get("backup", True))
                try:
                    res_fix = auto_remediate_path(
                        target,
                        dry_run=not apply_changes,
                        create_backup=make_backup,
                        allow_outside_cwd=False,
                    )
                    resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {"content": [{"type": "text", "text": json.dumps(res_fix, indent=2)}]},
                    }
                except PermissionError as exc:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32602, "message": str(exc)},
                    }
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tname}"},
                }
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-security-auditor",
        description="Static Python AST + heuristic pre-audit scanner and stdio MCP server for MCP tools, agent hooks, and Firebase rules.",
    )
    parser.add_argument("positional_target", nargs="?", default=None, help="Directory or file path to scan")
    parser.add_argument(
        "--target",
        "-t",
        dest="flag_target",
        default=None,
        help="Directory or file path to scan (GitHub Action & CLI compatible)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "markdown", "sarif"],
        default="json",
        help="Output report format (default: json)",
    )
    parser.add_argument("--output", "-o", default=None, help="Optional file path to write report output")
    parser.add_argument("--ci", action="store_true", help="Exit with code 1 if HIGH or CRITICAL findings are detected")
    parser.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Exit with code 1 if findings at or above this severity exist",
    )
    parser.add_argument(
        "--include-raw-secrets",
        action="store_true",
        help="Disable default secret-value redaction in output snippets (use with caution)",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Redact matched hardcoded secret tokens in place within workspace (creates <file>.bak backup unless --no-backup is passed)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview files that --fix would redact without modifying any files on disk",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip creating <file>.bak backups when running --fix",
    )
    parser.add_argument(
        "--allow-outside-cwd",
        action="store_true",
        help="Explicitly allow --fix on a target path outside the current working directory",
    )
    parser.add_argument(
        "--pre-push",
        action="store_true",
        help="Run in Git pre-commit/pre-push guard mode (exits 1 if HIGH or CRITICAL findings are detected)",
    )
    parser.add_argument("--mcp", action="store_true", help="Run as a stdio JSON-RPC 2.0 MCP server")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.mcp:
        return run_mcp_server()

    target = args.flag_target or args.positional_target or "."
    if args.fix or args.dry_run:
        fix_report = auto_remediate_path(
            target,
            dry_run=bool(args.dry_run),
            create_backup=not bool(args.no_backup),
            allow_outside_cwd=bool(args.allow_outside_cwd),
        )
        print(json.dumps(fix_report, indent=2, ensure_ascii=False))
        return 0

    report = scan_path(target, include_raw_secrets=args.include_raw_secrets)

    if args.format == "markdown":
        rendered = format_markdown(report)
    elif args.format == "sarif":
        rendered = json.dumps(format_sarif(report), indent=2, ensure_ascii=False)
    else:
        rendered = json.dumps(report, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out_f:
            out_f.write(rendered + "\n")
    else:
        print(rendered)

    threshold = args.fail_on or ("HIGH" if (args.ci or args.pre_push) else None)
    if threshold:
        min_rank = SEVERITY_ORDER[threshold]
        blocking = [f for f in report["findings"] if SEVERITY_ORDER.get(f["severity"], 0) >= min_rank]
        if blocking:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
