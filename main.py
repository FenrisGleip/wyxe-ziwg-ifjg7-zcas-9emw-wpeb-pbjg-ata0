# CIPHER v5.0 — Multi-Agent Red Team Threat Intelligence Pipeline
#
# Architecture:
#   [Fetcher] → [Triage] → [Recon] → [Analyst] → [Exploit] → [Detection]
#              → [Editor] → [Critic loop ×N] → [Atomic RT yaml] → [KG update]
#
# Free-tier AI stack (all optional, pipeline auto-falls-back):
#   - Cerebras llama-3.3-70b  : primary report generator (1M tok/day)
#   - OpenRouter deepseek-v3.1: exploit specialist (50 req/day free)
#   - Groq llama-3.3-70b      : triage & fast steps (TPD 100K)
#   - Gemini 2.5 Flash        : critic (250 RPD)
#
# Data enrichment:
#   - NVD API, CISA KEV, MITRE ATT&CK, GitHub code search,
#     Tavily deep search, VirusTotal, AlienVault OTX
# ============================================================================

import os, json, re, time, hashlib, urllib.request, urllib.parse, urllib.error
import xml.etree.ElementTree as ET
from html import unescape
from datetime import datetime, timezone, timedelta
from pathlib import Path

JST = timezone(timedelta(hours=9))
def now_jst(): return datetime.now(JST)

# ─── Client Initialization ──────────────────────────────────────────────────
print("=" * 60)
print("  CIPHER v5.0 — Multi-Agent Red Team Intel")
print("=" * 60)

from groq import Groq
GROQ_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_KEY:
    raise RuntimeError("GROQ_API_KEY is required")
groq_client = Groq(api_key=GROQ_KEY)
print("[INIT] ✓ Groq (triage)")

cerebras_client = None
try:
    from cerebras.cloud.sdk import Cerebras
    if os.getenv("CEREBRAS_API_KEY"):
        cerebras_client = Cerebras(api_key=os.getenv("CEREBRAS_API_KEY"))
        print("[INIT] ✓ Cerebras (primary generator)")
    else:
        print("[INIT] ⚠ CEREBRAS_API_KEY missing — get free key at cloud.cerebras.ai")
except ImportError:
    print("[INIT] ⚠ cerebras-cloud-sdk not installed")

openrouter_client = None
try:
    from openai import OpenAI
    if os.getenv("OPENROUTER_API_KEY"):
        openrouter_client = OpenAI(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
        )
        print("[INIT] ✓ OpenRouter (exploit specialist)")
    else:
        print("[INIT] ⚠ OPENROUTER_API_KEY missing — get free key at openrouter.ai")
except ImportError:
    print("[INIT] ⚠ openai package not installed")

gemini_model = None
try:
    import google.generativeai as genai
    if os.getenv("GEMINI_API_KEY"):
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        gemini_model = genai.GenerativeModel("gemini-2.5-flash")
        print("[INIT] ✓ Gemini (critic)")
except ImportError:
    pass

tavily_client = None
try:
    from tavily import TavilyClient
    if os.getenv("TAVILY_API_KEY"):
        tavily_client = TavilyClient(api_key=os.getenv("TAVILY_API_KEY"))
        print("[INIT] ✓ Tavily")
except ImportError:
    pass

VT_KEY       = os.getenv("VIRUSTOTAL_API_KEY")
OTX_KEY      = os.getenv("OTX_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
USER_AGENT   = "Mozilla/5.0 (compatible; CIPHER-Intel/5.0)"

if VT_KEY:  print("[INIT] ✓ VirusTotal (IoC enrichment)")
if OTX_KEY: print("[INIT] ✓ AlienVault OTX (IoC enrichment)")

# ─── Config ─────────────────────────────────────────────────────────────────
MASTER_DATA       = "all_articles.json"
KG_DATA           = "knowledge_graph.json"
RUN_LOG_FILE      = "run_log.json"
ATOMIC_DIR        = "atomic_tests"
MAX_DB_ENTRIES    = 300
MIN_REPORT_LEN    = 900
MIN_SOURCE_LEN    = 400
MAX_ITEMS_PER_FEED = 5
MAX_PER_CATEGORY  = 6
SLEEP_BETWEEN_REQ = 1.0
CRITIC_THRESHOLD  = 7      # /10 required to accept report
MAX_CRITIC_LOOPS  = 2      # max revision rounds per article

Path(ATOMIC_DIR).mkdir(exist_ok=True)

# ─── RSS Feeds & Tavily Queries ─────────────────────────────────────────────
RSS_FEEDS = {
    "MALWARE": [
        "https://securelist.com/feed/",
        "https://cybersecuritynews.com/feed/",
        "https://blog.malwarebytes.com/feed/",
        "https://isc.sans.edu/rssfeed_full.xml",
        "https://www.helpnetsecurity.com/feed/",
        "https://research.checkpoint.com/feed/",
    ],
    "INITIAL": [
        "https://securityaffairs.com/feed",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://www.zerodayinitiative.com/rss/published/",
        "https://seclists.org/rss/fulldisclosure.rss",
    ],
    "POST_EXP": [
        "https://www.elastic.co/security-labs/rss/feed.xml",
        "https://redcanary.com/feed/",
        "https://specterops.io/blog/feed/",
        "https://bishopfox.com/blog/feed",
    ],
    "AI_SEC": [
        "https://blog.trailofbits.com/feed/",
        "https://simonwillison.net/atom/everything/",
        "https://embracethered.com/blog/index.xml",
    ],
}

TAVILY_QUERIES = {
    "MALWARE":  ["new malware loader shellcode EDR bypass technical analysis"],
    "INITIAL":  ["zero-day PoC exploit published CVE proof of concept GitHub"],
    "POST_EXP": ["privilege escalation technique Active Directory Kerberoasting"],
    "AI_SEC":   ["LLM agent jailbreak prompt injection new attack technique"],
}

# ─── Category Context (English — better LLM instruction following) ──────────
CATEGORY_CONTEXT = {
    "MALWARE": """CATEGORY FOCUS: Malware analysis
Key details to extract and reconstruct:
- Loader internals: shellcode/PE decryption, mapping, execution (VirtualAllocEx, WriteProcessMemory, NtCreateThreadEx, etc.)
- Obfuscation: exact algorithm (XOR key, RC4, AES-CBC+IV), key material location
- C2 protocol: transport (HTTP/DNS/custom), beacon interval+jitter, encoding, URI patterns
- Persistence: registry key path, scheduled task XML, WMI subscription query
- EDR evasion: AMSI bypass, ETW patching, direct/indirect syscalls, unhooking, process injection target""",
    "INITIAL": """CATEGORY FOCUS: Initial access / vulnerability exploitation
Key details to extract and reconstruct:
- Root cause: exact vulnerable code path, parameter/header/field that triggers the bug
- Vulnerability class: buffer overflow offset, SQLi context, deserialization gadget chain, auth bypass
- Affected versions: exact version strings, patch commit reference, advisory URL
- Exploit trigger: HTTP method, endpoint path, required headers, auth state, payload format
- Bypass conditions: WAF evasion, auth prerequisites, race condition window""",
    "POST_EXP": """CATEGORY FOCUS: Post-exploitation / lateral movement
Key details to extract and reconstruct:
- Privilege escalation: misconfiguration (SeImpersonatePrivilege, weak service ACL, unquoted path, token abuse)
- Lateral movement: protocol (SMB/WinRM/DCOM), credential type, ports, auth context
- Credential dumping: LSASS access method (MiniDump, direct read, PPL bypass), SAM/NTDS extraction
- AD attack: Kerberoastable SPN, RBCD prerequisite, DCSync rights, ACL abuse
- Defense evasion: injection target, LOLBAS binary, AMSI/ETW bypass""",
    "AI_SEC": """CATEGORY FOCUS: AI/LLM attack
Key details to extract and reconstruct:
- Injection point: system prompt, tool description, RAG content, fine-tuning data, API, MCP component, agent memory
- Attack mechanism: context confusion, role override, indirect injection, training data poisoning, adversarial input
- Concrete payload: actual strings/templates/configs that trigger the behavior
- Impact: data exfiltration, jailbreak, agent hijack, SSRF via tool, model theft
- Bypass: how safety filters / guardrails are circumvented""",
}

# ============================================================================
# AGENT PROMPTS (all English for better instruction-following)
# Each agent produces strict JSON output.
# ============================================================================

# ─── Triage Agent ───────────────────────────────────────────────────────────
def prompt_triage(content: str, category: str) -> str:
    ctx = CATEGORY_CONTEXT.get(category, "")
    return f"""You are a senior red team operator triaging threat intel articles.
{ctx}

Score novelty 1-5:
  5 = new CVE / new technique / original research / new bypass
  4 = meaningful variant of known technique (new target/evasion/tool)
  3 = known technique with valuable applied detail
  2 = known technique re-explained, no new info
  1 = educational content, vendor marketing, no technical depth

Selection: what can attacker achieve? can a tester replicate in a lab?

EXCEPTIONS (accept even score 2):
- unpatched 0-day PoC published
- working exploit for new CVE
- in-the-wild (ITW) exploitation confirmed

Output ONLY JSON, no prose, no markdown fences:

Skip: {{"skip": true, "reason": "short reason in Japanese"}}

Accept: {{"skip": false, "score": <1-5>, "title_jp": "Japanese title ≤30 chars",
  "cve_ids": ["CVE-2024-XXXXX"], "poc_url": "GitHub URL or empty",
  "cvss_score": "numeric or empty", "mitre_ids": ["T1566.001"],
  "threat_actor": "APT name or empty", "malware_family": "family or empty",
  "summary_points": ["≤100 char point1", "point2", "point3"],
  "info_density": "high|medium|low",
  "research_keywords": ["english kw1", "kw2"]}}

SOURCE ARTICLE:
{content[:3500]}"""


# ─── Analyst Agent (technical mechanism) ────────────────────────────────────
def prompt_analyst(content: str, triage: dict, research_context: str,
                   related_articles: str) -> str:
    ctx = CATEGORY_CONTEXT.get(triage.get("category", ""), "")
    research_block = f"\n\n=== ADDITIONAL RESEARCH (NVD/Tavily/GitHub/OTX/VT) ===\n{research_context[:5000]}\n" if research_context else ""
    related_block = f"\n\n=== RELATED PRIOR ARTICLES (Self-RAG) ===\n{related_articles[:3000]}\n" if related_articles else ""
    return f"""You are a reverse engineer / vuln researcher writing the TECHNICAL MECHANISM
section of a red team report. Reader: a tester who will reproduce this tomorrow.

{ctx}
{research_block}
{related_block}

Write the following section in Japanese (tool names, CVE, API, commands stay English):

## 脆弱性・脅威の技術的メカニズム

Requirements:
- Explain WHY the attack works from an attacker perspective
- Include specific API calls, memory operations, protocol fields, code paths
- For CVE: vulnerable code path, trigger condition, patch diff if available
- For malware: loader → decryption → execution steps at implementation level
- Minimum 600 Japanese characters
- NO vague terms: "advanced", "sophisticated", "complex" are banned
- Tag each fact with [記事] / [NVD] / [Tavily] / [GitHub] / [推測]

Also output your assessment of what's MISSING from public info that a tester would need.

Output ONLY JSON:
{{"mechanism_md": "## 脆弱性・脅威の技術的メカニズム\\n...",
  "missing_info": ["what's unclear 1", "unclear 2"],
  "key_iocs_extracted": ["hash/ip/domain/uri found in sources"]}}

SOURCE ARTICLE:
{content[:5000]}"""


# ─── Exploit Agent (reproduction guide, uses DeepSeek — strong at code) ─────
def prompt_exploit(content: str, triage: dict, mechanism_md: str,
                   research_context: str) -> str:
    return f"""You are an offensive security engineer writing the REPRODUCTION GUIDE for
red team testers. Your output is used to replicate the attack in a lab tomorrow.

Previous mechanism analysis:
{mechanism_md[:3000]}

Additional research:
{research_context[:3000]}

Write in Japanese (tool/CVE/API/commands stay English). Output the following sections:

## 攻撃再現ガイド

### 前提条件・環境
- OS, network, account, privilege level
- Tools, services, external resources required
- Target's required configuration state

### 攻撃フロー
Break into numbered phases. Each step MUST have:
  **【操作】** exactly what to do (UI/CLI/config/code)
  **【目的】** why this step is needed tactically
  **【結果】** what happens / what is gained
  **【ソース】** [記事] / [NVD] / [Tavily] / [GitHub] / [推測]

### 実装・設定の詳細
Concrete values (CLSIDs, specific API calls, registry keys, OAuth params, filenames).
Use code blocks where natural:

```powershell
# actual working command
```

```python
# actual PoC snippet
```

## 🧪 ラボ再現環境 (Lab Setup)
Provide a minimal reproducible environment:
```dockerfile
# or Vagrantfile / terraform snippet that stands up a vulnerable lab
```

Also extract 1-3 Atomic Red Team style test cases (yaml format) that could be used
to execute this technique for purple team exercises.

Output ONLY JSON:
{{"reproduction_md": "## 攻撃再現ガイド\\n...",
  "lab_setup_md": "## 🧪 ラボ再現環境\\n...",
  "atomic_tests": [
    {{"name": "T1059.001 - Technique Name", "description": "...",
      "platform": "windows", "executor": "powershell",
      "command": "actual command", "cleanup": "cleanup command"}}
  ]}}

SOURCE ARTICLE:
{content[:4000]}"""


# ─── Detection Agent (Sigma/KQL/SPL queries) ────────────────────────────────
def prompt_detection(mechanism_md: str, reproduction_md: str, iocs: list) -> str:
    ioc_str = "\n".join(f"- {i}" for i in iocs[:20]) if iocs else "none extracted"
    return f"""You are a detection engineer. Based on the technical mechanism and
reproduction guide below, produce CONCRETE detection and defensive controls.

=== Mechanism ===
{mechanism_md[:2500]}

=== Reproduction ===
{reproduction_md[:2500]}

=== Known IoCs ===
{ioc_str}

Output in Japanese (product names, queries, keys stay English).

## 検知・防御策

### 防御策 (minimum 3 concrete items)
- "Enable X", "Disable Y", "Restrict Z" format ONLY
- Each item specifies WHICH setting WHERE

### 検知策
1. **検知ポイント**: log sources that catch this
   (EDR process events, Windows Event 4688, Sysmon ID X, NDR DNS, etc.)

2. **SIEMクエリ**: provide at least ONE WORKING query with REAL IoCs from the article.
   Choose the most appropriate format:

```sigma
# sigma rule
title: ...
detection:
  selection:
    ...
  condition: selection
```

OR

```kql
// Microsoft Sentinel / Defender KQL
DeviceProcessEvents
| where ...
```

OR

```spl
# Splunk SPL
index=* ...
```

3. **False positive considerations**: what legitimate activity might trigger this?

## IoC・痕跡情報
Structured list: Hashes / C2 domains / IPs / URIs / User-Agents / filenames / registry.
Write "記事中に記載なし" for categories with no data.

Output ONLY JSON:
{{"detection_md": "## 検知・防御策\\n...",
  "ioc_md": "## IoC・痕跡情報\\n...",
  "sigma_rule": "yaml text or empty"}}"""


# ─── Editor Agent (final synthesis) ─────────────────────────────────────────
def prompt_editor(triage: dict, mechanism_md: str, reproduction_md: str,
                  lab_setup_md: str, detection_md: str, ioc_md: str,
                  research_context: str) -> str:
    return f"""You are the lead editor combining specialist outputs into a final
red team intel report. Produce the complete report in Japanese markdown.

Assemble sections in this exact order:
1. ## 概要 (write this now: 1-2 sentence core + 3-5 bullet points + 🆕 新規性ポイント + attribution)
2. Technical mechanism (given below)
3. Reproduction guide (given below)
4. Lab setup (given below)
5. IoC section (given below)
6. Detection (given below)
7. ## MITRE ATT&CK マッピング (infer from content, pick accurate IDs with descriptions)
8. ## 🔍 情報ソースサマリ (list which facts came from which source)

Triage metadata: {json.dumps(triage, ensure_ascii=False)[:500]}

=== Mechanism ===
{mechanism_md[:3000]}
=== Reproduction ===
{reproduction_md[:3000]}
=== Lab Setup ===
{lab_setup_md[:1500]}
=== Detection ===
{detection_md[:2500]}
=== IoC ===
{ioc_md[:1500]}
=== Research context excerpt ===
{research_context[:1500]}

Write the 概要 section fresh, keeping it tight and information-dense:
- Opening: "〇〇が報告された。重要なのは 〜 という点である。"
- 3-5 technical bullets (what / how / why dangerous)
- **🆕 新規性・差異化ポイント:** (bold paragraph)
- Attribution block: APT / Malware / CVE / IoC (write 記載なし if unknown)

Output ONLY JSON:
{{"final_report_md": "## 概要\\n...(full assembled report)",
  "title_jp": "≤30 char Japanese title",
  "mitre_ids": ["T1566.001"],
  "cve_ids": ["CVE-..."]}}"""


# ─── Critic Agent (quality gate) ────────────────────────────────────────────
def prompt_critic(report_md: str, triage: dict) -> str:
    return f"""You are a harsh senior red team lead reviewing a junior's intel report.
Score the report rigorously for RED TEAM UTILITY (0-10 per dimension).

Triage metadata: {json.dumps(triage, ensure_ascii=False)[:300]}

REPORT:
{report_md[:8000]}

Score these dimensions strictly:
1. **specificity** (0-10): count concrete API calls, CLI commands, registry keys,
   file paths, specific values. Abstract language = low score.
2. **reproducibility** (0-10): can a tester actually set up and run this tomorrow?
   Are prerequisites, tools, steps complete?
3. **accuracy** (0-10): are ATT&CK IDs correct? Do sections contradict each other?
   Are facts consistent with what's known?
4. **detection_quality** (0-10): are detection queries realistic/working?
   Do they include real IoCs?
5. **completeness** (0-10): are all required sections present and substantive?

OVERALL = min(all 5 dimensions). This is the gate score.

Also list specific ISSUES that must be fixed before acceptance:
- each issue = concrete problem + fix suggestion

Output ONLY JSON:
{{"specificity": <0-10>, "reproducibility": <0-10>, "accuracy": <0-10>,
  "detection_quality": <0-10>, "completeness": <0-10>,
  "overall": <min of above>,
  "issues": ["specific problem 1 + fix", "problem 2 + fix"],
  "verdict": "ACCEPT|REVISE"}}"""


# ─── Revision Agent (fix issues from critic) ────────────────────────────────
def prompt_revise(current_report: str, issues: list, research_context: str) -> str:
    issues_str = "\n".join(f"- {i}" for i in issues[:10])
    return f"""Revise the report to fix these specific issues identified by the critic.
Preserve everything that's already good. Only modify sections with issues.

=== ISSUES TO FIX ===
{issues_str}

=== AVAILABLE RESEARCH CONTEXT (use to fill gaps) ===
{research_context[:3000]}

=== CURRENT REPORT ===
{current_report[:9000]}

Output ONLY JSON:
{{"final_report_md": "## 概要\\n...(full revised report)",
  "changes_made": ["what was changed 1", "change 2"]}}"""


# ============================================================================
# LLM CALL WRAPPERS — each with JSON mode, retry, graceful failure
# ============================================================================

def _extract_json(raw: str) -> dict | None:
    if not raw: return None
    cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    try: return json.loads(cleaned)
    except json.JSONDecodeError: pass
    bs, be = cleaned.find("{"), cleaned.rfind("}")
    if bs != -1 and be > bs:
        try: return json.loads(cleaned[bs:be+1])
        except json.JSONDecodeError: pass
        # Fix unescaped newlines inside strings
        fixed = re.sub(r'("(?:[^"\\]|\\.)*")',
            lambda m: m.group(1).replace("\n","\\n").replace("\r",""),
            cleaned[bs:be+1], flags=re.DOTALL)
        try: return json.loads(fixed)
        except json.JSONDecodeError: pass
    return None


def call_cerebras(prompt: str, model: str = "llama3.3-70b",
                  max_tokens: int = 8000) -> dict | None:
    if not cerebras_client: return None
    try:
        resp = cerebras_client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.25,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        return _extract_json(resp.choices[0].message.content)
    except Exception as e:
        print(f"    ✗ [Cerebras/{model}] {str(e)[:140]}")
        return None


def call_openrouter(prompt: str, model: str = "deepseek/deepseek-chat-v3-0324:free",
                    max_tokens: int = 8000) -> dict | None:
    if not openrouter_client: return None
    try:
        resp = openrouter_client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.25,
            max_tokens=max_tokens,
            extra_headers={
                "HTTP-Referer": "https://github.com/cipher-intel",
                "X-Title": "CIPHER Intel",
            },
        )
        return _extract_json(resp.choices[0].message.content)
    except Exception as e:
        print(f"    ✗ [OR/{model.split('/')[-1][:20]}] {str(e)[:140]}")
        return None


_GROQ_TPD_DEAD: set = set()

def call_groq(prompt: str, model: str = "llama-3.3-70b-versatile",
              max_tokens: int = 3500) -> dict | None:
    if model in _GROQ_TPD_DEAD: return None
    try:
        resp = groq_client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.15,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        return _extract_json(resp.choices[0].message.content)
    except Exception as e:
        err = str(e).lower()
        if "tokens per day" in err or "tpd" in err:
            print(f"    ✗ [Groq/{model}] TPD exhausted")
            _GROQ_TPD_DEAD.add(model)
        elif "rate_limit" in err:
            m = re.search(r"try again in ([\d.]+)([smh])", err)
            wait = 30
            if m:
                val, unit = float(m.group(1)), m.group(2)
                wait = min(val * {"s":1,"m":60,"h":3600}[unit], 45)
            print(f"    ✗ [Groq/{model}] TPM — waiting {wait:.0f}s")
            time.sleep(wait)
            try:
                resp = groq_client.chat.completions.create(
                    model=model, messages=[{"role":"user","content":prompt}],
                    temperature=0.15, max_tokens=max_tokens,
                    response_format={"type":"json_object"})
                return _extract_json(resp.choices[0].message.content)
            except Exception as e2:
                print(f"    ✗ [Groq/{model}] retry failed: {str(e2)[:100]}")
        else:
            print(f"    ✗ [Groq/{model}] {str(e)[:140]}")
    return None


def call_gemini(prompt: str) -> dict | None:
    if not gemini_model: return None
    try:
        import google.generativeai as genai
        resp = gemini_model.generate_content(
            prompt,
            generation_config=genai.GenerationConfig(
                temperature=0.2, max_output_tokens=8192,
                response_mime_type="application/json",
            ),
        )
        return _extract_json(resp.text or "")
    except Exception as e:
        err = str(e)
        if "429" in err or "quota" in err.lower():
            print(f"    ✗ [Gemini] rate limit — waiting 40s")
            time.sleep(40)
            try:
                resp = gemini_model.generate_content(
                    prompt,
                    generation_config=genai.GenerationConfig(
                        temperature=0.2, max_output_tokens=8192,
                        response_mime_type="application/json"))
                return _extract_json(resp.text or "")
            except Exception:
                return None
        print(f"    ✗ [Gemini] {err[:140]}")
        return None


def call_llm_chain(prompt: str, prefer: list[str] = None) -> dict | None:
    """Try generators in order until one succeeds.
    prefer = ordered list of: 'cerebras', 'openrouter', 'groq', 'gemini'"""
    order = prefer or ["cerebras", "openrouter", "groq", "gemini"]
    for name in order:
        if name == "cerebras":
            r = call_cerebras(prompt)
        elif name == "openrouter":
            r = call_openrouter(prompt)
        elif name == "groq":
            r = call_groq(prompt)
        elif name == "gemini":
            r = call_gemini(prompt)
        else:
            continue
        if r:
            print(f"    ✓ [{name}] OK")
            return r
    return None
# ============================================================================
# main.py  —  Part 2 of 3
# ============================================================================
# Append directly after Part 1.
#
# Contents:
#   - RSS / article body / Tavily fetchers
#   - Data enrichment: NVD, CISA KEV, MITRE ATT&CK, GitHub code search,
#                      VirusTotal, AlienVault OTX
#   - Self-RAG (30-day window keyword match against existing DB)
#   - Knowledge Graph update (APT/Malware/CVE/Tool/Technique/Industry/Country)
#   - Atomic Red Team yaml writer
#   - multi_agent_pipeline()  — orchestration of all 7 agents with critic loop
#   - process_article()       — single-article end-to-end handler
# ============================================================================


# ─── RSS / HTML body fetch (improved from v4.1) ─────────────────────────────
def fetch_rss(feed_url: str, max_items: int = 5) -> list[dict]:
    try:
        req = urllib.request.Request(feed_url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml, text/xml, */*",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
        root = ET.fromstring(raw)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        items = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)

        def parse_dt(s: str):
            if not s: return None
            for fmt in ["%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S GMT",
                        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"]:
                try:
                    dt = datetime.strptime(s.strip(), fmt)
                    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                except ValueError: continue
            return None

        for item in root.findall(".//item")[:max_items * 3]:
            title = (item.findtext("title", "") or "").strip()
            url = (item.findtext("link", "") or "").strip()
            pub = parse_dt(item.findtext("pubDate", "") or item.findtext("dc:date", ""))
            if pub and pub < cutoff: continue
            summary = item.findtext("description", "") or item.findtext("summary", "")
            content_el = item.find("{http://purl.org/rss/1.0/modules/content/}encoded")
            body = content_el.text if content_el is not None else summary
            body = unescape(re.sub(r"<[^>]+>", " ", body or "")).strip()
            if url: items.append({"url": url, "title": title, "content": body})
            if len(items) >= max_items: break

        if not items:
            for entry in root.findall("atom:entry", ns)[:max_items * 3]:
                title = (entry.findtext("atom:title", "", ns) or "").strip()
                link_el = entry.find("atom:link", ns)
                url = link_el.get("href", "") if link_el is not None else ""
                pub = parse_dt(entry.findtext("atom:updated", "", ns) or
                               entry.findtext("atom:published", "", ns))
                if pub and pub < cutoff: continue
                summary = (entry.findtext("atom:summary", "", ns) or
                           entry.findtext("atom:content", "", ns) or "")
                body = unescape(re.sub(r"<[^>]+>", " ", summary)).strip()
                if url: items.append({"url": url, "title": title, "content": body})
                if len(items) >= max_items: break
        return items
    except Exception as e:
        print(f"  ✗ RSS {feed_url[:50]}: {str(e)[:100]}")
        return []


def fetch_article_body(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        for tag in ("script","style","nav","footer","aside","header","form"):
            raw = re.sub(rf"<{tag}[^>]*>.*?</{tag}>", " ", raw,
                         flags=re.DOTALL | re.IGNORECASE)
        raw = re.sub(r"<!--.*?-->", " ", raw, flags=re.DOTALL)
        codes = re.findall(r"<(?:pre|code)[^>]*>(.*?)</(?:pre|code)>", raw,
                           re.DOTALL | re.IGNORECASE)
        code_text = "\n".join(unescape(re.sub(r"<[^>]+>", "", c)) for c in codes)[:2500]

        def clean(s):
            s = re.sub(r"<[^>]+>", " ", s)
            s = unescape(s)
            return re.sub(r"\s{2,}", " ", s).strip()

        for pattern in [
            r"<article[^>]*>(.*?)</article>",
            r"<main[^>]*>(.*?)</main>",
        ]:
            m = re.search(pattern, raw, re.DOTALL | re.IGNORECASE)
            if m:
                body = clean(m.group(1))
                if len(body) >= 300:
                    return (body + ("\n\nCODE:\n" + code_text if code_text else ""))[:10000]

        cands = re.findall(
            r'<div[^>]*(?:class|id)\s*=\s*"[^"]*(?:content|post|entry|article|body|main|single)[^"]*"[^>]*>(.*?)</div>',
            raw, re.DOTALL | re.IGNORECASE)
        if cands:
            best = max(cands, key=lambda c: len(clean(c)))
            body = clean(best)
            if len(body) >= 300:
                return (body + ("\n\nCODE:\n" + code_text if code_text else ""))[:10000]

        paras = re.findall(r"<p[^>]*>(.*?)</p>", raw, re.DOTALL | re.IGNORECASE)
        if paras:
            body = clean(" ".join(paras))
            if len(body) >= 200:
                return (body + ("\n\nCODE:\n" + code_text if code_text else ""))[:10000]

        return (clean(raw)[:8000] + ("\n\nCODE:\n" + code_text if code_text else ""))[:10000]
    except Exception as e:
        print(f"  ✗ body fetch {url[:50]}: {str(e)[:100]}")
        return ""


def fetch_tavily(query: str, max_results: int = 3) -> list[dict]:
    if not tavily_client: return []
    try:
        results = tavily_client.search(query=query, search_depth="advanced",
                                       max_results=max_results, days=3).get("results", [])
        return [{"url": r.get("url", ""), "title": r.get("title", ""),
                 "content": r.get("content", "")} for r in results
                if r.get("url") and len(r.get("content", "")) >= 200]
    except Exception as e:
        print(f"  ✗ Tavily {query[:40]}: {str(e)[:100]}")
        return []


# ─── Data Enrichment Sources ────────────────────────────────────────────────
def extract_cve_ids(text: str) -> list[str]:
    ids = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    seen, out = set(), []
    for i in ids:
        u = i.upper()
        if u not in seen:
            seen.add(u); out.append(u)
    return out[:5]


def fetch_nvd_cve(cve_id: str) -> str:
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        if not vulns: return ""
        cve = vulns[0].get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")[:800]
        cvss_str = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if cve.get("metrics", {}).get(key):
                m = cve["metrics"][key][0].get("cvssData", {})
                cvss_str = f"CVSS {m.get('baseScore','?')} ({m.get('baseSeverity','?')}) vector={m.get('vectorString','?')}"
                break
        cwes = [d["value"] for w in cve.get("weaknesses", [])
                for d in w.get("description", []) if d.get("value","").startswith("CWE-")][:3]
        refs = cve.get("references", [])[:6]
        ref_lines = [f"  - {r.get('url','')} [{','.join(r.get('tags',[]))}]" for r in refs]
        out = f"[NVD] {cve_id}\n  Desc: {desc}\n"
        if cvss_str: out += f"  {cvss_str}\n"
        if cwes: out += f"  CWE: {', '.join(cwes)}\n"
        if ref_lines: out += "  Refs:\n" + "\n".join(ref_lines) + "\n"
        return out
    except Exception as e:
        print(f"    ✗ NVD {cve_id}: {str(e)[:100]}")
        return ""


_cisa_kev_cache = None
def fetch_cisa_kev() -> dict:
    global _cisa_kev_cache
    if _cisa_kev_cache is not None: return _cisa_kev_cache
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        _cisa_kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        print(f"    [CISA KEV] cached {len(_cisa_kev_cache)} entries")
    except Exception as e:
        print(f"    ✗ CISA KEV: {str(e)[:100]}")
        _cisa_kev_cache = {}
    return _cisa_kev_cache


def check_kev(cve_id: str) -> str:
    kev = fetch_cisa_kev()
    if cve_id in kev:
        v = kev[cve_id]
        return (f"[CISA KEV] {cve_id} — ITW EXPLOITED\n"
                f"  Added: {v.get('dateAdded','')}\n"
                f"  Ransomware use: {v.get('knownRansomwareCampaignUse','')}\n"
                f"  Required action: {v.get('requiredAction','')[:200]}\n")
    return ""


def fetch_attack_technique(tid: str) -> str:
    try:
        tid_clean = tid.split(".")[0]
        url = f"https://attack.mitre.org/techniques/{tid_clean.replace('T','T')}/"
        # ATT&CK has no JSON API without MCP; fetch HTML and extract description
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        m = re.search(r'<div class="description-body">(.*?)</div>', html, re.DOTALL)
        if m:
            desc = re.sub(r"<[^>]+>", " ", m.group(1))
            desc = re.sub(r"\s{2,}", " ", unescape(desc)).strip()[:500]
            return f"[ATT&CK {tid}] {desc}\n"
    except Exception:
        pass
    return ""


def search_github_code(query: str) -> str:
    try:
        q = urllib.parse.quote(query)
        url = f"https://api.github.com/search/code?q={q}&per_page=3"
        headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
        if GITHUB_TOKEN: headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        items = data.get("items", [])[:3]
        if not items: return ""
        lines = [f"[GitHub code] {query}"]
        for it in items:
            lines.append(f"  - {it.get('html_url','')}")
            lines.append(f"    repo: {it.get('repository',{}).get('full_name','')}")
            lines.append(f"    path: {it.get('path','')}")
        return "\n".join(lines) + "\n"
    except Exception as e:
        print(f"    ✗ GH code: {str(e)[:80]}")
        return ""


def search_github_repos(keyword: str) -> str:
    try:
        q = urllib.parse.quote(f"{keyword} PoC exploit")
        url = f"https://api.github.com/search/repositories?q={q}&sort=updated&per_page=5"
        headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
        if GITHUB_TOKEN: headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        items = data.get("items", [])[:5]
        if not items: return ""
        lines = [f"[GitHub repos] {keyword}"]
        for it in items:
            desc = (it.get("description") or "").strip()[:120]
            lines.append(f"  - {it.get('html_url','')} ⭐{it.get('stargazers_count',0)} {desc}")
        return "\n".join(lines) + "\n"
    except Exception as e:
        print(f"    ✗ GH repos: {str(e)[:80]}")
        return ""


def fetch_virustotal_ioc(ioc: str, ioc_type: str = "domain") -> str:
    if not VT_KEY: return ""
    try:
        endpoint = {"domain": "domains", "ip": "ip_addresses",
                    "hash": "files", "url": "urls"}.get(ioc_type, "domains")
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT, "x-apikey": VT_KEY})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        rep = attrs.get("reputation", 0)
        return (f"[VirusTotal] {ioc} ({ioc_type})\n"
                f"  Malicious: {stats.get('malicious',0)} / "
                f"Suspicious: {stats.get('suspicious',0)} / "
                f"Harmless: {stats.get('harmless',0)}\n"
                f"  Reputation: {rep}\n")
    except Exception as e:
        return ""


def fetch_otx_ioc(ioc: str, ioc_type: str = "domain") -> str:
    if not OTX_KEY: return ""
    try:
        ep_map = {"domain": "domain", "ip": "IPv4", "hash": "file", "url": "url"}
        section = ep_map.get(ioc_type, "domain")
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc}/general"
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT, "X-OTX-API-KEY": OTX_KEY})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        pulses = data.get("pulse_info", {}).get("count", 0)
        names = [p.get("name","")[:60] for p in data.get("pulse_info",{}).get("pulses",[])[:3]]
        return (f"[OTX] {ioc} — {pulses} pulses\n"
                f"  Related: {'; '.join(names)}\n")
    except Exception:
        return ""


# ─── Research Orchestrator (called per article) ─────────────────────────────
def run_research_agent(triage: dict, content: str) -> str:
    """Collect enrichment from all available sources based on triage."""
    parts = []
    cve_ids = triage.get("cve_ids") or extract_cve_ids(content + " " + triage.get("title_jp", ""))

    # NVD + CISA KEV for each CVE
    for cid in cve_ids[:3]:
        print(f"      [NVD] {cid}")
        nvd = fetch_nvd_cve(cid)
        if nvd: parts.append(nvd)
        kev = check_kev(cid)
        if kev: parts.append(kev)
        time.sleep(0.4)

    # ATT&CK descriptions
    for tid in (triage.get("mitre_ids") or [])[:3]:
        atk = fetch_attack_technique(tid)
        if atk: parts.append(atk)
        time.sleep(0.3)

    # Tavily deep search on each keyword
    for kw in (triage.get("research_keywords") or [])[:2]:
        q = f"{cve_ids[0]} technical analysis" if cve_ids else f"{kw} technical analysis exploit"
        print(f"      [Tavily] {q[:55]}")
        if tavily_client:
            try:
                results = tavily_client.search(query=q, search_depth="advanced",
                                               max_results=2).get("results", [])
                for r in results:
                    parts.append(f"[Tavily] {r.get('url','')}\n  {r.get('content','')[:450]}\n")
            except Exception: pass
        time.sleep(0.3)

    # GitHub PoC + code search per CVE
    for cid in cve_ids[:2]:
        gh = search_github_repos(cid)
        if gh: parts.append(gh)
        ghc = search_github_code(cid)
        if ghc: parts.append(ghc)
        time.sleep(0.4)

    return "\n".join(parts)


# ─── Self-RAG: related articles from past 30 days ───────────────────────────
def find_related_articles(db: list[dict], triage: dict, max_items: int = 4) -> str:
    """Find related articles from past 30 days using keyword overlap."""
    cutoff = (now_jst() - timedelta(days=30)).strftime("%Y-%m-%d")
    recent = [a for a in db if a.get("date", "0") >= cutoff]
    if not recent: return ""

    # Build keyword set from triage
    kws = set()
    for c in (triage.get("cve_ids") or []): kws.add(c.upper())
    for m in (triage.get("mitre_ids") or []): kws.add(m)
    if triage.get("threat_actor"):   kws.add(triage["threat_actor"].lower())
    if triage.get("malware_family"): kws.add(triage["malware_family"].lower())
    for kw in (triage.get("research_keywords") or [])[:3]:
        kws.add(kw.lower())

    if not kws: return ""

    scored = []
    for a in recent:
        hay = (a.get("title","") + " " + " ".join(a.get("summary_points",[])) + " " +
               " ".join(a.get("cve_ids",[])) + " " + " ".join(a.get("mitre_ids",[])) + " " +
               (a.get("threat_actor","") or "") + " " + (a.get("malware_family","") or "")).lower()
        score = sum(1 for k in kws if k.lower() in hay)
        if score > 0:
            scored.append((score, a))
    scored.sort(key=lambda x: -x[0])

    if not scored: return ""
    lines = []
    for score, a in scored[:max_items]:
        lines.append(f"[Related article, overlap={score}] {a.get('date','')} {a.get('title','')}")
        if a.get("summary_points"):
            lines.append(f"  Summary: {' / '.join(a['summary_points'][:3])[:300]}")
        if a.get("cve_ids"):
            lines.append(f"  CVEs: {', '.join(a['cve_ids'][:4])}")
        if a.get("mitre_ids"):
            lines.append(f"  ATT&CK: {', '.join(a['mitre_ids'][:4])}")
    return "\n".join(lines)


# ─── Knowledge Graph ────────────────────────────────────────────────────────
def load_kg() -> dict:
    if Path(KG_DATA).exists():
        try:
            return json.loads(Path(KG_DATA).read_text(encoding="utf-8"))
        except Exception: pass
    return {
        "entities": {
            "threat_actors": {}, "malware_families": {}, "cves": {},
            "tools": {}, "techniques": {}, "industries": {}, "countries": {},
        },
        "relationships": [],
        "updated": "",
    }


def save_kg(kg: dict) -> None:
    kg["updated"] = now_jst().strftime("%Y-%m-%d %H:%M")
    Path(KG_DATA).write_text(json.dumps(kg, ensure_ascii=False, indent=2), encoding="utf-8")


def update_kg(kg: dict, entry: dict, triage: dict) -> None:
    """Register entities from a new article into the KG."""
    url = entry.get("url", "")
    date = entry.get("date", "")

    def _add(section: str, key: str):
        if not key or not key.strip(): return
        key = key.strip()
        bucket = kg["entities"].setdefault(section, {})
        rec = bucket.setdefault(key, {"articles": [], "first_seen": date, "last_seen": date})
        if url not in rec["articles"]:
            rec["articles"].append(url)
        rec["last_seen"] = date

    # Direct entities from triage/entry
    if triage.get("threat_actor"):   _add("threat_actors",    triage["threat_actor"])
    if triage.get("malware_family"): _add("malware_families", triage["malware_family"])
    for cve in entry.get("cve_ids", []):     _add("cves", cve)
    for tid in entry.get("mitre_ids", []):   _add("techniques", tid)

    # industries / countries / tools extracted by editor_entities (added in Part 3)
    for ind in entry.get("industries", []):  _add("industries", ind)
    for ctry in entry.get("countries", []):  _add("countries", ctry)
    for tool in entry.get("tools", []):      _add("tools", tool)

    # Relationships
    actor = triage.get("threat_actor")
    family = triage.get("malware_family")
    if actor and family:
        kg["relationships"].append({
            "from": actor, "rel": "uses_malware", "to": family,
            "source": url, "date": date,
        })
    for tid in entry.get("mitre_ids", [])[:5]:
        if actor:
            kg["relationships"].append({
                "from": actor, "rel": "uses_technique", "to": tid,
                "source": url, "date": date,
            })
    for ctry in entry.get("countries", []):
        if actor:
            kg["relationships"].append({
                "from": actor, "rel": "targets_country", "to": ctry,
                "source": url, "date": date,
            })
    for ind in entry.get("industries", []):
        if actor:
            kg["relationships"].append({
                "from": actor, "rel": "targets_industry", "to": ind,
                "source": url, "date": date,
            })

    # Dedupe relationships (last 500 kept)
    seen = set()
    deduped = []
    for r in reversed(kg["relationships"]):
        k = (r["from"], r["rel"], r["to"])
        if k not in seen:
            seen.add(k); deduped.append(r)
    kg["relationships"] = list(reversed(deduped))[-500:]


# ─── Atomic Red Team yaml writer ────────────────────────────────────────────
def write_atomic_tests(article_id: str, atomic_tests: list[dict]) -> list[str]:
    if not atomic_tests: return []
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", article_id)[:80]
    written = []
    for idx, t in enumerate(atomic_tests[:5]):
        filename = f"{ATOMIC_DIR}/{safe_id}_{idx+1}.yaml"
        try:
            y = (
                f"# Auto-generated by CIPHER v5.0\n"
                f"# Source: {article_id}\n"
                f"attack_technique: {t.get('name','Unknown').split(' ')[0]}\n"
                f"display_name: {json.dumps(t.get('name','Unknown'), ensure_ascii=False)}\n"
                f"atomic_tests:\n"
                f"  - name: {json.dumps(t.get('name','Test'), ensure_ascii=False)}\n"
                f"    description: |\n"
                f"      {(t.get('description','') or '').replace(chr(10), chr(10)+'      ')}\n"
                f"    supported_platforms:\n"
                f"      - {t.get('platform','windows')}\n"
                f"    executor:\n"
                f"      name: {t.get('executor','command_prompt')}\n"
                f"      command: |\n"
                f"        {(t.get('command','') or '').replace(chr(10), chr(10)+'        ')}\n"
            )
            if t.get("cleanup"):
                y += (f"      cleanup_command: |\n"
                      f"        {t['cleanup'].replace(chr(10), chr(10)+'        ')}\n")
            Path(filename).write_text(y, encoding="utf-8")
            written.append(filename)
        except Exception as e:
            print(f"    ✗ atomic write: {e}")
    return written


# ============================================================================
# MULTI-AGENT PIPELINE
# ============================================================================
def multi_agent_pipeline(content: str, category: str, triage: dict,
                         research_context: str, related_articles: str) -> dict | None:
    """
    Run the full 7-agent pipeline with Critic loop.
    Returns final report dict or None on failure.
    """
    triage["category"] = category

    # ─── Agent 1: Analyst (Cerebras primary) ────────────────────────────
    print(f"    [Analyst] generating mechanism...")
    analyst_out = call_llm_chain(
        prompt_analyst(content, triage, research_context, related_articles),
        prefer=["cerebras", "openrouter", "groq"],
    )
    if not analyst_out or not analyst_out.get("mechanism_md"):
        print(f"    ✗ Analyst failed")
        return None
    mechanism_md = analyst_out["mechanism_md"]
    extra_iocs = analyst_out.get("key_iocs_extracted", [])

    # ─── Agent 2: Exploit writer (DeepSeek via OpenRouter primary) ──────
    print(f"    [Exploit] generating reproduction + lab + atomic...")
    exploit_out = call_llm_chain(
        prompt_exploit(content, triage, mechanism_md, research_context),
        prefer=["openrouter", "cerebras", "groq"],
    )
    if not exploit_out:
        print(f"    ✗ Exploit failed")
        return None
    reproduction_md = exploit_out.get("reproduction_md", "")
    lab_setup_md    = exploit_out.get("lab_setup_md", "")
    atomic_tests    = exploit_out.get("atomic_tests", [])

    # ─── Agent 3: Detection engineer ────────────────────────────────────
    print(f"    [Detection] generating SIEM queries...")
    detection_out = call_llm_chain(
        prompt_detection(mechanism_md, reproduction_md, extra_iocs),
        prefer=["cerebras", "groq", "openrouter"],
    )
    if not detection_out:
        print(f"    ✗ Detection failed — using minimal stub")
        detection_out = {"detection_md": "## 検知・防御策\n(生成失敗)",
                         "ioc_md": "## IoC・痕跡情報\n記載なし"}
    detection_md = detection_out.get("detection_md", "")
    ioc_md       = detection_out.get("ioc_md", "")

    # ─── Agent 4: Editor (final synthesis) ──────────────────────────────
    print(f"    [Editor] assembling final report...")
    editor_out = call_llm_chain(
        prompt_editor(triage, mechanism_md, reproduction_md, lab_setup_md,
                      detection_md, ioc_md, research_context),
        prefer=["cerebras", "openrouter", "groq"],
    )
    if not editor_out or not editor_out.get("final_report_md"):
        print(f"    ✗ Editor failed")
        return None
    final_report = editor_out["final_report_md"]

    if len(final_report) < MIN_REPORT_LEN:
        print(f"    ✗ report too short ({len(final_report)} < {MIN_REPORT_LEN})")
        return None

    # ─── Agent 5: Critic loop ───────────────────────────────────────────
    critic_scores = []
    for loop in range(MAX_CRITIC_LOOPS + 1):
        print(f"    [Critic] reviewing (loop {loop+1})...")
        critic_out = call_llm_chain(
            prompt_critic(final_report, triage),
            prefer=["gemini", "cerebras", "groq"],
        )
        if not critic_out:
            print(f"    ⚠ Critic unavailable — accepting as-is")
            break
        overall = critic_out.get("overall", 0)
        critic_scores.append({
            "loop": loop + 1, "overall": overall,
            "specificity": critic_out.get("specificity", 0),
            "reproducibility": critic_out.get("reproducibility", 0),
            "accuracy": critic_out.get("accuracy", 0),
            "detection_quality": critic_out.get("detection_quality", 0),
            "completeness": critic_out.get("completeness", 0),
        })
        print(f"    [Critic] overall={overall}/10 "
              f"(spec={critic_out.get('specificity',0)} "
              f"repro={critic_out.get('reproducibility',0)} "
              f"acc={critic_out.get('accuracy',0)} "
              f"det={critic_out.get('detection_quality',0)} "
              f"cmp={critic_out.get('completeness',0)})")

        if overall >= CRITIC_THRESHOLD or critic_out.get("verdict") == "ACCEPT":
            print(f"    ✓ Critic ACCEPT")
            break
        if loop >= MAX_CRITIC_LOOPS:
            print(f"    ⚠ max critic loops reached — accepting")
            break

        # ─── Revise ────────────────────────────────────────────────
        issues = critic_out.get("issues", [])
        print(f"    [Revise] fixing {len(issues)} issues...")
        revise_out = call_llm_chain(
            prompt_revise(final_report, issues, research_context),
            prefer=["cerebras", "openrouter", "groq"],
        )
        if revise_out and revise_out.get("final_report_md"):
            final_report = revise_out["final_report_md"]
        else:
            print(f"    ⚠ Revise failed — keeping previous")
            break

    return {
        "title":          editor_out.get("title_jp") or triage.get("title_jp") or "Untitled",
        "summary_points": triage.get("summary_points", []),
        "poc_url":        triage.get("poc_url", ""),
        "cvss_score":     triage.get("cvss_score", ""),
        "mitre_ids":      editor_out.get("mitre_ids") or triage.get("mitre_ids", []),
        "cve_ids":        editor_out.get("cve_ids") or triage.get("cve_ids", []),
        "threat_actor":   triage.get("threat_actor", ""),
        "malware_family": triage.get("malware_family", ""),
        "content":        final_report,
        "atomic_tests":   atomic_tests,
        "critic_scores":  critic_scores,
    }


# ============================================================================
# process_article  — single article end-to-end
# ============================================================================
def process_article(url: str, title: str, content: str, category: str,
                    seen_title_hashes: set, db: list[dict]) -> dict | None:
    # 1. Body completion
    if len(content) < 1500:
        print(f"    fetching full body...")
        fetched = fetch_article_body(url)
        if len(fetched) > len(content):
            content = fetched
    if len(content) < 150:
        print(f"    skip (body too short)")
        return None

    # 2. Triage (Groq — cheap & fast)
    triage = call_groq(prompt_triage(content, category))
    if triage is None:
        triage = call_llm_chain(prompt_triage(content, category),
                                prefer=["cerebras", "openrouter", "gemini"])
    if triage is None or triage.get("skip"):
        reason = (triage or {}).get("reason", "triage failed")
        print(f"    skip: {reason}")
        return None

    print(f"    ✓ triage: score={triage.get('score','?')} "
          f"density={triage.get('info_density','?')} "
          f"actor={triage.get('threat_actor','-')} "
          f"family={triage.get('malware_family','-')}")

    # 3. Research agent (always run for score>=4, or low density)
    score = triage.get("score", 0)
    density = triage.get("info_density", "medium")
    research_context = ""
    if score >= 4 or density == "low" or (density == "medium" and len(content) < MIN_SOURCE_LEN):
        print(f"    🔍 research agent...")
        research_context = run_research_agent(triage, content)

    # 4. Self-RAG — related recent articles
    related = find_related_articles(db, triage, max_items=4)
    if related:
        print(f"    📚 found related articles in last 30d")

    # 5. Multi-agent pipeline
    result = multi_agent_pipeline(content, category, triage, research_context, related)
    if result is None:
        return None

    # 6. Dedup by title hash
    th = hashlib.md5(re.sub(r"[^\w]", "", result["title"]).lower().encode()).hexdigest()[:8]
    if th in seen_title_hashes:
        print(f"    ✗ duplicate title")
        return None
    seen_title_hashes.add(th)

    # 7. Write atomic tests
    article_id = hashlib.md5(url.encode()).hexdigest()[:12]
    atomic_files = write_atomic_tests(article_id, result.get("atomic_tests", []))
    if atomic_files:
        print(f"    📝 wrote {len(atomic_files)} atomic yaml files")

    return {
        "date":           now_jst().strftime("%Y-%m-%d"),
        "category":       category,
        "title":          result["title"],
        "summary_points": result.get("summary_points", []),
        "poc_url":        result.get("poc_url", ""),
        "cvss_score":     result.get("cvss_score", ""),
        "mitre_ids":      result.get("mitre_ids", []),
        "cve_ids":        result.get("cve_ids", []),
        "threat_actor":   result.get("threat_actor", ""),
        "malware_family": result.get("malware_family", ""),
        "content":        result["content"],
        "url":            url,
        "researched":     bool(research_context),
        "critic_scores":  result.get("critic_scores", []),
        "atomic_files":   atomic_files,
        "industries":     [],   # filled by editor_entities pass (Part 3 optional)
        "countries":      [],
    }

# ============================================================================
# main.py  —  Part 3 of 3 (final)
# Append directly after Part 2.
# ============================================================================

# ─── DB / Run Log ───────────────────────────────────────────────────────────
def load_db() -> list[dict]:
    if Path(MASTER_DATA).exists():
        try: return json.loads(Path(MASTER_DATA).read_text(encoding="utf-8"))
        except Exception: pass
    return []


def update_db(db: list[dict], new_entries: list[dict]) -> list[dict]:
    existing = {a["url"] for a in db}
    added = 0
    for e in new_entries:
        if e["url"] not in existing:
            db.append(e); added += 1
    db = sorted(db, key=lambda x: x["date"], reverse=True)[:MAX_DB_ENTRIES]
    Path(MASTER_DATA).write_text(json.dumps(db, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"DB: +{added} / {len(db)} total")
    return db


def load_run_log() -> list[dict]:
    if Path(RUN_LOG_FILE).exists():
        try: return json.loads(Path(RUN_LOG_FILE).read_text(encoding="utf-8"))
        except Exception: pass
    return []


def append_run_log(run_log: list[dict], new_count: int, total: int,
                   stats: dict) -> list[dict]:
    entry = {
        "datetime_jst":     now_jst().strftime("%Y-%m-%d %H:%M"),
        "new_articles":     new_count,
        "total_articles":   total,
        "researched_count": stats.get("researched_count", 0),
        "critic_passed":    stats.get("critic_passed", 0),
        "critic_revised":   stats.get("critic_revised", 0),
        "avg_critic_score": stats.get("avg_critic_score", 0),
        "tpd_exhausted":    stats.get("tpd_exhausted", False),
        "categories":       stats.get("categories", {}),
    }
    run_log.append(entry)
    run_log = run_log[-120:]
    Path(RUN_LOG_FILE).write_text(json.dumps(run_log, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
    return run_log


# ============================================================================
# MAIN COLLECTION LOOP
# ============================================================================
def fetch_and_analyze(existing_urls: set, db: list[dict]) -> tuple[list[dict], dict]:
    print("\n" + "=" * 60)
    print("  START: multi-agent collection")
    print("=" * 60)

    new_articles: list[dict] = []
    seen_urls = set(existing_urls)
    seen_title_hashes = set()
    run_stats = {
        "tpd_exhausted": False, "researched_count": 0,
        "critic_passed": 0, "critic_revised": 0,
        "critic_scores_all": [],
        "categories": {},
    }

    for cat_id, feeds in RSS_FEEDS.items():
        cat_stats = {"adopted": 0, "skipped": 0, "researched": 0,
                     "tpd_hit": False, "feed_errors": []}
        run_stats["categories"][cat_id] = cat_stats

        if len(_GROQ_TPD_DEAD) >= 2 and not (cerebras_client or openrouter_client or gemini_model):
            print(f"  [{cat_id}] skipped (all LLMs exhausted)")
            cat_stats["tpd_hit"] = True
            run_stats["tpd_exhausted"] = True
            continue

        print(f"\n[{cat_id}] " + "─" * 40)
        cat_count = 0

        for feed_url in feeds:
            if cat_count >= MAX_PER_CATEGORY: break
            print(f"  RSS: {feed_url[:60]}")
            items = fetch_rss(feed_url, MAX_ITEMS_PER_FEED)
            print(f"    got {len(items)} items")
            if not items:
                host = feed_url.split("/")[2] if "/" in feed_url else feed_url
                cat_stats["feed_errors"].append(host)

            for item in items:
                if cat_count >= MAX_PER_CATEGORY: break
                url = item["url"]
                if url in seen_urls:
                    cat_stats["skipped"] += 1; continue
                seen_urls.add(url)
                print(f"\n  → {url[:70]}")

                entry = process_article(url, item["title"], item["content"],
                                        cat_id, seen_title_hashes, db)
                if entry is None:
                    cat_stats["skipped"] += 1; continue

                new_articles.append(entry)
                cat_count += 1
                cat_stats["adopted"] += 1
                if entry.get("researched"):
                    cat_stats["researched"] += 1
                    run_stats["researched_count"] += 1

                # Track critic scores
                cs = entry.get("critic_scores", [])
                if cs:
                    best = max(cs, key=lambda x: x.get("overall", 0))
                    run_stats["critic_scores_all"].append(best.get("overall", 0))
                    if best.get("overall", 0) >= CRITIC_THRESHOLD:
                        run_stats["critic_passed"] += 1
                    if len(cs) > 1:
                        run_stats["critic_revised"] += 1

                time.sleep(SLEEP_BETWEEN_REQ)

        print(f"  [{cat_id}] adopted={cat_count} researched={cat_stats['researched']}")

    # Tavily discovery phase
    if tavily_client and not run_stats["tpd_exhausted"]:
        print(f"\n[TAVILY DISCOVERY] " + "─" * 40)
        for cat_id, queries in TAVILY_QUERIES.items():
            cat_stats = run_stats["categories"].setdefault(cat_id, {
                "adopted": 0, "skipped": 0, "researched": 0,
                "tpd_hit": False, "feed_errors": []})
            for q in queries:
                print(f"  query: {q[:60]}")
                items = fetch_tavily(q, 3)
                for item in items:
                    url = item["url"]
                    if url in seen_urls:
                        cat_stats["skipped"] += 1; continue
                    seen_urls.add(url)
                    print(f"\n  → {url[:70]}")
                    entry = process_article(url, item["title"], item["content"],
                                            cat_id, seen_title_hashes, db)
                    if entry is None:
                        cat_stats["skipped"] += 1; continue
                    new_articles.append(entry)
                    cat_stats["adopted"] += 1
                    if entry.get("researched"):
                        cat_stats["researched"] += 1
                        run_stats["researched_count"] += 1
                    cs = entry.get("critic_scores", [])
                    if cs:
                        best = max(cs, key=lambda x: x.get("overall", 0))
                        run_stats["critic_scores_all"].append(best.get("overall", 0))
                        if best.get("overall", 0) >= CRITIC_THRESHOLD:
                            run_stats["critic_passed"] += 1
                        if len(cs) > 1:
                            run_stats["critic_revised"] += 1
                    time.sleep(SLEEP_BETWEEN_REQ)

    if run_stats["critic_scores_all"]:
        run_stats["avg_critic_score"] = round(
            sum(run_stats["critic_scores_all"]) / len(run_stats["critic_scores_all"]), 1)

    print("\n" + "=" * 60)
    print(f"  DONE: {len(new_articles)} adopted, "
          f"{run_stats['researched_count']} researched, "
          f"avg critic score: {run_stats.get('avg_critic_score', 0)}/10")
    print("=" * 60)
    return new_articles, run_stats


# ============================================================================
# HTML GENERATION
# ============================================================================
def generate_html(db: list[dict], run_log: list[dict], kg: dict) -> None:
    # articles.js
    js = "window.__ARTICLES__ = " + json.dumps(db, ensure_ascii=False) + ";"
    Path("articles.js").write_text(js, encoding="utf-8")
    print(f"wrote articles.js ({len(js)} bytes, {len(db)} entries)")

    # log.js
    Path("log.js").write_text(
        "window.__RUN_LOG__ = " + json.dumps(run_log, ensure_ascii=False) + ";",
        encoding="utf-8")

    # kg.js — extract top entities for UI panel
    top_kg = {}
    for section in ("threat_actors", "malware_families", "cves", "techniques",
                    "industries", "countries"):
        items = kg.get("entities", {}).get(section, {})
        ranked = sorted(items.items(), key=lambda x: -len(x[1].get("articles", [])))[:10]
        top_kg[section] = [{"name": k, "count": len(v.get("articles", [])),
                            "last_seen": v.get("last_seen", "")} for k, v in ranked]
    top_kg["updated"] = kg.get("updated", "")
    top_kg["relationships_count"] = len(kg.get("relationships", []))
    Path("kg.js").write_text(
        "window.__KG__ = " + json.dumps(top_kg, ensure_ascii=False) + ";",
        encoding="utf-8")

    Path("index.html").write_text(_build_index_html(), encoding="utf-8")
    Path("log.html").write_text(_build_log_html(), encoding="utf-8")
    print("wrote index.html / log.html")


def _build_index_html() -> str:
    return r"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIPHER v5 // Red Team Intel</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.8/dist/purify.min.js"></script>
<style>
:root{
  --bg:#0f1419;--surf:#1a1f29;--surf2:#232834;--bdr:#2a3140;
  --text:#c8d1dc;--muted:#7a8699;--hi:#fff;
  --acc:#4fc3f7;--acc2:#ffb74d;--good:#66bb6a;--bad:#ef5350;
  --MAL:#ef5350;--INIT:#ffb74d;--POST:#ba68c8;--AI:#4fc3f7;
  --mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans JP',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6}
a{color:var(--acc);text-decoration:none}
a:hover{text-decoration:underline}
.hdr{position:sticky;top:0;z-index:50;background:rgba(15,20,25,.95);backdrop-filter:blur(8px);border-bottom:1px solid var(--bdr);padding:14px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.hdr-title{font-size:1.15rem;font-weight:700;color:var(--hi)}
.hdr-title span{color:var(--acc)}
.hdr-sub{font-family:var(--mono);font-size:.7rem;color:var(--muted)}
.hdr-stats{margin-left:auto;display:flex;gap:14px;font-family:var(--mono);font-size:.75rem;color:var(--muted)}
.hdr-stats b{color:var(--hi)}
.hdr-log{font-family:var(--mono);font-size:.72rem;color:var(--muted);border:1px solid var(--bdr);padding:5px 10px;border-radius:4px}
.hdr-log:hover{color:var(--acc);border-color:var(--acc);text-decoration:none}
.kg-panel{max-width:900px;margin:14px auto 0;padding:14px 20px;background:var(--surf);border:1px solid var(--bdr);border-radius:8px;display:none}
.kg-panel.open{display:block}
.kg-toggle{max-width:900px;margin:14px auto 0;padding:0 20px;font-family:var(--mono);font-size:.7rem;color:var(--muted);cursor:pointer}
.kg-toggle:hover{color:var(--acc)}
.kg-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.kg-sec{background:var(--surf2);border:1px solid var(--bdr);border-radius:6px;padding:10px 12px}
.kg-sec h4{font-family:var(--mono);font-size:.65rem;color:var(--acc);letter-spacing:.08em;margin-bottom:6px}
.kg-item{font-family:var(--mono);font-size:.72rem;color:var(--text);padding:2px 0;display:flex;justify-content:space-between}
.kg-item b{color:var(--acc2)}
.ctrl{max-width:900px;margin:18px auto 8px;padding:0 20px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
#search{flex:1;min-width:200px;padding:10px 14px;background:var(--surf);border:1px solid var(--bdr);color:var(--hi);border-radius:6px;font-size:.9rem;outline:none}
#search:focus{border-color:var(--acc)}
#search::placeholder{color:var(--muted)}
.filters{display:flex;gap:6px;flex-wrap:wrap}
.fbtn{padding:6px 12px;background:var(--surf);border:1px solid var(--bdr);color:var(--muted);border-radius:20px;cursor:pointer;font-family:var(--mono);font-size:.72rem;font-weight:600}
.fbtn:hover{color:var(--text);border-color:var(--muted)}
.fbtn.on{background:var(--acc);color:#000;border-color:var(--acc)}
.feed{max-width:900px;margin:0 auto;padding:0 20px 60px}
.day{font-family:var(--mono);font-size:.72rem;color:var(--muted);letter-spacing:.1em;margin:24px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--bdr)}
.day.today{color:var(--acc)}
.card{background:var(--surf);border:1px solid var(--bdr);border-radius:8px;padding:18px 20px;margin-bottom:12px;cursor:pointer}
.card:hover{border-color:var(--muted)}
.card-top{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap}
.tag{font-family:var(--mono);font-size:.65rem;font-weight:700;padding:3px 9px;border-radius:3px;letter-spacing:.04em}
.tag.MALWARE{background:rgba(239,83,80,.15);color:var(--MAL)}
.tag.INITIAL{background:rgba(255,183,77,.15);color:var(--INIT)}
.tag.POST_EXP{background:rgba(186,104,200,.15);color:var(--POST)}
.tag.AI_SEC{background:rgba(79,195,247,.15);color:var(--AI)}
.meta{font-family:var(--mono);font-size:.7rem;color:var(--muted)}
.score{font-family:var(--mono);font-size:.68rem;font-weight:700;padding:2px 8px;border-radius:3px;margin-left:auto;background:var(--surf2);color:var(--muted)}
.score.s-good{background:rgba(102,187,106,.15);color:var(--good)}
.score.s-mid{background:rgba(255,183,77,.15);color:var(--INIT)}
.score.s-bad{background:rgba(239,83,80,.15);color:var(--bad)}
.cvss{font-family:var(--mono);font-size:.68rem;font-weight:700;padding:2px 8px;border-radius:3px}
.cvss.crit{background:rgba(239,83,80,.15);color:var(--MAL)}
.cvss.high{background:rgba(255,183,77,.15);color:var(--INIT)}
.cvss.med{background:rgba(255,213,79,.15);color:#ffd54f}
.cvss.low{background:rgba(79,195,247,.15);color:var(--AI)}
.researched,.revised{font-family:var(--mono);font-size:.62rem;font-weight:700;padding:2px 8px;border-radius:3px}
.researched{background:rgba(186,104,200,.15);color:var(--POST)}
.revised{background:rgba(255,183,77,.15);color:var(--INIT)}
.title{font-size:1.12rem;font-weight:700;color:var(--hi);line-height:1.45;margin-bottom:8px}
.sum{list-style:none;padding:0;margin:0}
.sum li{padding:3px 0 3px 16px;position:relative;font-size:.88rem;line-height:1.65}
.sum li::before{content:'•';position:absolute;left:4px;color:var(--acc)}
.chips{display:flex;gap:5px;flex-wrap:wrap;margin-top:12px}
.chip{font-family:var(--mono);font-size:.65rem;padding:2px 8px;border-radius:3px;background:var(--surf2);color:var(--muted);border:1px solid var(--bdr)}
.chip.cve{color:var(--INIT);border-color:rgba(255,183,77,.3)}
.chip.mitre{color:var(--POST);border-color:rgba(186,104,200,.3)}
.chip.apt{color:var(--bad);border-color:rgba(239,83,80,.3);font-weight:700}
.chip.mal{color:var(--MAL);border-color:rgba(239,83,80,.25)}
.chip.poc{color:var(--AI);border-color:rgba(79,195,247,.3);font-weight:700}
.chip.atomic{color:var(--good);border-color:rgba(102,187,106,.3);font-weight:700}
.src{display:block;margin-top:10px;padding-top:10px;border-top:1px solid var(--bdr);font-family:var(--mono);font-size:.68rem;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.empty{text-align:center;padding:80px 20px;color:var(--muted);font-family:var(--mono)}
#det{position:fixed;inset:0;background:var(--bg);z-index:100;display:none;flex-direction:column}
#det.open{display:flex}
.det-hdr{position:sticky;top:0;background:rgba(15,20,25,.95);backdrop-filter:blur(8px);border-bottom:1px solid var(--bdr);padding:12px 20px;display:flex;align-items:center;gap:12px}
.back{background:var(--surf);border:1px solid var(--bdr);color:var(--text);padding:7px 16px;border-radius:6px;cursor:pointer;font-family:var(--mono);font-size:.75rem;font-weight:600}
.back:hover{border-color:var(--acc);color:var(--acc)}
.det-src{margin-left:auto;font-family:var(--mono);font-size:.7rem;color:var(--muted)}
.det-body{flex:1;overflow-y:auto;padding:30px 20px 60px}
.det-in{max-width:780px;margin:0 auto}
.det-title{font-size:1.7rem;font-weight:700;color:var(--hi);line-height:1.3;margin-bottom:14px}
.det-meta{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--bdr)}
.poc-btn{background:var(--AI);color:#000;padding:8px 16px;border-radius:6px;font-family:var(--mono);font-weight:700;font-size:.78rem}
.atomic-list{background:var(--surf);border:1px solid var(--good);border-radius:6px;padding:12px 16px;margin:16px 0;font-size:.85rem}
.atomic-list h4{color:var(--good);font-family:var(--mono);font-size:.78rem;margin-bottom:6px}
.atomic-list a{display:block;margin:3px 0;font-family:var(--mono);font-size:.78rem}
.critic-bar{background:var(--surf);border:1px solid var(--bdr);border-radius:6px;padding:10px 14px;margin:14px 0;font-family:var(--mono);font-size:.7rem;display:flex;gap:14px;flex-wrap:wrap}
.critic-bar b{color:var(--hi)}
.md h1{display:none}
.md h2{font-size:1.15rem;font-weight:700;color:var(--hi);margin:32px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--bdr)}
.md h3{font-size:.98rem;font-weight:700;color:var(--acc2);margin:20px 0 8px}
.md h4{font-size:.92rem;font-weight:700;color:var(--acc);margin:16px 0 6px}
.md p{margin:10px 0}
.md ul,.md ol{padding-left:24px;margin:10px 0}
.md li{margin:5px 0}
.md strong{color:var(--hi);font-weight:700}
.md code{font-family:var(--mono);font-size:.85em;background:var(--surf2);color:var(--acc2);padding:2px 6px;border-radius:3px}
.md pre{background:#0a0d12;border:1px solid var(--bdr);border-left:3px solid var(--acc);border-radius:6px;padding:14px 16px;overflow-x:auto;margin:14px 0;position:relative}
.md pre code{background:none;color:#e0e6ed;padding:0;font-size:.82rem;line-height:1.7}
.md blockquote{border-left:3px solid var(--bdr);padding:4px 14px;color:var(--muted);margin:12px 0;background:var(--surf)}
.md table{border-collapse:collapse;margin:14px 0;font-size:.85rem;width:100%}
.md th,.md td{padding:8px 12px;border:1px solid var(--bdr);text-align:left}
.md th{background:var(--surf2);color:var(--hi)}
.copy{position:absolute;top:8px;right:8px;background:var(--surf);border:1px solid var(--bdr);color:var(--muted);font-family:var(--mono);font-size:.65rem;padding:3px 9px;border-radius:4px;cursor:pointer}
.copy:hover{color:var(--acc);border-color:var(--acc)}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:4px}
@media(max-width:600px){
  .hdr{padding:12px 14px}
  .hdr-stats{font-size:.7rem;gap:10px;width:100%;order:3}
  .ctrl{padding:0 14px}
  .feed{padding:0 14px 60px}
  .card{padding:15px 16px}
  .title{font-size:1.02rem}
  .det-body{padding:24px 16px 50px}
  .det-title{font-size:1.35rem}
}
</style>
</head>
<body>

<header class="hdr">
  <div>
    <div class="hdr-title"><span>◆</span> CIPHER v5</div>
    <div class="hdr-sub">// Multi-Agent Red Team Intel</div>
  </div>
  <div class="hdr-stats">
    <span><b id="stat-total">0</b> total</span>
    <span><b id="stat-today">0</b> today</span>
    <span><b id="stat-research">0</b> 🔍</span>
    <span><b id="stat-score">—</b> avg</span>
  </div>
  <a href="log.html" class="hdr-log">📋 実行ログ</a>
</header>

<div class="kg-toggle" onclick="document.getElementById('kg-panel').classList.toggle('open')">▶ Knowledge Graph (click to expand)</div>
<div class="kg-panel" id="kg-panel"><div class="kg-grid" id="kg-grid"></div></div>

<div class="ctrl">
  <input type="text" id="search" placeholder="🔍 タイトル・本文・CVE・APT・国・業界で検索..." autocomplete="off">
  <div class="filters">
    <button class="fbtn on" data-cat="ALL">ALL</button>
    <button class="fbtn" data-cat="MALWARE">MAL</button>
    <button class="fbtn" data-cat="INITIAL">INIT</button>
    <button class="fbtn" data-cat="POST_EXP">POST</button>
    <button class="fbtn" data-cat="AI_SEC">AI</button>
    <button class="fbtn" data-cat="RESEARCHED">🔍</button>
    <button class="fbtn" data-cat="HIGH_SCORE">★7+</button>
  </div>
</div>

<main class="feed" id="feed"></main>

<div id="det">
  <div class="det-hdr">
    <button class="back" onclick="closeDet()">← 戻る</button>
    <a id="det-src-link" class="det-src" href="#" target="_blank">元記事 ↗</a>
  </div>
  <div class="det-body"><div class="det-in" id="det-body"></div></div>
</div>

<script src="kg.js"></script>
<script src="articles.js"></script>
<script>
const db = (window.__ARTICLES__ || []).slice();
const kg = window.__KG__ || {};
const today = new Date().toISOString().slice(0,10);
let activeCat = 'ALL';

function esc(s){return (s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function cvssCls(s){const n=parseFloat(s);if(isNaN(n))return'';if(n>=9)return'crit';if(n>=7)return'high';if(n>=4)return'med';return'low'}
function pocOk(u){return u && u.startsWith('http')}
function bestScore(a){
  const cs=a.critic_scores||[];
  if(!cs.length)return null;
  return Math.max(...cs.map(c=>c.overall||0));
}
function scoreCls(s){if(s==null)return'';if(s>=7)return's-good';if(s>=5)return's-mid';return's-bad'}

// Stats
document.getElementById('stat-total').textContent=db.length;
document.getElementById('stat-today').textContent=db.filter(a=>a.date===today).length;
document.getElementById('stat-research').textContent=db.filter(a=>a.researched).length;
const scored=db.map(bestScore).filter(x=>x!=null);
document.getElementById('stat-score').textContent=scored.length?(scored.reduce((a,b)=>a+b,0)/scored.length).toFixed(1):'—';

// KG panel
const kgSections=[
  {key:'threat_actors',label:'APT / Actor'},
  {key:'malware_families',label:'Malware'},
  {key:'cves',label:'CVE'},
  {key:'techniques',label:'ATT&CK'},
  {key:'industries',label:'Industries'},
  {key:'countries',label:'Countries'},
];
const kgGrid=document.getElementById('kg-grid');
kgSections.forEach(s=>{
  const items=(kg[s.key]||[]).slice(0,8);
  if(!items.length)return;
  const div=document.createElement('div');
  div.className='kg-sec';
  div.innerHTML='<h4>'+s.label+'</h4>'+items.map(i=>
    '<div class="kg-item"><span>'+esc(i.name)+'</span><b>'+i.count+'</b></div>').join('');
  kgGrid.appendChild(div);
});

// Filters
document.querySelectorAll('.fbtn').forEach(b=>{
  b.onclick=()=>{
    document.querySelectorAll('.fbtn').forEach(x=>x.classList.remove('on'));
    b.classList.add('on');activeCat=b.dataset.cat;render();
  };
});
document.getElementById('search').oninput=render;

function render(){
  const q=document.getElementById('search').value.toLowerCase();
  const feed=document.getElementById('feed');
  feed.innerHTML='';
  const filtered=db.filter(a=>{
    if(activeCat==='RESEARCHED')return a.researched;
    if(activeCat==='HIGH_SCORE'){const s=bestScore(a);return s!=null&&s>=7}
    if(activeCat!=='ALL'&&a.category!==activeCat)return false;
    if(q){
      const hay=(a.title+' '+(a.summary_points||[]).join(' ')+' '+a.content+' '+
        (a.cve_ids||[]).join(' ')+' '+(a.threat_actor||'')+' '+(a.malware_family||'')+' '+
        (a.industries||[]).join(' ')+' '+(a.countries||[]).join(' ')).toLowerCase();
      if(!hay.includes(q))return false;
    }
    return true;
  });
  if(!filtered.length){feed.innerHTML='<div class="empty">// 該当なし</div>';return}
  const groups={};
  filtered.forEach(a=>{(groups[a.date]=groups[a.date]||[]).push(a)});
  const frag=document.createDocumentFragment();
  Object.keys(groups).sort().reverse().forEach(date=>{
    const d=document.createElement('div');
    d.className='day'+(date===today?' today':'');
    d.textContent=date===today?date+'  ● TODAY':date;
    frag.appendChild(d);
    groups[date].forEach(a=>{
      const card=document.createElement('div');
      card.className='card';
      const pts=(a.summary_points||[]).slice(0,3);
      const sumHtml=pts.length?'<ul class="sum">'+pts.map(p=>'<li>'+esc(p)+'</li>').join('')+'</ul>':'';
      const cvssH=a.cvss_score?'<span class="cvss '+cvssCls(a.cvss_score)+'">CVSS '+esc(a.cvss_score)+'</span>':'';
      const resH=a.researched?'<span class="researched">🔍</span>':'';
      const revH=(a.critic_scores||[]).length>1?'<span class="revised">↻ revised</span>':'';
      const bs=bestScore(a);
      const scH=bs!=null?'<span class="score '+scoreCls(bs)+'">★'+bs+'/10</span>':'';
      const aptH=a.threat_actor?'<span class="chip apt">'+esc(a.threat_actor)+'</span>':'';
      const malH=a.malware_family?'<span class="chip mal">'+esc(a.malware_family)+'</span>':'';
      const cveH=(a.cve_ids||[]).slice(0,3).map(c=>'<span class="chip cve">'+esc(c)+'</span>').join('');
      const mitH=(a.mitre_ids||[]).slice(0,4).map(m=>'<span class="chip mitre">'+esc(m)+'</span>').join('');
      const pocH=pocOk(a.poc_url)?'<span class="chip poc">⚡ PoC</span>':'';
      const atH=(a.atomic_files||[]).length?'<span class="chip atomic">🧪 '+a.atomic_files.length+' atomic</span>':'';
      let host=a.url;try{host=new URL(a.url).hostname.replace(/^www\./,'')}catch(e){}
      card.innerHTML=`
        <div class="card-top">
          <span class="tag ${a.category}">${a.category}</span>
          <span class="meta">${a.date}</span>
          ${resH}${revH}${cvssH}${scH}
        </div>
        <div class="title">${esc(a.title)}</div>
        ${sumHtml}
        <div class="chips">${aptH}${malH}${cveH}${mitH}${pocH}${atH}</div>
        <a class="src" href="${esc(a.url)}" target="_blank" onclick="event.stopPropagation()">📎 ${esc(host)}</a>
      `;
      card.onclick=()=>openDet(a);
      frag.appendChild(card);
    });
  });
  feed.appendChild(frag);
}

function openDet(a){
  const body=document.getElementById('det-body');
  let meta='<span class="tag '+a.category+'">'+a.category+'</span>';
  meta+='<span class="meta">'+a.date+'</span>';
  if(a.cvss_score)meta+='<span class="cvss '+cvssCls(a.cvss_score)+'">CVSS '+esc(a.cvss_score)+'</span>';
  const bs=bestScore(a);
  if(bs!=null)meta+='<span class="score '+scoreCls(bs)+'">★'+bs+'/10</span>';
  if(a.researched)meta+='<span class="researched">🔍 補完済</span>';
  if(a.threat_actor)meta+='<span class="chip apt">'+esc(a.threat_actor)+'</span>';
  if(a.malware_family)meta+='<span class="chip mal">'+esc(a.malware_family)+'</span>';
  (a.cve_ids||[]).forEach(c=>meta+='<span class="chip cve">'+esc(c)+'</span>');
  (a.mitre_ids||[]).forEach(m=>meta+='<span class="chip mitre">'+esc(m)+'</span>');
  if(pocOk(a.poc_url))meta+='<a href="'+esc(a.poc_url)+'" target="_blank" class="poc-btn">⚡ PoC</a>';

  // Critic bar
  let criticBar='';
  const cs=(a.critic_scores||[]);
  if(cs.length){
    const best=cs.reduce((x,y)=>(y.overall||0)>(x.overall||0)?y:x);
    criticBar='<div class="critic-bar">'+
      '<span>📊 Critic Review</span>'+
      '<span>Overall: <b>'+best.overall+'/10</b></span>'+
      '<span>Specificity: <b>'+best.specificity+'</b></span>'+
      '<span>Reproducibility: <b>'+best.reproducibility+'</b></span>'+
      '<span>Accuracy: <b>'+best.accuracy+'</b></span>'+
      '<span>Detection: <b>'+best.detection_quality+'</b></span>'+
      '<span>Completeness: <b>'+best.completeness+'</b></span>'+
      (cs.length>1?'<span>↻ '+(cs.length-1)+' revision(s)</span>':'')+
      '</div>';
  }

  // Atomic list
  let atomicList='';
  if((a.atomic_files||[]).length){
    atomicList='<div class="atomic-list"><h4>🧪 Atomic Red Team Tests</h4>'+
      a.atomic_files.map(f=>'<a href="'+esc(f)+'" target="_blank">▸ '+esc(f)+'</a>').join('')+
      '</div>';
  }

  const rendered=DOMPurify.sanitize(marked.parse(a.content||''));
  body.innerHTML=`
    <div class="det-title">${esc(a.title)}</div>
    <div class="det-meta">${meta}</div>
    ${criticBar}
    ${atomicList}
    <div class="md">${rendered}</div>
    <div style="margin-top:36px;padding-top:18px;border-top:1px solid var(--bdr)">
      <div style="font-family:var(--mono);font-size:.7rem;color:var(--muted);margin-bottom:6px">// SOURCE</div>
      <a href="${esc(a.url)}" target="_blank" style="font-family:var(--mono);font-size:.8rem;word-break:break-all">${esc(a.url)}</a>
    </div>
  `;
  body.querySelectorAll('pre').forEach(pre=>{
    const btn=document.createElement('button');btn.className='copy';btn.textContent='COPY';
    btn.onclick=e=>{e.stopPropagation();
      const txt=pre.querySelector('code')?.textContent||pre.textContent;
      navigator.clipboard.writeText(txt).then(()=>{btn.textContent='✓';setTimeout(()=>btn.textContent='COPY',1500)});
    };
    pre.appendChild(btn);
  });
  document.getElementById('det-src-link').href=a.url;
  document.getElementById('det').classList.add('open');
  history.pushState({view:'detail'},'');
}
function closeDet(){document.getElementById('det').classList.remove('open')}
window.onpopstate=()=>closeDet();
render();
</script>
</body>
</html>"""


def _build_log_html() -> str:
    return r"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIPHER // Run Log</title>
<style>
:root{--bg:#0f1419;--surf:#1a1f29;--surf2:#232834;--bdr:#2a3140;--text:#c8d1dc;--muted:#7a8699;--hi:#fff;--acc:#4fc3f7;--good:#66bb6a;--err:#ef5350;--mono:ui-monospace,monospace;--sans:-apple-system,'Noto Sans JP',sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);padding:30px 20px 60px}
.wrap{max-width:780px;margin:0 auto}
.back{display:inline-block;font-family:var(--mono);font-size:.75rem;color:var(--muted);border:1px solid var(--bdr);padding:6px 12px;border-radius:6px;text-decoration:none;margin-bottom:20px}
.back:hover{color:var(--acc);border-color:var(--acc)}
h1{font-size:1.6rem;font-weight:700;color:var(--hi)}
h1 span{color:var(--acc)}
.sub{font-family:var(--mono);font-size:.72rem;color:var(--muted);margin:4px 0 24px}
.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:30px}
@media(max-width:600px){.grid{grid-template-columns:1fr 1fr}}
.stat{background:var(--surf);border:1px solid var(--bdr);border-radius:8px;padding:16px;text-align:center}
.stat b{display:block;font-size:1.4rem;color:var(--hi)}
.stat .lbl{font-family:var(--mono);font-size:.62rem;color:var(--muted);margin-top:4px}
.stat.warn b{color:var(--err)}
.stat.good b{color:var(--good)}
.row{background:var(--surf);border:1px solid var(--bdr);border-radius:6px;padding:12px 16px;margin-bottom:6px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.row.today{border-left:3px solid var(--acc)}
.dt{font-family:var(--mono);font-size:.82rem;color:var(--hi);flex:1}
.badge{font-family:var(--mono);font-size:.68rem;padding:2px 8px;border-radius:3px;font-weight:700}
.badge.new{background:rgba(79,195,247,.15);color:var(--acc)}
.badge.zero{color:var(--muted);background:var(--surf2)}
.badge.res{background:rgba(186,104,200,.15);color:#ba68c8}
.badge.score{background:rgba(102,187,106,.15);color:var(--good)}
</style></head><body>
<div class="wrap">
<a href="index.html" class="back">← CIPHER</a>
<h1><span>◆</span> Run Log</h1>
<div class="sub">// マルチエージェント実行履歴</div>
<div class="grid" id="summary"></div>
<div id="rows"></div>
</div>
<script src="log.js"></script>
<script>
const log=(window.__RUN_LOG__||[]).slice().reverse();
const today=new Date().toISOString().slice(0,10);
const totalRuns=log.length;
const totalNew=log.reduce((s,r)=>s+(r.new_articles||0),0);
const totalRes=log.reduce((s,r)=>s+(r.researched_count||0),0);
const totalPass=log.reduce((s,r)=>s+(r.critic_passed||0),0);
const avgScore=(()=>{const ss=log.map(r=>r.avg_critic_score||0).filter(x=>x>0);return ss.length?(ss.reduce((a,b)=>a+b,0)/ss.length).toFixed(1):'—'})();
document.getElementById('summary').innerHTML=`
<div class="stat"><b>${totalRuns}</b><div class="lbl">RUNS</div></div>
<div class="stat"><b>${totalNew}</b><div class="lbl">ARTICLES</div></div>
<div class="stat"><b>${totalRes}</b><div class="lbl">RESEARCHED</div></div>
<div class="stat good"><b>${totalPass}</b><div class="lbl">CRITIC PASS</div></div>
<div class="stat"><b>${avgScore}</b><div class="lbl">AVG SCORE</div></div>`;
const rows=document.getElementById('rows');
if(!log.length){rows.innerHTML='<div style="text-align:center;padding:60px;color:var(--muted);font-family:var(--mono)">// no runs</div>'}
else{
rows.innerHTML=log.map(r=>{
  const td=r.datetime_jst?.startsWith(today);
  const nb=r.new_articles>0?`<span class="badge new">+${r.new_articles}</span>`:`<span class="badge zero">±0</span>`;
  const rb=r.researched_count>0?`<span class="badge res">🔍${r.researched_count}</span>`:'';
  const sb=r.avg_critic_score>0?`<span class="badge score">★${r.avg_critic_score}</span>`:'';
  return `<div class="row ${td?'today':''}">
    <div class="dt">${r.datetime_jst}</div>
    ${nb}${rb}${sb}
    <span style="font-family:var(--mono);font-size:.68rem;color:var(--muted)">total: ${r.total_articles||'—'}</span>
  </div>`;
}).join('');
}
</script></body></html>"""


# ============================================================================
# ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    db = load_db()
    kg = load_kg()
    existing_urls = {a["url"] for a in db}
    print(f"[INIT] loaded DB: {len(db)} articles, KG: "
          f"{sum(len(v) for v in kg.get('entities',{}).values())} entities")

    new_data, run_stats = fetch_and_analyze(existing_urls, db)

    # Update knowledge graph with new articles
    for entry in new_data:
        triage_proxy = {
            "threat_actor":   entry.get("threat_actor", ""),
            "malware_family": entry.get("malware_family", ""),
            "cve_ids":        entry.get("cve_ids", []),
            "mitre_ids":      entry.get("mitre_ids", []),
        }
        update_kg(kg, entry, triage_proxy)
    save_kg(kg)
    print(f"[KG] saved: {sum(len(v) for v in kg['entities'].values())} entities, "
          f"{len(kg['relationships'])} relationships")

    db = update_db(db, new_data)
    run_log = load_run_log()
    run_log = append_run_log(run_log, len(new_data), len(db), run_stats)
    generate_html(db, run_log, kg)

    print("\n✓ Run complete")
