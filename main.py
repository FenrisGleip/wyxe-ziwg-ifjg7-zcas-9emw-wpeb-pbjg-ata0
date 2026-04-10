# RED-TACTICAL INTELLIGENCE AGENT v4.0
# 主な改善点:
#   - エージェント調査フェーズ追加: 情報不十分な記事をLLMに捨てさせず、
#     NVD API / Tavily追加検索 / GitHub検索で情報補完してからレポート化
#   - 本文抽出ヒューリスティックの改善 (<article>/<main>タグ優先)
#   - プロンプトを単一系統に統合、Gemini max_tokens を 8192 に増量
#   - research_log をレポートに埋め込み、情報ソースを透明化
#   - MIN_REPORT_LEN を 800 に緩和、補完後に再生成する二段構成
import os
import json
import re
import time
import hashlib
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from html import unescape
from groq import Groq
from datetime import datetime, timezone, timedelta

try:
    from tavily import TavilyClient
    _TAVILY_AVAILABLE = True
except ImportError:
    _TAVILY_AVAILABLE = False

try:
    import google.generativeai as genai
    _GEMINI_AVAILABLE = True
except ImportError:
    _GEMINI_AVAILABLE = False

JST = timezone(timedelta(hours=9))
def now_jst():
    return datetime.now(JST)

# ─────────────────────────────────────────────
# 設定
# ─────────────────────────────────────────────
GROQ_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_KEY:
    raise RuntimeError("GROQ_API_KEY が未設定です。GitHub Secrets を確認してください。")
groq_client = Groq(api_key=GROQ_KEY)

TAVILY_KEY = os.getenv("TAVILY_API_KEY")
tavily_client = TavilyClient(api_key=TAVILY_KEY) if (_TAVILY_AVAILABLE and TAVILY_KEY) else None

GEMINI_KEY = os.getenv("GEMINI_API_KEY")
if _GEMINI_AVAILABLE and GEMINI_KEY:
    genai.configure(api_key=GEMINI_KEY)
    gemini_model = genai.GenerativeModel("gemini-2.5-flash-lite")
    print("[INIT] ✓ Gemini 2.5 Flash 利用可能")
else:
    gemini_model = None
    if not _GEMINI_AVAILABLE:
        print("[INIT] ⚠ google-generativeai が未インストール — workflow.yml で pip install を確認")
    elif not GEMINI_KEY:
        print("[INIT] ⚠ GEMINI_API_KEY が未設定 — GitHub Secrets を確認")
    print("[INIT] ⚠ Geminiが使えないためGroqのみで実行します(TPD枯渇リスク大)")

if tavily_client:
    print("[INIT] ✓ Tavily 利用可能")
else:
    if not _TAVILY_AVAILABLE:
        print("[INIT] ⚠ tavily-python が未インストール")
    elif not TAVILY_KEY:
        print("[INIT] ⚠ TAVILY_API_KEY が未設定")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # あれば検索レートが上がる(任意)

MASTER_DATA     = "all_articles.json"
OUTPUT_HTML     = "index.html"
MAX_DB_ENTRIES  = 200
MIN_REPORT_LEN  = 600   # さらに緩和: Gemini主体なら品質は担保されるが、短い速報も許容
MIN_SOURCE_LEN  = 400
MAX_RETRIES     = 1     # 3 → 1: 品質不足時のリトライは TPD を無駄食いするので廃止
SLEEP_BETWEEN_REQ = 6.0

# Gemini をレポート生成の主役に。Groq はスクリーニング専用 (軽量・高速)
PRIMARY_MODEL  = "llama-3.3-70b-versatile"  # 安定モデルに切替
FALLBACK_MODEL = "meta-llama/llama-4-scout-17b-16e-instruct"

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0.0.0 Safari/537.36")

# ─────────────────────────────────────────────
# RSSフィード定義 (カテゴリ別)
# ─────────────────────────────────────────────
RSS_FEEDS = {
    "MALWARE": [
        "https://securelist.com/feed/",
        "https://cybersecuritynews.com/feed/",
        "https://blog.malwarebytes.com/feed/",
        "https://isc.sans.edu/rssfeed_full.xml",
        "https://www.helpnetsecurity.com/feed/",
    ],
    "INITIAL": [
        "https://securityaffairs.com/feed",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://www.zerodayinitiative.com/rss/published/",
        "https://seclists.org/rss/fulldisclosure.rss",
    ],
    "POST_EXP": [
        "https://www.cyderes.com/feed/",
        "https://research.checkpoint.com/feed/",
        "https://www.elastic.co/security-labs/rss/feed.xml",
        "https://www.redpacketsecurity.com/feed/",
        "https://bishopfox.com/blog/feed",
    ],
    "AI_SEC": [
        "https://blog.trailofbits.com/feed/",
        "https://simonwillison.net/atom/everything/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.microsoft.com/en-us/security/blog/feed/",
        "https://research.checkpoint.com/feed/",
    ],
}

TAVILY_QUERIES = {
    "MALWARE":  ["new malware technical analysis loader shellcode EDR bypass 2026"],
    "INITIAL":  ["zero-day PoC exploit published unpatched Windows Linux 2026",
                 "CVE 2026 proof of concept GitHub exploit released"],
    "POST_EXP": ["new privilege escalation technique Windows Active Directory 2026"],
    "AI_SEC":   ["LLM AI agent attack jailbreak prompt injection new technique 2026"],
}
TAVILY_MAX_RESULTS = 3
MAX_ITEMS_PER_FEED = 5
MAX_PER_CATEGORY   = 4

# ─────────────────────────────────────────────
# プロンプト (カテゴリ文脈)
# ─────────────────────────────────────────────
CATEGORY_CONTEXT = {
    "MALWARE": """
MALWARE ANALYSIS FOCUS:
- Internal loader mechanism: shellcode/PE decryption, mapping, execution (VirtualAlloc, WriteProcessMemory, CreateRemoteThread etc.)
- Obfuscation: exact algorithm (XOR key, RC4, AES-CBC with IV), key storage
- C2 protocol: HTTP/DNS/custom, beaconing interval, jitter, encoding, URI patterns
- Persistence: exact registry key, scheduled task XML, WMI subscription
- EDR evasion: AMSI bypass, ETW patching, direct syscalls, process hollowing target
""",
    "INITIAL": """
INITIAL ACCESS FOCUS:
- Root cause: exact vulnerable code path, which parameter/header/field triggers the bug
- Vulnerability class: buffer overflow offset, SQLi context, deserialization gadget chain, auth bypass condition
- Affected versions: exact version strings, patch commit/advisory reference
- Exploit trigger: HTTP method, endpoint path, required headers/auth state, payload format
- Bypass conditions: WAF bypass, auth prerequisite, race condition window
""",
    "POST_EXP": """
POST-EXPLOITATION FOCUS:
- Privilege escalation: specific misconfiguration (SeImpersonatePrivilege, weak ACL, unquoted path, token abuse)
- Lateral movement: exact protocol (SMB/WinRM/DCOM), credential type, required ports
- Credential dumping: LSASS access (MiniDump, direct read, PPL bypass), SAM/NTDS extraction
- AD attack: Kerberoastable SPN, RBCD prerequisite, DCSync rights
- EDR evasion: injection target process, LOLBAS binary, obfuscation
""",
    "AI_SEC": """
AI/LLM ATTACK FOCUS:
- Attack vector: injection point (system prompt, tool description, RAG content, fine-tuning data, API, MCP, agent memory)
- Attack mechanism: context confusion, role override, indirect injection, data poisoning, adversarial input
- Concrete payload: actual strings, templates, configurations triggering the behavior
- Impact: data exfiltration, jailbreak, agent hijack, SSRF, tool misuse, model theft
- Bypass: how safety filters are circumvented
- PoC reproducibility: tools, configs, payload templates a red teamer can run tomorrow
""",
}

# ─────────────────────────────────────────────
# プロンプトビルダ
# ─────────────────────────────────────────────
def build_screening_prompt(content: str, category: str) -> str:
    """Groq 軽量スクリーニング: 新規性スコアと要点抽出のみ"""
    ctx = CATEGORY_CONTEXT.get(category, "")
    return f"""あなたはオフェンシブセキュリティの専門家です。
以下の記事を評価し、JSONのみを出力してください。説明・マークダウン不要。
{ctx}
新規性スコア (1-5):
  5 = 新規CVE・新技術・オリジナルリサーチ・新バイパス
  4 = 既知技術の有意な新バリアント
  3 = 既知手法の具体的適用事例
  2 = 既知手法の概説
  1 = 教育コンテンツ・マーケティング

選定基準:
- 攻撃者が何を達成できるか具体的か
- テスターがラボで試せる手順が推測できるか

スコア 1-2 → {{"skip": true, "reason": "除外理由"}}
スコア 3-5 → {{"skip": false, "score": <数値>, "title": "30字以内日本語", "cve_ids": ["CVE-2024-XXXX"], "poc_url": "GitHub URL か空", "cvss_score": "数値 or 空", "mitre_ids": ["T1566.001"], "summary_points": ["要点1 100字以内", "要点2", "要点3"], "info_density": "high|medium|low", "research_keywords": ["追加調査用の英語キーワード 2-4個"]}}

info_density 判定基準:
- high: PoC/コード例/IoC/具体的API呼び出し/詳細な手順が記事に含まれる
- medium: 概要と一部技術詳細はあるが再現手順は不足
- low: 速報・概要のみ、技術詳細ほぼなし (→ エージェント追加調査が必要)

例外: 以下はスコア2でも skip:false:
- 未パッチ・ゼロデイ PoC 公開
- 新CVE に対する機能する Exploit 公開
- ITW 悪用確認

SOURCE:
{content[:3500]}"""


def build_report_prompt(content: str, category: str, research_context: str = "") -> str:
    """Gemini/Groq 詳細レポート生成"""
    ctx = CATEGORY_CONTEXT.get(category, "")
    research_block = ""
    if research_context:
        research_block = f"""

━━━ 追加調査情報 (AIエージェントが記事以外から補完) ━━━
以下は元記事の情報不足を補うため、NVD / Tavily / GitHub から収集した追加情報です。
この情報を積極的に統合し、記事単独では再現困難だった部分を補完したレポートを作成してください。
ただし各情報の出所は [NVD]/[Tavily]/[GitHub] として必ず明記してください。

{research_context[:6000]}
━━━ 追加調査情報ここまで ━━━
"""
    return f"""あなたはオフェンシブセキュリティの専門家 (レッドチームオペレーター歴15年) です。
社内のレッドチームテスター向けに、攻撃を再現するための内部技術レポートを作成してください。

対象読者: 明日ラボ環境でこの攻撃を試みるテスター。曖昧な記述は不要。
{ctx}
{research_block}

━━━ 思考ステップ (出力不要) ━━━
1. 攻撃者は何を達成できるか?
2. 成立の前提条件 (権限/アクセス/バージョン) は?
3. 既存の検知・防御はどこで効き、どこで効かないか?
4. ラボ再現の最低手順は?
5. 記事と追加調査情報を統合し、専門知識で補える詳細は?

━━━ レポート作成ルール ━━━
【言語】全セクション日本語。ツール名・CVE・API・コマンドのみ英語維持。
【完結性】全セクション最後まで書く。途中省略禁止。
【情報源】追加調査情報を使った箇所は [NVD]/[Tavily追加調査]/[GitHub] のタグを付ける。
【推測】記事・追加情報にない部分を専門知識で補う場合は [推測] を付記。

## 概要
1-2文の核心サマリ: 「〇〇が報告された。重要なのは〜という点である」
技術的要点 (箇条書き 3-5): 各点「何が・どのように・なぜ危険か」1文
**🆕 新規性・差異化ポイント:** (太字) 従来手法との差異
属性: APT / Malware / CVE / IoC (不明は「記載なし」)

## 脆弱性・脅威の技術的メカニズム
- 脆弱コンポーネントと悪用の仕組みを技術的に説明
- API呼び出し・メモリ操作・プロトコルフィールド・コードパス具体的に
- CVE: 脆弱コードパス・トリガー条件
- マルウェア: ロード→復号→実行の内部動作を段階的に
- 最低500字。「高度な」「巧妙な」等の抽象表現禁止

## 攻撃再現ガイド
### 前提条件・環境
OS・権限・必要ツール・攻撃対象の状態

### 攻撃フロー
フェーズごとに:
  【操作】何を・どこで・どのように
  【目的】攻撃上なぜ必要か
  【結果】何が起きるか・何が得られるか
  情報源タグを必ず付ける ([記事] / [NVD] / [Tavily追加調査] / [GitHub] / [推測])

### 実装・設定の詳細
CLSID・API呼び出し・レジストリキー・ファイルパス等を
コードブロック付きで説明

## IoC・痕跡情報
ハッシュ・C2・URI・User-Agent・証明書等。なければ「記載なし」

## MITRE ATT&CK マッピング
記事の手法に対応するIDのみ (サブテクニックID + 説明)

## 検知・防御策
**防御策** (最低3項目・具体的な設定変更形式)
**検知策**: 検知ポイント + Sigma/KQL/SPL クエリ (具体的IoC含む)

## 🔍 情報ソースサマリ
このレポートで使用した情報源を箇条書き:
- [記事] 元記事から取得した情報の種類
- [NVD] 取得したCVE詳細 (該当時)
- [Tavily追加調査] 補完した情報の種類 (該当時)
- [GitHub] 参照したPoC/コード (該当時)
- [推測] 専門知識で補完した箇所

OUTPUT: ONLY valid JSON. No markdown fences. Use \\n for newlines in report field.
{{"title":"30字以内日本語","summary_points":["要点1","要点2","要点3"],"poc_url":"GitHub URL or 空","cvss_score":"数値 or 空","mitre_ids":["T1566.001"],"cve_ids":["CVE-2024-XXXX"],"report":"## 概要\\n..."}}

SOURCE ARTICLE:
{content[:6000]}"""


# ─────────────────────────────────────────────
# JSON 抽出
# ─────────────────────────────────────────────
def extract_json(raw: str) -> dict | None:
    if not raw:
        return None
    # <think> ブロック除去
    cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    # ```json フェンス除去
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()

    # パターン1: そのままパース
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # パターン2: 最初の { から最後の }
    bs, be = cleaned.find("{"), cleaned.rfind("}")
    if bs != -1 and be > bs:
        try:
            return json.loads(cleaned[bs:be+1])
        except json.JSONDecodeError:
            pass

    # パターン3: JSON文字列内の生改行をエスケープしてリトライ
    if bs != -1 and be > bs:
        candidate = cleaned[bs:be+1]
        # 文字列リテラル内の改行のみ \n に置換 (単純ヒューリスティック)
        fixed = re.sub(
            r'("(?:[^"\\]|\\.)*")',
            lambda m: m.group(1).replace("\n", "\\n").replace("\r", ""),
            candidate,
            flags=re.DOTALL,
        )
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
    return None


def validate_result(res: dict) -> bool:
    if not res or res.get("skip"):
        return False
    if not res.get("title") or len(res["title"]) < 5:
        return False
    if not res.get("report") or len(res["report"]) < MIN_REPORT_LEN:
        return False
    poc = res.get("poc_url", "")
    if poc and not poc.startswith("http"):
        res["poc_url"] = ""
    cvss = res.get("cvss_score", "")
    if cvss:
        try:
            float(cvss)
        except ValueError:
            res["cvss_score"] = ""
    raw_ids = res.get("mitre_ids", [])
    res["mitre_ids"] = [i for i in raw_ids if re.match(r"T\d{4}", str(i))][:5]
    pts = res.get("summary_points", [])
    res["summary_points"] = [p[:100] for p in pts if p][:4]
    return True


# ─────────────────────────────────────────────
# LLM 呼び出し
# ─────────────────────────────────────────────
def call_gemini(prompt: str) -> dict | None:
    if not gemini_model:
        return None
    for attempt in range(2):
        try:
            response = gemini_model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.2,
                    max_output_tokens=4096,
                )
            )
            raw = response.text
            result = extract_json(raw)
            if result and validate_result(result):
                return result
            if result and result.get("skip"):
                return None
            print(f"    ✗ [Gemini] attempt {attempt+1} — 品質不足")
            return None
        except Exception as e:
            err = str(e)
            if "429" in err or "quota" in err.lower() or "rate" in err.lower():
                wait = 30 if attempt == 0 else 60
                print(f"    ✗ [Gemini] レート制限 — {wait}秒待機...")
                time.sleep(wait)
            else:
                print(f"    ✗ [Gemini] {e}")
                return None
    return None


_tpd_hit_models: set = set()

def call_llm_report(prompt: str) -> dict | None:
    """Groq フォールバックレポート生成 (Gemini未設定時のみ)"""
    global _tpd_hit_models
    _RATE_LIMIT_PAT = re.compile(r"try again in ([\d.]+)([smh])")

    def _parse_wait(err_str: str) -> float:
        m = _RATE_LIMIT_PAT.search(str(err_str))
        if not m:
            return 5.0
        val, unit = float(m.group(1)), m.group(2)
        return val * {"s": 1, "m": 60, "h": 3600}.get(unit, 1)

    for model in [PRIMARY_MODEL, FALLBACK_MODEL]:
        if model in _tpd_hit_models:
            continue
        try:
            resp = groq_client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=3500,
            )
            result = extract_json(resp.choices[0].message.content)
            if result and result.get("skip"):
                return None
            if result and validate_result(result):
                print(f"    ✓ [{model}] レポート生成完了")
                return result
            print(f"    ✗ [{model}] 品質不足 — 次モデルへ")
        except Exception as e:
            err = str(e)
            if "decommissioned" in err:
                print(f"    ✗ [{model}] decommissioned")
            elif "rate_limit_exceeded" in err:
                if "tokens per day" in err.lower() or "tpd" in err.lower():
                    print(f"    ✗ [{model}] TPD 上限")
                    _tpd_hit_models.add(model)
                else:
                    wait = min(_parse_wait(err), 30)
                    print(f"    ✗ [{model}] TPM — {wait:.0f}秒待機")
                    time.sleep(wait)
            else:
                print(f"    ✗ [{model}] {e}")
    return None


def call_llm_screening(prompt: str) -> dict | None:
    """スクリーニング専用: skip 判定結果もそのまま返す (validate はしない)"""
    global _tpd_hit_models
    for model in [PRIMARY_MODEL, FALLBACK_MODEL]:
        for attempt in range(2):
            try:
                resp = groq_client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=1500,
                )
                result = extract_json(resp.choices[0].message.content)
                if result is not None:
                    return result
                time.sleep(1)
            except Exception as e:
                err = str(e)
                if "tokens per day" in err.lower() or "tpd" in err.lower():
                    _tpd_hit_models.add(model)
                    break
                time.sleep(2)
    return None


# ─────────────────────────────────────────────
# エージェント調査フェーズ (情報補完)
# ─────────────────────────────────────────────
def extract_cve_ids(text: str) -> list[str]:
    """テキストから CVE ID を抽出して重複除去"""
    ids = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    seen = set()
    out = []
    for i in ids:
        u = i.upper()
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:5]  # 最大5件


def fetch_nvd_cve(cve_id: str) -> str:
    """NVD API から CVE 詳細を取得して要約文字列を返す"""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return ""
        cve = vulns[0].get("cve", {})
        descs = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        # CVSS
        metrics = cve.get("metrics", {})
        cvss_str = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                cvss_str = f"CVSS {m.get('baseScore','?')} ({m.get('baseSeverity','?')}) vector={m.get('vectorString','?')}"
                break

        # CWE
        weaknesses = cve.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"):
                    cwes.append(d["value"])
        cwe_str = ", ".join(cwes[:3]) if cwes else ""

        # 参考リンク (tag ありを優先)
        refs = cve.get("references", [])
        ref_lines = []
        for r in refs[:8]:
            tags = ",".join(r.get("tags", []))
            ref_lines.append(f"  - {r.get('url','')} [{tags}]")

        out = f"[NVD] {cve_id}\n"
        out += f"  Description: {desc_en[:800]}\n"
        if cvss_str:
            out += f"  {cvss_str}\n"
        if cwe_str:
            out += f"  CWE: {cwe_str}\n"
        if ref_lines:
            out += "  References:\n" + "\n".join(ref_lines) + "\n"
        return out
    except Exception as e:
        print(f"    ✗ NVD取得失敗 ({cve_id}): {e}")
        return ""


def search_github_poc(keyword: str) -> str:
    """GitHub で PoC/Exploit リポジトリを検索して要約を返す"""
    try:
        q = urllib.parse.quote(f"{keyword} PoC exploit")
        url = f"https://api.github.com/search/repositories?q={q}&sort=updated&per_page=5"
        headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        items = data.get("items", [])[:5]
        if not items:
            return ""
        lines = [f"[GitHub] search: {keyword}"]
        for it in items:
            desc = (it.get("description") or "").strip()[:150]
            lines.append(f"  - {it.get('html_url','')} ⭐{it.get('stargazers_count',0)} {desc}")
        return "\n".join(lines) + "\n"
    except Exception as e:
        print(f"    ✗ GitHub検索失敗 ({keyword}): {e}")
        return ""


def tavily_deep_search(query: str, max_results: int = 3) -> str:
    """Tavily で技術詳細を追加検索して本文要約を返す"""
    if not tavily_client:
        return ""
    try:
        results = tavily_client.search(
            query=query,
            search_depth="advanced",
            max_results=max_results,
        ).get("results", [])
        if not results:
            return ""
        lines = [f"[Tavily追加調査] query: {query}"]
        for r in results:
            content = (r.get("content") or "")[:500]
            lines.append(f"  URL: {r.get('url','')}")
            lines.append(f"  {content}")
        return "\n".join(lines) + "\n"
    except Exception as e:
        print(f"    ✗ Tavily詳細検索失敗 ({query[:40]}): {e}")
        return ""


def agent_research(screening: dict, original_content: str, category: str) -> str:
    """
    情報不足の記事に対し、エージェントが追加情報を収集する。
    戻り値は LLM プロンプトに埋め込める research_context 文字列。
    """
    print(f"    🔍 エージェント調査フェーズ開始...")
    research_parts = []

    # 1. CVE ID を抽出 → NVD から詳細取得
    cve_ids = screening.get("cve_ids") or []
    if not cve_ids:
        cve_ids = extract_cve_ids(original_content + " " + screening.get("title", ""))
    for cid in cve_ids[:3]:
        print(f"      [NVD] fetching {cid}")
        nvd_info = fetch_nvd_cve(cid)
        if nvd_info:
            research_parts.append(nvd_info)
        time.sleep(0.5)

    # 2. Tavily で技術詳細を追加検索
    keywords = screening.get("research_keywords") or []
    if not keywords and screening.get("title"):
        # タイトルから簡易キーワード生成
        keywords = [screening["title"]]
    for kw in keywords[:2]:
        if cve_ids:
            q = f"{cve_ids[0]} technical analysis exploit PoC"
        else:
            q = f"{kw} technical analysis exploit"
        print(f"      [Tavily] {q[:60]}")
        tv_info = tavily_deep_search(q, max_results=2)
        if tv_info:
            research_parts.append(tv_info)
        time.sleep(0.5)

    # 3. GitHub で PoC 検索
    if cve_ids:
        for cid in cve_ids[:2]:
            print(f"      [GitHub] {cid}")
            gh_info = search_github_poc(cid)
            if gh_info:
                research_parts.append(gh_info)
            time.sleep(0.5)

    merged = "\n".join(research_parts)
    if merged:
        print(f"    ✓ 追加情報 {len(merged)} 文字収集")
    else:
        print(f"    ✗ 追加情報収集できず")
    return merged


# ─────────────────────────────────────────────
# 重複チェック
# ─────────────────────────────────────────────
def title_hash(title: str) -> str:
    normalized = re.sub(r"[^\w]", "", title).lower()
    return hashlib.md5(normalized.encode()).hexdigest()[:8]


# ─────────────────────────────────────────────
# RSS / 本文取得
# ─────────────────────────────────────────────
def fetch_rss(feed_url: str, max_items: int = 5) -> list[dict]:
    try:
        req = urllib.request.Request(
            feed_url,
            headers={"User-Agent": USER_AGENT,
                     "Accept": "application/rss+xml, application/xml, text/xml, */*"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
        root = ET.fromstring(raw)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        items = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)

        def parse_pubdate(s: str):
            if not s:
                return None
            for fmt in [
                "%a, %d %b %Y %H:%M:%S %z",
                "%a, %d %b %Y %H:%M:%S GMT",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%SZ",
            ]:
                try:
                    dt = datetime.strptime(s.strip(), fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue
            return None

        # RSS 2.0
        for item in root.findall(".//item")[:max_items * 3]:
            title = item.findtext("title", "").strip()
            url = item.findtext("link", "").strip()
            pub_raw = item.findtext("pubDate", "") or item.findtext("dc:date", "")
            pub_dt = parse_pubdate(pub_raw)
            if pub_dt and pub_dt < cutoff:
                continue
            summary = item.findtext("description", "") or item.findtext("summary", "")
            content_el = item.find("{http://purl.org/rss/1.0/modules/content/}encoded")
            body = content_el.text if content_el is not None else summary
            body = unescape(re.sub(r"<[^>]+>", " ", body or "")).strip()
            if url:
                items.append({"url": url, "title": title, "content": body})
            if len(items) >= max_items:
                break

        # Atom
        if not items:
            for entry in root.findall("atom:entry", ns)[:max_items * 3]:
                title = entry.findtext("atom:title", "", ns).strip()
                link_el = entry.find("atom:link", ns)
                url = link_el.get("href", "") if link_el is not None else ""
                pub_raw = entry.findtext("atom:updated", "", ns) or entry.findtext("atom:published", "", ns)
                pub_dt = parse_pubdate(pub_raw)
                if pub_dt and pub_dt < cutoff:
                    continue
                summary = entry.findtext("atom:summary", "", ns) or entry.findtext("atom:content", "", ns)
                body = unescape(re.sub(r"<[^>]+>", " ", summary or "")).strip()
                if url:
                    items.append({"url": url, "title": title, "content": body})
                if len(items) >= max_items:
                    break
        return items
    except Exception as e:
        print(f"  ✗ RSS取得失敗 ({feed_url[:50]}): {e}")
        return []


def fetch_article_body(url: str) -> str:
    """
    改善版: <article>/<main>優先 → <div>内の<p>密度スコアリング → 全<p>集約
    ナビゲーション・広告ノイズを軽減。
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")

        # script/style/nav/footer/aside/header を先に削除
        for tag in ("script", "style", "nav", "footer", "aside", "header", "form"):
            raw = re.sub(rf"<{tag}[^>]*>.*?</{tag}>", " ", raw, flags=re.DOTALL | re.IGNORECASE)
        raw = re.sub(r"<!--.*?-->", " ", raw, flags=re.DOTALL)

        # <pre><code> は改行保持で抽出 (IoC/コマンド例)
        codes = re.findall(r"<(?:pre|code)[^>]*>(.*?)</(?:pre|code)>", raw, re.DOTALL | re.IGNORECASE)
        code_text = "\n".join(unescape(re.sub(r"<[^>]+>", "", c)) for c in codes)[:2000]

        def _clean(s: str) -> str:
            s = re.sub(r"<[^>]+>", " ", s)
            s = unescape(s)
            s = re.sub(r"\s{2,}", " ", s).strip()
            return s

        # 戦略1: <article> タグ
        m = re.search(r"<article[^>]*>(.*?)</article>", raw, re.DOTALL | re.IGNORECASE)
        if m:
            body = _clean(m.group(1))
            if len(body) >= 300:
                return (body + ("\n\nCODE:\n" + code_text if code_text else ""))[:10000]

        # 戦略2: <main> タグ
        m = re.search(r"<main[^>]*>(.*?)</main>", raw, re.DOTALL | re.IGNORECASE)
        if m:
            body = _clean(m.group(1))
            if len(body) >= 300:
                return (body + ("\n\nCODE:\n" + code_text if code_text else ""))[:10000]

        # 戦略3: class/id に "content|post|entry|article|body" を含む div を優先
        candidates = re.findall(
            r'<div[^>]*(?:class|id)\s*=\s*"[^"]*(?:content|post|entry|article|body|main)[^"]*"[^>]*>(.*?)</div>',
            raw, re.DOTALL | re.IGNORECASE
        )
        if candidates:
            best = max(candidates, key=lambda c: len(_clean(c)))
            body = _clean(best)
            if len(body) >= 300:
                return (body + ("\n\nCODE:\n" + code_text if code_text else ""))[:10000]

        # 戦略4: 全<p>タグを集約(ナビなどは上で削除済み)
        paras = re.findall(r"<p[^>]*>(.*?)</p>", raw, re.DOTALL | re.IGNORECASE)
        if paras:
            body = _clean(" ".join(paras))
            if len(body) >= 200:
                return (body + ("\n\nCODE:\n" + code_text if code_text else ""))[:10000]

        # 戦略5: 最終フォールバック — 全体を剥がす
        body = _clean(raw)
        return (body[:8000] + ("\n\nCODE:\n" + code_text if code_text else ""))[:10000]
    except Exception as e:
        print(f"  ✗ 本文取得失敗 ({url[:50]}): {e}")
        return ""


def fetch_tavily(query: str, max_results: int = 3) -> list[dict]:
    if not tavily_client:
        return []
    try:
        results = tavily_client.search(
            query=query,
            search_depth="advanced",
            max_results=max_results,
            days=3,
        )["results"]
        items = []
        for r in results:
            url = r.get("url", "")
            content = r.get("content", "")
            title = r.get("title", "")
            if url and len(content) >= 200:
                items.append({"url": url, "title": title, "content": content})
        return items
    except Exception as e:
        print(f"  ✗ Tavily検索エラー ({query[:40]}): {e}")
        return []


# ─────────────────────────────────────────────
# 記事処理コア (統一関数: RSS/Tavily 両方で使用)
# ─────────────────────────────────────────────
def process_article(url: str, title: str, content: str, category: str,
                    seen_title_hashes: set) -> dict | None:
    """
    1記事を処理してDBエントリを返す。失敗時 None。
    情報密度が低ければエージェント調査フェーズを実行。
    """
    # 1. 本文が短ければ直接フェッチ
    if len(content) < 1500:
        print(f"    本文補完フェッチ...")
        fetched = fetch_article_body(url)
        if len(fetched) > len(content):
            content = fetched

    if len(content) < 150:
        print(f"    skip (本文不足)")
        return None

    # 2. スクリーニング (Groq)
    screening = call_llm_screening(build_screening_prompt(content, category))
    if screening is None:
        print(f"    skip (スクリーニング失敗)")
        return None
    if screening.get("skip"):
        print(f"    skip (新規性なし): {screening.get('reason','')}")
        return None

    print(f"    ✓ スクリーニング OK (score={screening.get('score','?')}, density={screening.get('info_density','?')})")

    # 3. 情報密度判定 → 不足ならエージェント調査
    density = screening.get("info_density", "medium")
    research_context = ""
    # low または (medium かつ 本文400字未満) なら調査を実行
    if density == "low" or (density == "medium" and len(content) < MIN_SOURCE_LEN):
        research_context = agent_research(screening, content, category)

    # CVE が検出されたが密度 high でも、追加情報があると質が上がるので軽く取得
    elif screening.get("cve_ids"):
        for cid in screening["cve_ids"][:2]:
            nvd_info = fetch_nvd_cve(cid)
            if nvd_info:
                research_context += nvd_info
            time.sleep(0.5)

    # 4. レポート生成 (Gemini 必須 — Groq は TPD 枯渇しやすいため使わない)
    if gemini_model:
        result = call_gemini(build_report_prompt(content, category, research_context))
        if result is None:
            print(f"    ✗ Gemini レポート生成失敗 — スキップ")
            return None
        print(f"    ✓ [Gemini] レポート生成完了")
    else:
        # Gemini 未設定時のみ Groq でフォールバック (非推奨)
        print(f"    ⚠ Gemini未設定のためGroqでレポート生成(非推奨)")
        result = call_llm_report(build_report_prompt(content, category, research_context))
        if result is None:
            return None

    # スクリーニング結果で補完
    result.setdefault("title", screening.get("title", ""))
    result.setdefault("poc_url", screening.get("poc_url", ""))
    result.setdefault("cvss_score", screening.get("cvss_score", ""))
    result.setdefault("mitre_ids", screening.get("mitre_ids", []))
    result.setdefault("summary_points", screening.get("summary_points", []))
    if "cve_ids" not in result:
        result["cve_ids"] = screening.get("cve_ids", [])

    # タイトル重複
    th = title_hash(result["title"])
    if th in seen_title_hashes:
        print(f"    ✗ タイトル重複: {result['title'][:40]}")
        return None
    seen_title_hashes.add(th)

    return {
        "date":           now_jst().strftime("%Y-%m-%d"),
        "category":       category,
        "title":          result["title"],
        "summary_points": result.get("summary_points", []),
        "poc_url":        result.get("poc_url", ""),
        "cvss_score":     result.get("cvss_score", ""),
        "mitre_ids":      result.get("mitre_ids", []),
        "cve_ids":        result.get("cve_ids", []),
        "content":        result["report"],
        "url":            url,
        "researched":     bool(research_context),  # 調査フェーズ実行フラグ
    }


# ─────────────────────────────────────────────
# 情報収集メイン
# ─────────────────────────────────────────────
def fetch_and_analyze(existing_urls: set[str]) -> tuple[list[dict], dict]:
    print("=" * 50)
    print("  RED-INTEL AGENT v4.0 — 調査フェーズ対応")
    print("=" * 50)
    print(f"  既存DB URL数: {len(existing_urls)}")

    global _tpd_hit_models
    _tpd_hit_models = set()

    new_articles: list[dict] = []
    seen_urls = set(existing_urls)
    seen_title_hashes = set()
    tpd_exhausted = False

    run_stats = {
        "tpd_exhausted": False,
        "feed_errors":   [],
        "researched_count": 0,
        "categories":    {}
    }

    for cat_id, feeds in RSS_FEEDS.items():
        cat_stats = {"adopted": 0, "skipped_dup": 0, "skipped_low": 0,
                     "researched": 0, "tpd_hit": False, "feed_errors": []}
        run_stats["categories"][cat_id] = cat_stats

        if tpd_exhausted:
            print(f"  [{cat_id}] TPD上限のためスキップ")
            cat_stats["tpd_hit"] = True
            continue

        print(f"\n[{cat_id}] ───────────────────────")
        cat_count = 0

        for feed_url in feeds:
            if cat_count >= MAX_PER_CATEGORY:
                break
            print(f"  RSS: {feed_url[:60]}")
            items = fetch_rss(feed_url, MAX_ITEMS_PER_FEED)
            print(f"    取得: {len(items)} 件")
            if not items:
                cat_stats["feed_errors"].append(feed_url.split("/")[2] if "/" in feed_url else feed_url)

            for item in items:
                if cat_count >= MAX_PER_CATEGORY:
                    break
                url = item["url"]
                if url in seen_urls:
                    print(f"    skip (重複URL): {url[:55]}")
                    cat_stats["skipped_dup"] += 1
                    continue
                seen_urls.add(url)
                print(f"  → {url[:70]}")

                entry = process_article(url, item["title"], item["content"], cat_id, seen_title_hashes)

                if len(_tpd_hit_models) >= 2:
                    tpd_exhausted = True
                    run_stats["tpd_exhausted"] = True
                    cat_stats["tpd_hit"] = True
                    print("  !! 両モデルTPD上限 — 以降スキップ")
                    break

                if entry is None:
                    cat_stats["skipped_low"] += 1
                    continue

                new_articles.append(entry)
                cat_count += 1
                cat_stats["adopted"] += 1
                if entry.get("researched"):
                    cat_stats["researched"] += 1
                    run_stats["researched_count"] += 1
                time.sleep(SLEEP_BETWEEN_REQ)

        print(f"  [{cat_id}] {cat_count} 件採用 (うち調査補完 {cat_stats['researched']} 件)")

    # ──────────────────────────────────────
    # Tavily 発見フェーズ
    # ──────────────────────────────────────
    if tavily_client and not tpd_exhausted:
        print("\n[TAVILY 発見] ───────────────────────")
        for cat_id, queries in TAVILY_QUERIES.items():
            cat_stats = run_stats["categories"].setdefault(cat_id, {
                "adopted": 0, "skipped_dup": 0, "skipped_low": 0,
                "researched": 0, "tpd_hit": False, "feed_errors": []
            })
            for query in queries:
                if tpd_exhausted:
                    break
                print(f"  検索: {query[:60]}")
                items = fetch_tavily(query, TAVILY_MAX_RESULTS)
                print(f"    取得: {len(items)} 件")
                for item in items:
                    url = item["url"]
                    if url in seen_urls:
                        print(f"    skip (重複URL): {url[:55]}")
                        cat_stats["skipped_dup"] += 1
                        continue
                    seen_urls.add(url)
                    print(f"  → {url[:70]}")
                    entry = process_article(url, item["title"], item["content"], cat_id, seen_title_hashes)
                    if len(_tpd_hit_models) >= 2:
                        tpd_exhausted = True
                        run_stats["tpd_exhausted"] = True
                        print("  !! TPD上限")
                        break
                    if entry is None:
                        cat_stats["skipped_low"] += 1
                        continue
                    new_articles.append(entry)
                    cat_stats["adopted"] += 1
                    if entry.get("researched"):
                        cat_stats["researched"] += 1
                        run_stats["researched_count"] += 1
                    time.sleep(SLEEP_BETWEEN_REQ)
    else:
        if not tavily_client:
            print("\n[TAVILY] スキップ (APIキー未設定)")

    print(f"\n{'='*50}")
    print(f"  完了: {len(new_articles)} 件 (うち調査補完 {run_stats['researched_count']} 件)")
    print(f"{'='*50}")
    return new_articles, run_stats


# ─────────────────────────────────────────────
# DB / ログ
# ─────────────────────────────────────────────
def load_db() -> list[dict]:
    if os.path.exists(MASTER_DATA):
        try:
            with open(MASTER_DATA, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def update_db(db: list[dict], new_entries: list[dict]) -> list[dict]:
    existing_urls = {a["url"] for a in db}
    added = 0
    for entry in new_entries:
        if entry["url"] not in existing_urls:
            db.append(entry)
            added += 1
    db = sorted(db, key=lambda x: x["date"], reverse=True)[:MAX_DB_ENTRIES]
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    print(f"DB: {added} 件追加 / 合計 {len(db)} 件")
    return db


RUN_LOG_FILE = "run_log.json"

def load_run_log() -> list[dict]:
    if os.path.exists(RUN_LOG_FILE):
        try:
            with open(RUN_LOG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def append_run_log(run_log: list[dict], new_count: int, total: int, stats: dict = None) -> list[dict]:
    entry = {
        "datetime_jst":     now_jst().strftime("%Y-%m-%d %H:%M"),
        "new_articles":     new_count,
        "total_articles":   total,
        "researched_count": stats.get("researched_count", 0) if stats else 0,
        "tpd_exhausted":    stats.get("tpd_exhausted", False) if stats else False,
        "categories":       stats.get("categories", {}) if stats else {},
        "feed_errors":      stats.get("feed_errors", []) if stats else [],
    }
    run_log.append(entry)
    run_log = run_log[-90:]
    with open(RUN_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(run_log, f, ensure_ascii=False, indent=2)
    return run_log


# ─────────────────────────────────────────────
# HTML 生成 (既存の _build_index_html / _build_log_html をそのまま使用)
# ─────────────────────────────────────────────
def generate_html(db: list[dict], run_log: list[dict]) -> None:
    with open("articles.js", "w", encoding="utf-8") as f:
        f.write("window.__ARTICLES__ = " + json.dumps(db, ensure_ascii=False) + ";")
    print("データ書き出し: articles.js")
    with open("log.js", "w", encoding="utf-8") as f:
        f.write("window.__RUN_LOG__ = " + json.dumps(run_log, ensure_ascii=False) + ";")
    print("ログ書き出し: log.js")
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(_build_index_html())
    print("HTML書き出し: index.html")
    with open("log.html", "w", encoding="utf-8") as f:
        f.write(_build_log_html())
    print("HTML書き出し: log.html")


# ─────────────────────────────────────────────
# HTML テンプレート (既存のものを流用 + XSS対策のみ追加)
# ─────────────────────────────────────────────
def _build_index_html() -> str:
    """シンプル・可読性優先の1カラム UI"""
    return """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIPHER // Threat Intel</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.8/dist/purify.min.js"></script>
<style>
:root{
  --bg:#0f1419; --surf:#1a1f29; --surf2:#232834; --bdr:#2a3140;
  --text:#c8d1dc; --muted:#7a8699; --hi:#ffffff;
  --acc:#4fc3f7; --acc2:#ffb74d;
  --MAL:#ef5350; --INIT:#ffb74d; --POST:#ba68c8; --AI:#4fc3f7;
  --mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI','Hiragino Sans','Noto Sans JP',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:var(--acc);text-decoration:none}
a:hover{text-decoration:underline}

/* Header */
.hdr{
  position:sticky;top:0;z-index:50;background:rgba(15,20,25,.95);
  backdrop-filter:blur(8px);border-bottom:1px solid var(--bdr);
  padding:14px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;
}
.hdr-title{font-size:1.15rem;font-weight:700;color:var(--hi);letter-spacing:.02em}
.hdr-title span{color:var(--acc)}
.hdr-sub{font-family:var(--mono);font-size:.7rem;color:var(--muted)}
.hdr-stats{margin-left:auto;display:flex;gap:14px;font-family:var(--mono);font-size:.75rem;color:var(--muted)}
.hdr-stats b{color:var(--hi);font-weight:700}
.hdr-log{font-family:var(--mono);font-size:.72rem;color:var(--muted);border:1px solid var(--bdr);padding:5px 10px;border-radius:4px}
.hdr-log:hover{color:var(--acc);border-color:var(--acc);text-decoration:none}

/* Filter bar */
.ctrl{
  max-width:900px;margin:0 auto;padding:18px 20px 8px;
  display:flex;gap:10px;flex-wrap:wrap;align-items:center;
}
#search{
  flex:1;min-width:200px;padding:10px 14px;background:var(--surf);
  border:1px solid var(--bdr);color:var(--hi);border-radius:6px;
  font-family:var(--sans);font-size:.9rem;outline:none;
}
#search:focus{border-color:var(--acc)}
#search::placeholder{color:var(--muted)}
.filters{display:flex;gap:6px;flex-wrap:wrap}
.fbtn{
  padding:6px 12px;background:var(--surf);border:1px solid var(--bdr);
  color:var(--muted);border-radius:20px;cursor:pointer;
  font-family:var(--mono);font-size:.72rem;font-weight:600;letter-spacing:.03em;
  transition:all .15s;
}
.fbtn:hover{color:var(--text);border-color:var(--muted)}
.fbtn.on{background:var(--acc);color:#000;border-color:var(--acc)}

/* Feed */
.feed{max-width:900px;margin:0 auto;padding:0 20px 60px}
.day{
  font-family:var(--mono);font-size:.72rem;color:var(--muted);
  letter-spacing:.1em;margin:24px 0 10px;padding-bottom:6px;
  border-bottom:1px solid var(--bdr);
}
.day.today{color:var(--acc)}

/* Card */
.card{
  background:var(--surf);border:1px solid var(--bdr);border-radius:8px;
  padding:18px 20px;margin-bottom:12px;cursor:pointer;
  transition:border-color .15s, transform .1s;
}
.card:hover{border-color:var(--muted)}
.card:active{transform:scale(.998)}
.card-top{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap}
.tag{
  font-family:var(--mono);font-size:.65rem;font-weight:700;
  padding:3px 9px;border-radius:3px;letter-spacing:.04em;
}
.tag.MALWARE{background:rgba(239,83,80,.15);color:var(--MAL)}
.tag.INITIAL{background:rgba(255,183,77,.15);color:var(--INIT)}
.tag.POST_EXP{background:rgba(186,104,200,.15);color:var(--POST)}
.tag.AI_SEC{background:rgba(79,195,247,.15);color:var(--AI)}
.meta{font-family:var(--mono);font-size:.7rem;color:var(--muted)}
.cvss{
  font-family:var(--mono);font-size:.68rem;font-weight:700;
  padding:2px 8px;border-radius:3px;margin-left:auto;
}
.cvss.crit{background:rgba(239,83,80,.15);color:var(--MAL)}
.cvss.high{background:rgba(255,183,77,.15);color:var(--INIT)}
.cvss.med{background:rgba(255,213,79,.15);color:#ffd54f}
.cvss.low{background:rgba(79,195,247,.15);color:var(--AI)}
.researched{
  font-family:var(--mono);font-size:.62rem;font-weight:700;
  background:rgba(186,104,200,.15);color:var(--POST);
  padding:2px 8px;border-radius:3px;
}
.title{
  font-size:1.12rem;font-weight:700;color:var(--hi);
  line-height:1.45;margin-bottom:8px;letter-spacing:-.005em;
}
.sum{list-style:none;padding:0;margin:0}
.sum li{
  padding:3px 0 3px 16px;position:relative;color:var(--text);
  font-size:.88rem;line-height:1.65;
}
.sum li::before{content:'•';position:absolute;left:4px;color:var(--acc)}
.chips{display:flex;gap:5px;flex-wrap:wrap;margin-top:12px}
.chip{
  font-family:var(--mono);font-size:.65rem;padding:2px 8px;border-radius:3px;
  background:var(--surf2);color:var(--muted);border:1px solid var(--bdr);
}
.chip.cve{color:var(--INIT);border-color:rgba(255,183,77,.3)}
.chip.mitre{color:var(--POST);border-color:rgba(186,104,200,.3)}
.chip.poc{color:var(--AI);border-color:rgba(79,195,247,.3);font-weight:700}
.src{
  display:block;margin-top:10px;padding-top:10px;border-top:1px solid var(--bdr);
  font-family:var(--mono);font-size:.68rem;color:var(--muted);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.src:hover{color:var(--acc);text-decoration:none}
.empty{
  text-align:center;padding:80px 20px;color:var(--muted);
  font-family:var(--mono);font-size:.85rem;
}

/* Detail overlay */
#det{
  position:fixed;inset:0;background:var(--bg);z-index:100;
  display:none;flex-direction:column;overflow:hidden;
}
#det.open{display:flex}
.det-hdr{
  position:sticky;top:0;background:rgba(15,20,25,.95);backdrop-filter:blur(8px);
  border-bottom:1px solid var(--bdr);padding:12px 20px;
  display:flex;align-items:center;gap:12px;flex-shrink:0;
}
.back{
  background:var(--surf);border:1px solid var(--bdr);color:var(--text);
  padding:7px 16px;border-radius:6px;cursor:pointer;
  font-family:var(--mono);font-size:.75rem;font-weight:600;
}
.back:hover{border-color:var(--acc);color:var(--acc)}
.det-src{margin-left:auto;font-family:var(--mono);font-size:.7rem;color:var(--muted)}
.det-body{flex:1;overflow-y:auto;padding:30px 20px 60px}
.det-in{max-width:780px;margin:0 auto}
.det-title{
  font-size:1.7rem;font-weight:700;color:var(--hi);
  line-height:1.3;margin-bottom:14px;letter-spacing:-.01em;
}
.det-meta{
  display:flex;gap:8px;flex-wrap:wrap;align-items:center;
  margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--bdr);
}
.poc-btn{
  display:inline-flex;align-items:center;gap:6px;
  background:var(--AI);color:#000;padding:8px 16px;border-radius:6px;
  font-family:var(--mono);font-weight:700;font-size:.78rem;
}
.poc-btn:hover{text-decoration:none;opacity:.9}

/* Markdown body */
.md h1{display:none}
.md h2{
  font-size:1.15rem;font-weight:700;color:var(--hi);
  margin:32px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--bdr);
  letter-spacing:-.005em;
}
.md h3{font-size:.98rem;font-weight:700;color:var(--acc2);margin:20px 0 8px}
.md p{margin:10px 0;color:var(--text)}
.md ul,.md ol{padding-left:24px;margin:10px 0}
.md li{margin:5px 0;color:var(--text)}
.md strong{color:var(--hi);font-weight:700}
.md code{
  font-family:var(--mono);font-size:.85em;background:var(--surf2);
  color:var(--acc2);padding:2px 6px;border-radius:3px;
}
.md pre{
  background:#0a0d12;border:1px solid var(--bdr);border-left:3px solid var(--acc);
  border-radius:6px;padding:14px 16px;overflow-x:auto;margin:14px 0;
  position:relative;
}
.md pre code{
  background:none;color:#e0e6ed;padding:0;font-size:.82rem;line-height:1.7;
}
.md blockquote{
  border-left:3px solid var(--bdr);padding:4px 14px;color:var(--muted);
  margin:12px 0;background:var(--surf);
}
.md table{border-collapse:collapse;margin:14px 0;font-size:.85rem;width:100%}
.md th,.md td{padding:8px 12px;border:1px solid var(--bdr);text-align:left}
.md th{background:var(--surf2);color:var(--hi);font-weight:700}
.copy{
  position:absolute;top:8px;right:8px;background:var(--surf);border:1px solid var(--bdr);
  color:var(--muted);font-family:var(--mono);font-size:.65rem;
  padding:3px 9px;border-radius:4px;cursor:pointer;
}
.copy:hover{color:var(--acc);border-color:var(--acc)}

::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

@media(max-width:600px){
  .hdr{padding:12px 14px;gap:10px}
  .hdr-title{font-size:1rem}
  .hdr-stats{font-size:.7rem;gap:10px;width:100%;order:3}
  .ctrl{padding:14px 14px 6px}
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
    <div class="hdr-title"><span>◆</span> CIPHER Threat Intel</div>
    <div class="hdr-sub">// Red Team Reconnaissance</div>
  </div>
  <div class="hdr-stats">
    <span><b id="stat-total">0</b> total</span>
    <span><b id="stat-today">0</b> today</span>
    <span><b id="stat-research">0</b> 🔍</span>
  </div>
  <a href="log.html" class="hdr-log">📋 実行ログ</a>
</header>

<div class="ctrl">
  <input type="text" id="search" placeholder="🔍 タイトル・本文を検索..." autocomplete="off">
  <div class="filters">
    <button class="fbtn on" data-cat="ALL">ALL</button>
    <button class="fbtn" data-cat="MALWARE">MAL</button>
    <button class="fbtn" data-cat="INITIAL">INIT</button>
    <button class="fbtn" data-cat="POST_EXP">POST</button>
    <button class="fbtn" data-cat="AI_SEC">AI</button>
    <button class="fbtn" data-cat="RESEARCHED">🔍 補完済</button>
  </div>
</div>

<main class="feed" id="feed"></main>

<div id="det">
  <div class="det-hdr">
    <button class="back" onclick="closeDet()">← 戻る</button>
    <a id="det-src-link" class="det-src" href="#" target="_blank">元記事 ↗</a>
  </div>
  <div class="det-body">
    <div class="det-in" id="det-body"></div>
  </div>
</div>

<script src="articles.js"></script>
<script>
const db = (window.__ARTICLES__ || []).slice();
const today = new Date().toISOString().slice(0,10);
let activeCat = 'ALL';

function cvssCls(s){
  const n = parseFloat(s);
  if (isNaN(n)) return '';
  if (n >= 9) return 'crit';
  if (n >= 7) return 'high';
  if (n >= 4) return 'med';
  return 'low';
}
function pocOk(u){ return u && u.startsWith('http'); }
function esc(s){ return (s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

document.getElementById('stat-total').textContent = db.length;
document.getElementById('stat-today').textContent = db.filter(a => a.date === today).length;
document.getElementById('stat-research').textContent = db.filter(a => a.researched).length;

document.querySelectorAll('.fbtn').forEach(b => {
  b.onclick = () => {
    document.querySelectorAll('.fbtn').forEach(x => x.classList.remove('on'));
    b.classList.add('on');
    activeCat = b.dataset.cat;
    render();
  };
});
document.getElementById('search').oninput = render;

function render(){
  const q = document.getElementById('search').value.toLowerCase();
  const feed = document.getElementById('feed');
  feed.innerHTML = '';

  const filtered = db.filter(a => {
    if (activeCat === 'RESEARCHED') return a.researched;
    if (activeCat !== 'ALL' && a.category !== activeCat) return false;
    if (q) {
      const hay = (a.title + ' ' + (a.summary_points||[]).join(' ') + ' ' + a.content).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  if (!filtered.length) {
    feed.innerHTML = '<div class="empty">// 該当する情報がありません</div>';
    return;
  }

  // 日付でグループ化
  const groups = {};
  filtered.forEach(a => {
    (groups[a.date] = groups[a.date] || []).push(a);
  });

  const frag = document.createDocumentFragment();
  Object.keys(groups).sort().reverse().forEach(date => {
    const dayEl = document.createElement('div');
    dayEl.className = 'day' + (date === today ? ' today' : '');
    dayEl.textContent = date === today ? date + '  ● TODAY' : date;
    frag.appendChild(dayEl);

    groups[date].forEach(a => {
      const card = document.createElement('div');
      card.className = 'card';
      const pts = (a.summary_points || []).slice(0, 3);
      const sumHtml = pts.length
        ? '<ul class="sum">' + pts.map(p => '<li>' + esc(p) + '</li>').join('') + '</ul>'
        : '';
      const cvssHtml = a.cvss_score
        ? '<span class="cvss ' + cvssCls(a.cvss_score) + '">CVSS ' + esc(a.cvss_score) + '</span>'
        : '';
      const resHtml = a.researched ? '<span class="researched">🔍 補完済</span>' : '';
      const cveHtml = (a.cve_ids || []).slice(0, 3).map(c => '<span class="chip cve">' + esc(c) + '</span>').join('');
      const mitreHtml = (a.mitre_ids || []).slice(0, 4).map(m => '<span class="chip mitre">' + esc(m) + '</span>').join('');
      const pocHtml = pocOk(a.poc_url) ? '<span class="chip poc">⚡ PoC</span>' : '';
      let host = a.url;
      try { host = new URL(a.url).hostname.replace(/^www\\./, ''); } catch(e){}

      card.innerHTML = `
        <div class="card-top">
          <span class="tag ${a.category}">${a.category}</span>
          <span class="meta">${a.date}</span>
          ${resHtml}
          ${cvssHtml}
        </div>
        <div class="title">${esc(a.title)}</div>
        ${sumHtml}
        ${(cveHtml || mitreHtml || pocHtml) ? '<div class="chips">' + cveHtml + mitreHtml + pocHtml + '</div>' : ''}
        <a class="src" href="${esc(a.url)}" target="_blank" onclick="event.stopPropagation()">📎 ${esc(host)}</a>
      `;
      card.onclick = () => openDet(a);
      frag.appendChild(card);
    });
  });
  feed.appendChild(frag);
}

function openDet(a){
  const body = document.getElementById('det-body');
  let meta = '<span class="tag ' + a.category + '">' + a.category + '</span>';
  meta += '<span class="meta">' + a.date + '</span>';
  if (a.cvss_score) meta += '<span class="cvss ' + cvssCls(a.cvss_score) + '">CVSS ' + esc(a.cvss_score) + '</span>';
  if (a.researched) meta += '<span class="researched">🔍 エージェント補完済</span>';
  (a.cve_ids || []).forEach(c => meta += '<span class="chip cve">' + esc(c) + '</span>');
  (a.mitre_ids || []).forEach(m => meta += '<span class="chip mitre">' + esc(m) + '</span>');
  if (pocOk(a.poc_url)) meta += '<a href="' + esc(a.poc_url) + '" target="_blank" class="poc-btn">⚡ PoC Repository</a>';

  const rendered = DOMPurify.sanitize(marked.parse(a.content || ''));

  body.innerHTML = `
    <div class="det-title">${esc(a.title)}</div>
    <div class="det-meta">${meta}</div>
    <div class="md">${rendered}</div>
    <div style="margin-top:36px;padding-top:18px;border-top:1px solid var(--bdr)">
      <div style="font-family:var(--mono);font-size:.7rem;color:var(--muted);margin-bottom:6px">// SOURCE</div>
      <a href="${esc(a.url)}" target="_blank" style="font-family:var(--mono);font-size:.8rem;word-break:break-all">${esc(a.url)}</a>
    </div>
  `;

  // Copy buttons on code blocks
  body.querySelectorAll('pre').forEach(pre => {
    const btn = document.createElement('button');
    btn.className = 'copy';
    btn.textContent = 'COPY';
    btn.onclick = (e) => {
      e.stopPropagation();
      const txt = pre.querySelector('code')?.textContent || pre.textContent;
      navigator.clipboard.writeText(txt).then(() => {
        btn.textContent = '✓ OK';
        setTimeout(() => btn.textContent = 'COPY', 1500);
      });
    };
    pre.appendChild(btn);
  });

  document.getElementById('det-src-link').href = a.url;
  document.getElementById('det').classList.add('open');
  history.pushState({view:'detail'}, '');
}

function closeDet(){
  document.getElementById('det').classList.remove('open');
}
window.onpopstate = () => closeDet();

render();
</script>
</body>
</html>"""


def _build_log_html() -> str:
    return """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIPHER // Run Log</title>
<style>
:root{
  --bg:#0f1419; --surf:#1a1f29; --surf2:#232834; --bdr:#2a3140;
  --text:#c8d1dc; --muted:#7a8699; --hi:#ffffff;
  --acc:#4fc3f7; --acc2:#ffb74d; --err:#ef5350;
  --mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI','Hiragino Sans','Noto Sans JP',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;padding:30px 20px 60px}
.wrap{max-width:780px;margin:0 auto}
.back{
  display:inline-block;font-family:var(--mono);font-size:.75rem;
  color:var(--muted);border:1px solid var(--bdr);padding:6px 12px;
  border-radius:6px;text-decoration:none;margin-bottom:20px;
}
.back:hover{color:var(--acc);border-color:var(--acc)}
h1{font-size:1.6rem;font-weight:700;color:var(--hi);letter-spacing:-.01em;margin-bottom:4px}
h1 span{color:var(--acc)}
.sub{font-family:var(--mono);font-size:.72rem;color:var(--muted);margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:30px}
@media(max-width:600px){.grid{grid-template-columns:1fr 1fr}}
.stat{
  background:var(--surf);border:1px solid var(--bdr);border-radius:8px;
  padding:16px;text-align:center;
}
.stat b{display:block;font-size:1.5rem;font-weight:700;color:var(--hi)}
.stat .lbl{font-family:var(--mono);font-size:.65rem;color:var(--muted);letter-spacing:.05em;margin-top:4px}
.stat.warn b{color:var(--err)}
.section{
  font-family:var(--mono);font-size:.7rem;color:var(--muted);
  letter-spacing:.08em;margin-bottom:10px;
}
.row{
  background:var(--surf);border:1px solid var(--bdr);border-radius:6px;
  padding:12px 16px;margin-bottom:6px;
  display:flex;align-items:center;gap:10px;flex-wrap:wrap;
}
.row.today{border-left:3px solid var(--acc)}
.row.tpd{border-left:3px solid var(--err);background:rgba(239,83,80,.04)}
.dt{font-family:var(--mono);font-size:.82rem;color:var(--hi);flex:1;min-width:130px}
.badge{
  font-family:var(--mono);font-size:.68rem;padding:2px 8px;border-radius:3px;font-weight:700;
}
.badge.new{background:rgba(79,195,247,.15);color:var(--acc)}
.badge.zero{color:var(--muted);background:var(--surf2)}
.badge.res{background:rgba(186,104,200,.15);color:#ba68c8}
.badge.tpd{background:rgba(239,83,80,.15);color:var(--err)}
.badge.tdy{background:rgba(79,195,247,.15);color:var(--acc)}
.total{font-family:var(--mono);font-size:.68rem;color:var(--muted);margin-left:auto}
.cats{margin-top:8px;display:flex;gap:12px;flex-wrap:wrap;width:100%}
.cat-r{font-family:var(--mono);font-size:.68rem;font-weight:700}
.cat-r.ok{color:var(--acc)}
.cat-r.zero{color:var(--muted)}
.cat-r.err{color:var(--err)}
.empty{text-align:center;padding:60px 20px;color:var(--muted);font-family:var(--mono)}
</style>
</head>
<body>
<div class="wrap">
  <a href="index.html" class="back">← CIPHER</a>
  <h1><span>◆</span> Run Log</h1>
  <div class="sub">// AI調査実行履歴</div>
  <div class="grid" id="summary"></div>
  <div class="section">// 実行履歴 (新しい順)</div>
  <div id="rows"></div>
</div>
<script src="log.js"></script>
<script>
const log = (window.__RUN_LOG__ || []).slice().reverse();
const today = new Date().toISOString().slice(0,10);
const totalRuns = log.length;
const totalNew = log.reduce((s,r) => s + (r.new_articles || 0), 0);
const totalRes = log.reduce((s,r) => s + (r.researched_count || 0), 0);
const tpdCount = log.filter(r => r.tpd_exhausted).length;
const lastRun = log[0]?.datetime_jst || '—';

document.getElementById('summary').innerHTML = `
  <div class="stat"><b>${totalRuns}</b><div class="lbl">RUNS</div></div>
  <div class="stat"><b>${totalNew}</b><div class="lbl">ARTICLES</div></div>
  <div class="stat"><b>${totalRes}</b><div class="lbl">RESEARCHED</div></div>
  <div class="stat ${tpdCount>0?'warn':''}"><b>${tpdCount}</b><div class="lbl">TPD ERRORS</div></div>
`;

const CAT_LBL = {MALWARE:'MAL', INITIAL:'INIT', POST_EXP:'POST', AI_SEC:'AI'};

const rows = document.getElementById('rows');
if (!log.length) {
  rows.innerHTML = '<div class="empty">// 実行ログがありません</div>';
} else {
  rows.innerHTML = log.map(r => {
    const isToday = r.datetime_jst?.startsWith(today);
    const nb = r.new_articles > 0
      ? `<span class="badge new">+${r.new_articles}</span>`
      : `<span class="badge zero">±0</span>`;
    const rb = r.researched_count > 0
      ? `<span class="badge res">🔍${r.researched_count}</span>` : '';
    const tpdB = r.tpd_exhausted ? '<span class="badge tpd">TPD枯渇</span>' : '';
    const tdy = isToday ? '<span class="badge tdy">TODAY</span>' : '';

    const cats = r.categories || {};
    const catHtml = Object.entries(CAT_LBL).map(([id, lbl]) => {
      const c = cats[id];
      if (!c) return '';
      const adopted = c.adopted || 0;
      const cls = c.tpd_hit ? 'err' : adopted > 0 ? 'ok' : 'zero';
      const icon = c.tpd_hit ? '⚠' : adopted > 0 ? '✓' : '—';
      return `<span class="cat-r ${cls}">${lbl}: ${icon} ${adopted||''}</span>`;
    }).join('');

    return `<div class="row ${isToday?'today':''} ${r.tpd_exhausted?'tpd':''}">
      <div class="dt">${r.datetime_jst}</div>
      ${tdy}${nb}${rb}${tpdB}
      <span class="total">total: ${r.total_articles||'—'}</span>
      ${catHtml ? '<div class="cats">'+catHtml+'</div>' : ''}
    </div>`;
  }).join('');
}
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    db = load_db()
    existing_urls = {a["url"] for a in db}
    new_data, run_stats = fetch_and_analyze(existing_urls)
    db = update_db(db, new_data)
    run_log = load_run_log()
    run_log = append_run_log(run_log, len(new_data), len(db), run_stats)
    generate_html(db, run_log)
