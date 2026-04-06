# RED-TACTICAL INTELLIGENCE AGENT v3.1
import os
import json
import re
import time
import hashlib
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from html import unescape
from groq import Groq
from datetime import datetime, timezone, timedelta

JST = timezone(timedelta(hours=9))
def now_jst():
    return datetime.now(JST)

# ─────────────────────────────────────────────
# 設定
# ─────────────────────────────────────────────
GROQ_KEY    = os.getenv("GROQ_API_KEY")
if not GROQ_KEY:
    raise RuntimeError("GROQ_API_KEY が未設定です。GitHub Secrets を確認してください。")
groq_client = Groq(api_key=GROQ_KEY)

MASTER_DATA      = "all_articles.json"
OUTPUT_HTML      = "index.html"
MAX_DB_ENTRIES   = 200
MIN_REPORT_LEN   = 1200   # 品質フィルタ（高品質レポート重視）
MAX_RETRIES      = 3
SLEEP_BETWEEN_REQ = 1.0  # 記事間の最低待機（rate limitは動的ハンドリング）

# deepseek-r1-distill-llama-70b は2025年9月に廃止済み
# llama-4-scout: TPD 500,000 (llama-3.3-70b-versatileの5倍) で余裕あり
PRIMARY_MODEL  = "meta-llama/llama-4-scout-17b-16e-instruct"
FALLBACK_MODEL = "llama-3.3-70b-versatile"  # llama-4-scout失敗時のフォールバック

# ─────────────────────────────────────────────
# 検索クエリ（セキュリティ研究ソースに誘導）
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
# RSSフィード定義（カテゴリ別）
# 毎日の実行で新着記事のみ取得するため重複しない
# ─────────────────────────────────────────────
RSS_FEEDS = {
    "MALWARE": [
        "https://blog.malwarebytes.com/feed/",                        # Malwarebytes Labs (stable)
        "https://isc.sans.edu/rssfeed_full.xml",                      # SANS ISC Diary
        "https://securelist.com/feed/",                               # Kaspersky Securelist
        "https://www.darkreading.com/rss.xml",                        # Dark Reading
        "https://www.trellix.com/en-us/about/newsroom/stories/research/rss.xml",  # Trellix Research
    ],
    "INITIAL": [
        "https://feeds.feedburner.com/TheHackersNews",                # The Hacker News
        "https://seclists.org/rss/fulldisclosure.rss",                # Full Disclosure
        "https://www.zerodayinitiative.com/rss/published/",           # ZDI Published Advisories
        "https://portswigger.net/daily-swig/rss",                     # Daily Swig (PortSwigger)
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",      # CISA Advisories
    ],
    "POST_EXP": [
        "https://research.checkpoint.com/feed/",                      # Check Point Research
        "https://www.elastic.co/security-labs/rss/feed.xml",         # Elastic Security Labs
        "https://securelist.com/feed/",                               # Kaspersky Securelist
        "https://www.cyderes.com/blog/feed/",                         # Cyderes (post-exp focus)
        "https://posts.specterops.io/feed",                           # SpecterOps (AD/post-exp specialist)
    ],
    "AI_SEC": [
        "https://blog.trailofbits.com/feed/",                         # Trail of Bits
        "https://simonwillison.net/atom/everything/",                 # Simon Willison (LLM sec)
        "https://feeds.feedburner.com/TheHackersNews",                # The Hacker News (AI coverage)
        "https://www.microsoft.com/en-us/security/blog/feed/",        # Microsoft Security (AI threats)
        "https://research.checkpoint.com/feed/",                      # Check Point AI threat research
    ],
}

MAX_ITEMS_PER_FEED = 5   # 1フィードあたり最新N件をチェック
MAX_PER_CATEGORY  = 10  # カテゴリ上限（新規性フィルタで絞られる）

# ─────────────────────────────────────────────
# プロンプト（レッドチーム再現手順特化）
# ─────────────────────────────────────────────
CATEGORY_CONTEXT = {
    "MALWARE": """
MALWARE ANALYSIS FOCUS:
- Internal loader mechanism: how shellcode/PE is decrypted, mapped, executed (specific API calls: VirtualAlloc, WriteProcessMemory, CreateRemoteThread etc.)
- Obfuscation: exact algorithm (XOR key, RC4, AES-CBC with IV), where key material is stored
- C2 protocol: HTTP/DNS/custom, beaconing interval, jitter, encoding (base64/custom), URI patterns
- Persistence: exact registry key path, scheduled task XML, WMI subscription query
- EDR evasion: AMSI bypass method, ETW patching, direct syscalls, process hollowing target
INITIAL ACCESS FOCUS:
- Root cause: exact vulnerable code path, which parameter/header/field triggers the bug
- Vulnerability class: buffer overflow offset, SQL injection context, deserialization gadget chain, auth logic bypass condition
- Affected versions: exact version strings, patch commit/advisory reference
- Exploit trigger: HTTP method, endpoint path, required headers/auth state, payload format
- Bypass conditions: WAF bypass, auth prerequisite, race condition window
""",
    "POST_EXP": """
POST-EXPLOITATION FOCUS:
- Privilege escalation: specific misconfiguration (SeImpersonatePrivilege, weak service ACL, unquoted path, token abuse)
- Lateral movement: exact protocol (SMB/WinRM/DCOM), credential type needed, required ports
- Credential dumping: LSASS access method (MiniDump, direct read, PPL bypass), SAM/NTDS extraction path
- AD attack: Kerberoastable SPN list method, RBCD prerequisite, DCSync required rights
- EDR evasion: process to inject into, which LOLBAS binary, obfuscation needed
""",
    "AI_SEC": """
AI/LLM ATTACK FOCUS (broad coverage — any attack technique targeting AI/LLM systems):
- Attack vector: exact injection point or entry (system prompt, tool description, RAG content, fine-tuning data, model weights, API, MCP component, agent memory, etc.)
- Attack mechanism: why/how the model is manipulated (context confusion, role override, indirect injection, training data poisoning, adversarial input, etc.)
- Concrete payload or technique: actual strings, templates, configurations, or steps that trigger the behavior
- Impact: what the attacker achieves (data exfiltration, jailbreak, agent hijack, SSRF, tool misuse, model theft, denial of service, etc.)
- Bypass / evasion: how existing defenses or safety filters are circumvented
- PoC reproducibility: specific tools, configs, payload templates, or code a red teamer can run in a lab tomorrow
""",
}

def build_prompt(content: str, category: str) -> str:
    ctx = CATEGORY_CONTEXT.get(category, "")
    return f"""あなたはオフェンシブセキュリティの専門家（レッドチームオペレーター歴15年）です。
社内のレッドチームテスター向けに、攻撃者視点で攻撃を再現するための内部技術レポートを作成してください。

対象読者: 明日ラボ環境でこの攻撃を試みるレッドチームテスター。曖昧な記述は一切不要。
{ctx}
━━━ STEP 1: 記事選定（まず実施・出力不要） ━━━
以下の基準で新規性スコアを1〜5で評価してください:
  5 = 新規CVE・新技術・オリジナルリサーチ・広く知られていない新バイパス手法
  4 = 既知技術の有意な新バリアント（新ターゲット・新回避手法・新ツール）
  3 = 既知手法だが特定環境・設定への具体的な適用事例として価値あり
  2 = 既知手法の概説、新情報なし
  1 = 一般的な教育コンテンツ、ベンダーマーケティング、技術的深度なし

選定基準（重要）:
- 「攻撃者がこれを使って何ができるか」が具体的に書かれているか
- テスターがラボで試せる具体的な手順・ツール・設定が推測できるか
- 単なるインシデント報告や製品紹介ではなく、攻撃手法の技術詳細があるか

スコア1〜3の場合のみ、以下のJSONを出力してください:
{{"skip": true, "reason": "除外理由を日本語で記載"}}

スコア4〜5の場合: 以下のSTEP 2に進んでください。

━━━ STEP 2: レポート作成 ━━━

【言語ルール（絶対遵守）】
- 全セクションを日本語で記述すること
- ツール名・CVE ID・APIコール・コマンド構文のみ英語を維持
- 正例: 「本マルウェアはVirtualAllocExでリモートプロセスにメモリを確保し、WriteProcessMemoryで注入する」
- 誤例: 「This malware allocates memory using VirtualAllocEx」

【重要】全セクションを最後まで書き切ること。途中で切らないこと。
スペースが足りない場合は「## 検知・防御策」と「## IoC・痕跡情報」のみ短縮可。他は絶対に短縮しないこと。

[## 概要]
以下の構成で記述すること:

1〜2文の核心サマリー（冒頭）:
「〇〇が報告された。重要なのは〜という点である」の形式で書く。
例: 「CrystalX RATを用いたMaaS（Malware-as-a-Service）が報告された。重要なのは低スキルでも利用可能なマルウェアサービスとして拡散している点である。」

技術的要点（箇条書き3〜5点）:
・各点は「何が」「どのように」「なぜ危険か」を1文で表現
・「高度な」「巧妙な」等の抽象表現は使わず、具体的な動作・仕組みを書く

**🆕 新規性・差異化ポイント:**（独立した段落・太字）
従来手法との具体的な差異を1〜2文で記述。情報不足の場合は [推測] を付与。

属性情報（判明分のみ、不明は「記載なし」）:
APT: （脅威アクター名）
Malware: （マルウェア名）
CVE: （CVE番号）
IoC: （ハッシュ・IP・ドメインなど）

[## 脆弱性・脅威の技術的メカニズム]
攻撃者視点で「なぜこの攻撃が成立するか」を技術的に説明すること:
- 脆弱なコンポーネント・設定・ロジックを特定し、悪用の仕組みを説明
- APIコール名・メモリ操作・プロトコルフィールド・コードパスを具体的に記述
- CVEの場合: 脆弱なコードパス・トリガー条件・パッチ差分
- マルウェアの場合: ロード→復号→実行の各ステップを内部動作レベルで説明
- 最低300文字。表面的な説明は不可。攻撃者がどう悪用するかの視点を保つこと

[## 攻撃再現ガイド]

このセクションの目的: レッドチームテスターが「この攻撃を自分で再現するには何が必要か」を
理解できるよう、攻撃の流れを具体的に記述すること。
コマンド形式にこだわらず、設定手順・操作手順・必要な知識・ツール・サービスを含めて書く。

■ 前提条件・環境
- 必要なOS・ネットワーク構成・アカウント種別・権限レベル
- 必要なツール・サービス・外部リソース（登録が必要なものも含む）
- 攻撃対象の前提状態（どんな設定が有効だと悪用できるか）

■ 攻撃フロー（段階ごとに記述）
各フェーズを「準備→実行→維持」の構造で記述すること。
各ステップは以下を含む:
  - 【操作】何を・どこで・どのように行うか（UIでの操作・設定変更・コマンド等）
  - 【目的】この操作が攻撃上なぜ必要か
  - 【結果】この操作で何が起きるか・何が得られるか
  - 記事から読み取れない部分は知識から補完し [推測] を付記

■ 具体的な実装・設定の詳細
記事に言及された具体的な要素（特定CLSID・特定APIコール・特定設定値・
OAuthパラメータ・特定ファイル名・特定レジストリキー等）は
その作り方・設定方法・使い方を詳しく説明すること。
コードブロックが自然な場合は使用する。設定画面の操作の場合は手順を文章で説明する。

[## IoC・痕跡情報]
記事に記載されたIoC（ハッシュ・IP・ドメイン・URLパターン・C2ヘッダー・
URIパターン・ファイル名・レジストリキー等）を整理して記載:
- ハッシュ値: （MD5/SHA256）
- C2ドメイン・IP: 
- 特徴的なパターン（User-Agent・URI・証明書等）:
記事にIoCが含まれない場合は「記事中に記載なし」と明記する

[## MITRE ATT&CK マッピング]
記事の攻撃手法を正確に反映したATT&CKテクニックIDを選ぶこと。
T1055.012（プロセスホロウィング）はProcess Hollowingの場合のみ使用。
記事の実際の手法に合ったIDを選ぶこと（例: 権限昇格→T1068、フィッシング→T1566、クレデンシャルダンプ→T1003等）
各テクニックにサブテクニックIDと説明を付けること

[## 検知・防御策]

**防御策**
・具体的な設定変更・パッチ・権限制限（最低3項目）
・「〜を有効にする」「〜を無効化する」形式で具体的に記述

**検知策**
①検知ポイント: この攻撃が検知できるログ取得元を列挙
　（例: EDRのプロセス生成ログ、Windowsイベントログ4688、NDRのDNSクエリログ）
②SIEMクエリ（KQL / Sigma / SPL のいずれかで必ず1つ以上）:
```
具体的なIoCを含むクエリ（プロセス名・コマンドライン・通信先・レジストリキー等）
```

OUTPUT: ONLY valid JSON. No markdown fences around JSON. Use \n for newlines in report field.
IMPORTANT: All text fields must be in JAPANESE. Tool names, CVE IDs, API names, commands may remain in English.

Skip: {{"skip": true, "reason": "除外理由を日本語で記載"}}

Full: {{"title":"攻撃の核心を30字以内で表す日本語タイトル","summary_points":["核心サマリー（重要性含む1文）","技術的要点1","技術的要点2","技術的要点3"],"poc_url":"GitHubのURLか空文字","cvss_score":"数値のみか空文字","mitre_ids":["T1566.001","T1059.001"]  ← 必ず記事内容に合ったIDに書き換えること,"report":"## 概要\n...\n## 脆弱性・脅威の技術的メカニズム\n...\n## 攻撃再現ガイド\n■ 前提条件・環境\n...\n■ 攻撃フロー\n【フェーズ1: 準備】\n【操作】...\n【目的】...\n【結果】...\n【フェーズ2: 実行】\n...\n■ 具体的な実装・設定の詳細\n...\n## IoC・痕跡情報\n...\n## MITRE ATT&CK マッピング\n...\n## 検知・防御策\n**防御策**\n・...\n\n**検知策**\n①検知ポイント: ...\n②Sigma/KQL:\n```\n...\n```"}}

SOURCE ARTICLE:
{content[:4000]}"""


# ─────────────────────────────────────────────
# JSON抽出（deepseek-r1の<think>対応を強化）
# ─────────────────────────────────────────────
def extract_json(raw: str) -> dict | None:
    # <think>...</think> を非貪欲マッチで除去（ネスト・複数ブロック対応）
    cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
    cleaned = cleaned.strip()

    # ```json ... ``` または ``` ... ``` ブロックを除去
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()

    # パターン1: そのままパース
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # パターン2: 最初の { から最後の } まで抽出（外側のテキストを無視）
    brace_start = cleaned.find("{")
    brace_end   = cleaned.rfind("}")
    if brace_start != -1 and brace_end > brace_start:
        try:
            return json.loads(cleaned[brace_start:brace_end+1])
        except json.JSONDecodeError:
            pass

    return None

def validate_result(res: dict) -> bool:
    """品質フィルタ: 必須フィールドと最低品質チェック"""
    if not res:
        return False
    # 新規性スコアが低い記事はskipフラグで除外
    if res.get("skip"):
        return False
    if not res.get("title") or len(res["title"]) < 5:
        return False
    if not res.get("report") or len(res["report"]) < MIN_REPORT_LEN:
        return False
    # LLMがpoc_urlに "なし" "N/A" "none" 等を入れた場合は空文字に正規化
    poc = res.get("poc_url", "")
    if poc and not poc.startswith("http"):
        res["poc_url"] = ""
    # cvss_scoreが数値でなければ空文字に正規化
    cvss = res.get("cvss_score", "")
    if cvss:
        try:
            float(cvss)
        except ValueError:
            res["cvss_score"] = ""
    # mitre_ids: 正規フォーマット T\d{4}(.*)のみ残す、プレースホルダー除去
    import re as _re2
    raw_ids = res.get("mitre_ids", [])
    cleaned_ids = [i for i in raw_ids if _re2.match(r"T\d{4}", str(i))]
    res["mitre_ids"] = cleaned_ids[:5]  # 最大5件
    # summary_points: 各要素を100字以内に丸める（カードUIで見切れ防止）
    pts = res.get("summary_points", [])
    res["summary_points"] = [p[:100] for p in pts if p][:4]
    return True

# ─────────────────────────────────────────────
# LLM呼び出し（モデルフォールバック付きリトライ）
# ─────────────────────────────────────────────
def call_llm(prompt: str) -> dict | None:
    import re as _re
    _RATE_LIMIT_PAT = _re.compile(r"try again in ([\d.]+)([smh])")

    def _parse_wait(err_str: str) -> float:
        """APIエラーメッセージから待機秒数を抽出する"""
        m = _RATE_LIMIT_PAT.search(str(err_str))
        if not m:
            return 5.0
        val, unit = float(m.group(1)), m.group(2)
        return val * {"s": 1, "m": 60, "h": 3600}.get(unit, 1)

    _DECOMMISSIONED = "decommissioned"
    _RATE_LIMIT     = "rate_limit_exceeded"

    for model in [PRIMARY_MODEL, FALLBACK_MODEL]:
        model_dead = False  # このモデルが使用不可ならスキップ
        for attempt in range(MAX_RETRIES):
            if model_dead:
                break
            try:
                resp = groq_client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=2048,
                )
                raw = resp.choices[0].message.content
                result = extract_json(raw)

                if result and result.get("skip"):
                    # 新規性なし → 全モデル試す必要なく即終了
                    print(f"    ✗ [{model}] 新規性なし — {result.get('reason','')}")
                    return None

                if result and validate_result(result):
                    print(f"    ✓ [{model}] attempt {attempt+1} — OK")
                    return result

                print(f"    ✗ [{model}] attempt {attempt+1} — 品質不足, retry...")
                time.sleep(2)

            except Exception as e:
                err = str(e)
                if _DECOMMISSIONED in err:
                    # モデルが廃止 → このモデルは飛ばす
                    print(f"    ✗ [{model}] decommissioned — 次のモデルへ")
                    model_dead = True
                    break
                elif _RATE_LIMIT in err:
                    wait = min(_parse_wait(err), 60)  # 最大60秒待つ
                    print(f"    ✗ [{model}] rate limit — {wait:.0f}秒待機...")
                    time.sleep(wait)
                    # rate limitはTPD上限の可能性が高いので次モデルへ
                    model_dead = True
                    break
                else:
                    print(f"    ✗ [{model}] attempt {attempt+1} — {e}")
                    time.sleep(3)

    return None

# ─────────────────────────────────────────────
# 重複チェック（URLとタイトル類似度）
# ─────────────────────────────────────────────
def title_hash(title: str) -> str:
    """タイトルを正規化してハッシュ化（表記ゆれを吸収）"""
    normalized = re.sub(r"[^\w]", "", title).lower()
    return hashlib.md5(normalized.encode()).hexdigest()[:8]

# ─────────────────────────────────────────────
# RSSフィード取得ユーティリティ
# ─────────────────────────────────────────────
def fetch_rss(feed_url: str, max_items: int = 5) -> list[dict]:
    """RSSフィードから最新記事を取得して返す"""
    try:
        req = urllib.request.Request(
            feed_url,
            headers={"User-Agent": "Mozilla/5.0 (RedTeam Intel Agent/3.2)"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()

        root = ET.fromstring(raw)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        items = []

        cutoff = datetime.now(timezone.utc) - timedelta(days=7)

        def parse_pubdate(s: str):
            """RSS pubDate / Atom updated を datetime に変換"""
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
            title   = item.findtext("title", "").strip()
            url     = item.findtext("link", "").strip()
            pub_raw = item.findtext("pubDate", "") or item.findtext("dc:date", "")
            pub_dt  = parse_pubdate(pub_raw)
            # 日付が取れた場合は7日以内のみ採用（取れない場合はスキップしない）
            if pub_dt and pub_dt < cutoff:
                continue
            summary = item.findtext("description", "") or item.findtext("summary", "")
            content_el = item.find("{http://purl.org/rss/1.0/modules/content/}encoded")
            body = content_el.text if content_el is not None else summary
            body = unescape(re.sub(r"<[^>]+>", " ", body or "")).strip()
            if url and len(body) >= 300:
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
                pub_dt  = parse_pubdate(pub_raw)
                if pub_dt and pub_dt < cutoff:
                    continue
                summary = entry.findtext("atom:summary", "", ns) or entry.findtext("atom:content", "", ns)
                body = unescape(re.sub(r"<[^>]+>", " ", summary or "")).strip()
                if url and len(body) >= 300:
                    items.append({"url": url, "title": title, "content": body})
                if len(items) >= max_items:
                    break

        return items

    except Exception as e:
        print(f"  ✗ RSS取得失敗 ({feed_url[:50]}): {e}")
        return []


def fetch_article_body(url: str) -> str:
    """記事URLから本文をフェッチして返す（RSSの要約が短い場合の補完）"""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (RedTeam Intel Agent/3.2)"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        # 簡易HTML→テキスト
        raw = re.sub(r"<script[^>]*>.*?</script>", " ", raw, flags=re.DOTALL)
        raw = re.sub(r"<style[^>]*>.*?</style>",  " ", raw, flags=re.DOTALL)
        raw = re.sub(r"<[^>]+>", " ", raw)
        raw = unescape(raw)
        raw = re.sub(r"\s{2,}", " ", raw).strip()
        return raw[:8000]
    except Exception as e:
        print(f"  ✗ 本文取得失敗 ({url[:50]}): {e}")
        return ""


# ─────────────────────────────────────────────
# 情報収集メイン（RSS版）
# ─────────────────────────────────────────────
def fetch_and_analyze(existing_urls: set[str]) -> list[dict]:
    print("=" * 50)
    print("  RED-INTEL AGENT v3.2 — RSS情報収集開始")
    print("=" * 50)
    print(f"  既存DB URL数: {len(existing_urls)} 件（スキップ対象）")

    new_articles: list[dict] = []
    seen_urls         = set(existing_urls)
    seen_title_hashes = set()

    for cat_id, feeds in RSS_FEEDS.items():
        print(f"\n[{cat_id}] ───────────────────────")
        cat_count = 0

        for feed_url in feeds:
            if cat_count >= MAX_PER_CATEGORY:
                break

            print(f"  RSS: {feed_url[:60]}")
            items = fetch_rss(feed_url, MAX_ITEMS_PER_FEED)
            print(f"    取得: {len(items)} 件")

            for item in items:
                if cat_count >= MAX_PER_CATEGORY:
                    break

                url     = item["url"]
                content = item["content"]

                # 重複URL
                if url in seen_urls:
                    print(f"    skip (重複URL): {url[:55]}")
                    continue
                seen_urls.add(url)

                # 本文が短い場合は記事本文を直接フェッチ
                if len(content) < 1000:
                    print(f"    本文補完フェッチ: {url[:55]}")
                    fetched = fetch_article_body(url)
                    if fetched:
                        content = fetched

                # それでも短ければスキップ
                if len(content) < 400:
                    print(f"    skip (本文不足): {url[:55]}")
                    continue

                print(f"  → {url[:70]}")

                prompt = build_prompt(content, cat_id)
                result = call_llm(prompt)

                if result is None:
                    continue

                # タイトル重複チェック
                th = title_hash(result["title"])
                if th in seen_title_hashes:
                    print(f"    ✗ タイトル重複: {result['title'][:40]}")
                    continue
                seen_title_hashes.add(th)

                new_articles.append({
                    "date":           now_jst().strftime("%Y-%m-%d"),
                    "category":       cat_id,
                    "title":          result["title"],
                    "summary_points": result.get("summary_points", []),
                    "poc_url":        result.get("poc_url", ""),
                    "cvss_score":     result.get("cvss_score", ""),
                    "mitre_ids":      result.get("mitre_ids", []),
                    "content":        result["report"],
                    "url":            url,
                })
                cat_count += 1
                time.sleep(SLEEP_BETWEEN_REQ)

        print(f"  [{cat_id}] {cat_count} 件採用")

    print(f"\n{'='*50}")
    print(f"  完了: 合計 {len(new_articles)} 件")
    print(f"{'='*50}")
    return new_articles

# ─────────────────────────────────────────────
# DB更新
# ─────────────────────────────────────────────
def load_db() -> list[dict]:
    """DBを読み込んで返す。存在しない場合は空リスト。"""
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

    print(f"DB: {added} 件追加 / 合計 {len(db)} 件 → {MASTER_DATA}")
    return db


# ─────────────────────────────────────────────
# 実行ログ管理
# ─────────────────────────────────────────────
RUN_LOG_FILE = "run_log.json"

def load_run_log() -> list[dict]:
    if os.path.exists(RUN_LOG_FILE):
        try:
            with open(RUN_LOG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def append_run_log(run_log: list[dict], new_articles_count: int, total_count: int) -> list[dict]:
    entry = {
        "datetime_jst": now_jst().strftime("%Y-%m-%d %H:%M"),
        "new_articles":  new_articles_count,
        "total_articles": total_count,
    }
    run_log.append(entry)
    run_log = run_log[-90:]  # 直近90件のみ保持
    with open(RUN_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(run_log, f, ensure_ascii=False, indent=2)
    return run_log

# ─────────────────────────────────────────────
# HTML生成（index.html + log.html）
# ─────────────────────────────────────────────
def generate_html(db: list[dict], run_log: list[dict]) -> None:
    # ── articles.js ──────────────────────────────
    with open("articles.js", "w", encoding="utf-8") as f:
        f.write("window.__ARTICLES__ = " + json.dumps(db, ensure_ascii=False) + ";")
    print("データ書き出し: articles.js")

    # ── log.js ───────────────────────────────────
    with open("log.js", "w", encoding="utf-8") as f:
        f.write("window.__RUN_LOG__ = " + json.dumps(run_log, ensure_ascii=False) + ";")
    print("ログ書き出し: log.js")

    # ── index.html ───────────────────────────────
    index_html = _build_index_html()
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(index_html)
    print("HTML書き出し: index.html")

    # ── log.html ─────────────────────────────────
    log_html = _build_log_html()
    with open("log.html", "w", encoding="utf-8") as f:
        f.write(log_html)
    print("HTML書き出し: log.html")
    print("※ GitHub Actions で index.html / log.html / articles.js / log.js をコミットしてください")


def _build_index_html() -> str:
    return """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3CradialGradient id='g' cx='50%25' cy='40%25'%3E%3Cstop offset='0' stop-color='%2338bfff' stop-opacity='.9'/%3E%3Cstop offset='1' stop-color='%230a1628' stop-opacity='1'/%3E%3C/radialGradient%3E%3C/defs%3E%3Cpolygon points='16,2 28,9 28,23 16,30 4,23 4,9' fill='%230d1a2e' stroke='%2338bfff' stroke-width='1.5'/%3E%3Cpolygon points='16,6 24,10.5 24,21.5 16,26 8,21.5 8,10.5' fill='none' stroke='%2338bfff' stroke-width='.6' stroke-opacity='.4'/%3E%3Ctext x='16' y='21' text-anchor='middle' font-family='monospace' font-weight='700' font-size='13' fill='url(%23g)' letter-spacing='-1'%3EC%3C/text%3E%3Ccircle cx='16' cy='16' r='1.2' fill='%2338bfff' opacity='.7'/%3E%3Cline x1='16' y1='6' x2='16' y2='9' stroke='%2338bfff' stroke-width='.8' opacity='.5'/%3E%3Cline x1='16' y1='23' x2='16' y2='26' stroke='%2338bfff' stroke-width='.8' opacity='.5'/%3E%3Cline x1='4' y1='9' x2='6.5' y2='10.5' stroke='%2338bfff' stroke-width='.8' opacity='.5'/%3E%3Cline x1='27.5' y1='10.5' x2='28' y2='9' stroke='%2338bfff' stroke-width='.8' opacity='.5'/%3E%3C/svg%3E">
<title>CIPHER // THREAT INTELLIGENCE</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700&family=Noto+Sans+JP:wght@300;400;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:      #080d14;
  --surf:    #0d1220;
  --surf2:   #111a2e;
  --bdr:     #162040;
  --bdr2:    #1e3060;
  --text:    #7a9ec4;
  --hi:      #c8dff5;
  --muted:   #1e3050;
  --acc:     #38bfff;
  --acc2:    #f0c040;
  --MALWARE: #ff4455;
  --INITIAL: #f0c040;
  --POST_EXP:#b06aff;
  --AI_SEC:  #38bfff;
  --mono: 'JetBrains Mono', monospace;
  --sans: 'Noto Sans JP', sans-serif;
  --disp: 'Rajdhani', sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:14px;min-height:100vh}

/* noise overlay removed for scroll performance */

/* ════════════════════════════════
   DESKTOP LAYOUT
════════════════════════════════ */
.layout{display:flex;height:100vh;overflow:hidden}

/* ── Sidebar (desktop) ── */
.sidebar{
  width:240px;flex-shrink:0;
  background:var(--surf);
  border-right:1px solid var(--bdr);
  display:flex;flex-direction:column;
  position:relative;z-index:10;
}
.logo-wrap{padding:18px 16px 14px;border-bottom:1px solid var(--bdr);position:relative}
.logo-wrap::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,var(--acc),transparent)}
.logo-name{
  font-family:var(--disp);font-size:1.6rem;font-weight:700;letter-spacing:.12em;
  color:var(--acc);line-height:1;
}
.logo-sub{font-family:var(--mono);font-size:.55rem;color:var(--muted);letter-spacing:.18em;margin-top:4px}
.logo-log-link{
  display:inline-block;margin-top:8px;font-family:var(--mono);font-size:.6rem;
  color:var(--muted);text-decoration:none;border:1px solid var(--bdr2);
  padding:3px 8px;border-radius:2px;transition:.15s;letter-spacing:.05em;
}
.logo-log-link:hover{color:var(--acc2);border-color:var(--acc2)}

.search-wrap{
  padding:10px 12px 12px;border-bottom:1px solid var(--bdr);position:relative;
}
.search-wrap::before{
  content:'';position:absolute;
  left:22px;top:50%;transform:translateY(-50%);
  width:12px;height:12px;pointer-events:none;
  background:var(--muted);
  -webkit-mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z'/%3E%3C/svg%3E") center/contain no-repeat;
  mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z'/%3E%3C/svg%3E") center/contain no-repeat;
  transition:.2s;
}
.search-wrap:focus-within::before{background:var(--acc)}
#search-box-desk{
  width:100%;padding:9px 12px 9px 32px;
  background:var(--surface2);
  border:1px solid var(--bdr);
  color:var(--hi);border-radius:3px;
  outline:none;font-family:var(--mono);font-size:.72rem;
  transition:border-color .2s,background .2s;
  caret-color:var(--acc);
}
#search-box-desk:focus{
  border-color:var(--acc);
  background:var(--bg);
}
#search-box-desk::placeholder{color:var(--muted);letter-spacing:.03em}

.filter-wrap{padding:8px 10px;border-bottom:1px solid var(--bdr);display:flex;gap:4px;flex-wrap:wrap}
.cat-btn{
  padding:3px 9px;border-radius:2px;border:1px solid var(--bdr2);
  background:none;color:var(--muted);cursor:pointer;
  font-family:var(--mono);font-size:.6rem;font-weight:700;letter-spacing:.06em;transition:.15s;
}
.cat-btn:hover{color:var(--hi);border-color:var(--text)}
.cat-btn.active[data-cat="ALL"]{background:rgba(56,191,255,.1);border-color:var(--acc);color:var(--acc)}
.cat-btn.active[data-cat="MALWARE"]{background:rgba(255,68,85,.1);border-color:var(--MALWARE);color:var(--MALWARE)}
.cat-btn.active[data-cat="INITIAL"]{background:rgba(240,192,64,.1);border-color:var(--INITIAL);color:var(--INITIAL)}
.cat-btn.active[data-cat="POST_EXP"]{background:rgba(176,106,255,.1);border-color:var(--POST_EXP);color:var(--POST_EXP)}
.cat-btn.active[data-cat="AI_SEC"]{background:rgba(56,191,255,.1);border-color:var(--AI_SEC);color:var(--AI_SEC)}

.date-list{flex:1;overflow-y:auto;padding:8px;overscroll-behavior:contain}
.date-item{
  padding:7px 10px;border-radius:3px;cursor:pointer;
  font-family:var(--mono);font-size:.7rem;color:var(--muted);
  margin-bottom:2px;display:flex;justify-content:space-between;
  align-items:center;transition:.15s;border:1px solid transparent;
}
.date-item:hover{background:var(--surf2);color:var(--hi);border-color:var(--bdr2)}
.date-item.active{background:var(--surf2);color:var(--acc);border-color:var(--bdr2)}
.date-badge{font-size:.58rem;background:var(--bdr);color:var(--muted);padding:1px 6px;border-radius:2px}

.stats-bar{
  padding:10px 12px;border-top:1px solid var(--bdr);
  display:grid;grid-template-columns:1fr 1fr 1fr;gap:4px;
}
.stat-updated{
  grid-column:1/-1;border-top:1px solid var(--bdr);margin-top:4px;padding-top:6px;
  font-family:var(--mono);font-size:.55rem;color:var(--muted);text-align:center;letter-spacing:.05em;
}
.stat-updated span{color:var(--acc2)}

.stat{font-family:var(--mono);font-size:.55rem;color:var(--muted);text-align:center}
.stat-val{display:block;font-size:.85rem;font-weight:700;color:var(--acc);
  }

/* ── Main feed ── */
.main-feed{flex:1;overflow-y:auto;padding:16px;overscroll-behavior:contain;-webkit-overflow-scrolling:touch}
.feed{max-width:860px;margin:0 auto}
.day-label{
  font-family:var(--mono);font-size:.6rem;letter-spacing:.18em;color:var(--muted);
  padding:14px 2px 8px;border-bottom:1px solid var(--bdr);margin-bottom:10px;
  display:flex;align-items:center;gap:8px;
}
.day-label::before{content:'//';color:var(--acc);opacity:.5}

/* ── Card ── */
.card{
  background:var(--surf);border:1px solid var(--bdr);border-radius:4px;
  padding:15px 16px;margin-bottom:8px;cursor:pointer;transition:background .15s,border-color .15s;
  position:relative;overflow:hidden;
  contain:content;
}
.card-source-link{
  display:inline-block;margin-top:8px;
  font-family:var(--mono);font-size:.58rem;color:var(--muted);
  text-decoration:none;letter-spacing:.04em;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;
}
.card-source-link:hover{color:var(--acc2)}
.card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px}
.card[data-cat="MALWARE"]::before{background:var(--MALWARE)}
.card[data-cat="INITIAL"]::before{background:var(--INITIAL)}
.card[data-cat="POST_EXP"]::before{background:var(--POST_EXP)}
.card[data-cat="AI_SEC"]::before{background:var(--AI_SEC)}
.card:hover{background:var(--surf2);border-color:var(--bdr2)}
.card:active{opacity:.85}

.card-meta{display:flex;align-items:center;gap:7px;margin-bottom:8px;flex-wrap:wrap}
.cat-tag{
  font-family:var(--mono);font-size:.58rem;font-weight:700;
  padding:2px 8px;border-radius:2px;letter-spacing:.06em;
}
.cat-tag[data-cat="MALWARE"]{background:rgba(255,68,85,.12);color:var(--MALWARE);border:1px solid rgba(255,68,85,.25)}
.cat-tag[data-cat="INITIAL"]{background:rgba(240,192,64,.12);color:var(--INITIAL);border:1px solid rgba(240,192,64,.25)}
.cat-tag[data-cat="POST_EXP"]{background:rgba(176,106,255,.12);color:var(--POST_EXP);border:1px solid rgba(176,106,255,.25)}
.cat-tag[data-cat="AI_SEC"]{background:rgba(56,191,255,.08);color:var(--AI_SEC);border:1px solid rgba(56,191,255,.2)}
.card-date{font-family:var(--mono);font-size:.6rem;color:var(--muted)}
.cvss-badge{
  font-family:var(--mono);font-size:.58rem;font-weight:700;
  padding:2px 7px;border-radius:2px;margin-left:auto;
}
.cvss-critical{background:rgba(255,68,85,.12);color:#ff4455;border:1px solid rgba(255,68,85,.3)}
.cvss-high{background:rgba(240,192,64,.12);color:#f0c040;border:1px solid rgba(240,192,64,.3)}
.cvss-medium{background:rgba(251,191,36,.12);color:#fbbf24;border:1px solid rgba(251,191,36,.3)}
.cvss-low{background:rgba(56,191,255,.08);color:#38bfff;border:1px solid rgba(56,191,255,.2)}

.card-title{
  font-family:var(--disp);font-size:1.05rem;font-weight:600;
  color:var(--hi);line-height:1.4;margin-bottom:9px;letter-spacing:.02em;
}
.card-summary{font-size:.78rem;color:var(--text);line-height:1.7;list-style:none;padding:0}
.card-summary li{padding:1px 0 1px 14px;position:relative}
.card-summary li::before{content:'›';position:absolute;left:0;color:var(--acc);font-weight:700}
.card-footer{margin-top:10px;display:flex;gap:5px;flex-wrap:wrap;align-items:center}
.mitre-chip{
  font-family:var(--mono);font-size:.56rem;
  background:rgba(176,106,255,.08);color:#c084fc;
  border:1px solid rgba(176,106,255,.18);padding:2px 6px;border-radius:2px;
}
.poc-chip{
  font-family:var(--mono);font-size:.56rem;
  background:rgba(56,191,255,.07);color:var(--acc);
  border:1px solid rgba(56,191,255,.18);padding:2px 6px;border-radius:2px;
  animation:blink 2s infinite;
  will-change:opacity;
}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.55}}
.no-data{text-align:center;padding:80px 20px;font-family:var(--mono);color:var(--muted);font-size:.72rem;letter-spacing:.1em}

/* ── Card action buttons ── */
.card-actions{display:flex;gap:5px;margin-top:10px;padding-top:8px;border-top:1px solid var(--bdr)}
.act-btn{
  font-family:var(--mono);font-size:.58rem;font-weight:700;letter-spacing:.06em;
  padding:3px 10px;border-radius:2px;cursor:pointer;transition:background .15s,color .15s;
  background:none;border:1px solid var(--bdr2);color:var(--muted);
}
.act-btn:hover{color:var(--hi);border-color:var(--text)}
.act-btn.flag-btn.flagged{background:rgba(240,192,64,.1);color:var(--acc2);border-color:rgba(240,192,64,.3)}
.act-btn.delete-btn:hover{background:rgba(255,68,85,.08);color:var(--MALWARE);border-color:rgba(255,68,85,.3)}

/* ── Detail action bar ── */
.det-action-bar{display:flex;gap:8px;margin:16px 0;padding-bottom:16px;border-bottom:1px solid var(--bdr);flex-wrap:wrap}
.det-act-btn{
  font-family:var(--mono);font-size:.65rem;font-weight:700;letter-spacing:.06em;
  padding:6px 16px;border-radius:2px;cursor:pointer;transition:background .15s,color .15s;
  background:none;border:1px solid var(--bdr2);color:var(--muted);
}
.det-act-btn:hover{color:var(--hi);border-color:var(--text)}
.det-act-btn.flagged{background:rgba(240,192,64,.1);color:var(--acc2);border-color:rgba(240,192,64,.3)}
.det-act-btn.delete-btn:hover{background:rgba(255,68,85,.08);color:var(--MALWARE);border-color:rgba(255,68,85,.3)}
.det-act-btn.teams-btn{border-color:rgba(100,153,255,.3);color:#6499ff}
.det-act-btn.teams-btn:hover{background:rgba(100,153,255,.08);border-color:rgba(100,153,255,.5)}
.det-act-btn.teams-btn.sending{opacity:.5;pointer-events:none}

/* ── Teams settings modal ── */
.modal-overlay{
  display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:300;
  align-items:center;justify-content:center;
}
.modal-overlay.open{display:flex}
.modal{
  background:var(--surf);border:1px solid var(--bdr2);border-radius:6px;
  padding:28px 24px;max-width:480px;width:90%;position:relative;
}
.modal h3{font-family:var(--disp);font-size:1.1rem;color:var(--hi);margin-bottom:6px;letter-spacing:.05em}
.modal p{font-size:.75rem;color:var(--muted);margin-bottom:16px;line-height:1.6}
.modal label{display:block;font-family:var(--mono);font-size:.62rem;color:var(--text);margin-bottom:5px;letter-spacing:.06em}
.modal input{
  width:100%;padding:9px 12px;background:var(--bg);border:1px solid var(--bdr2);
  color:var(--hi);border-radius:3px;outline:none;font-family:var(--mono);font-size:.72rem;
  margin-bottom:14px;transition:.2s;
}
.modal input:focus{border-color:var(--acc)}
.modal-btns{display:flex;gap:8px;justify-content:flex-end;margin-top:4px}
.modal-btn{
  font-family:var(--mono);font-size:.65rem;font-weight:700;padding:7px 18px;
  border-radius:2px;cursor:pointer;transition:.15s;border:1px solid var(--bdr2);
  background:none;color:var(--muted);
}
.modal-btn:hover{color:var(--hi);border-color:var(--text)}
.modal-btn.primary{background:rgba(56,191,255,.1);color:var(--acc);border-color:rgba(56,191,255,.3)}
.modal-btn.primary:hover{background:rgba(56,191,255,.18)}
.teams-status{font-family:var(--mono);font-size:.6rem;margin-top:10px;padding:8px 10px;border-radius:3px;display:none}
.teams-status.ok{background:rgba(56,191,255,.08);color:var(--acc);border:1px solid rgba(56,191,255,.2);display:block}
.teams-status.err{background:rgba(255,68,85,.08);color:var(--MALWARE);border:1px solid rgba(255,68,85,.2);display:block}

/* ── Detail overlay ── */
#detail{
  position:fixed;inset:0;background:var(--bg);z-index:200;
  display:flex;flex-direction:column;
  transform:translateX(100%);transition:transform .28s cubic-bezier(.4,0,.2,1);
}
#detail.open{transform:none}
.det-header{
  background:rgba(12,23,18,.98);
  border-bottom:1px solid var(--bdr);padding:12px 16px;
  display:flex;align-items:center;gap:10px;flex-shrink:0;position:relative;
}
.det-header::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,var(--acc),transparent 60%)}
.back-btn{
  background:none;border:1px solid var(--bdr2);color:var(--acc);
  padding:6px 14px;border-radius:2px;cursor:pointer;
  font-family:var(--mono);font-size:.68rem;font-weight:700;transition:.15s;
}
.back-btn:hover{background:rgba(56,191,255,.07)}
.det-url{margin-left:auto;font-family:var(--mono);font-size:.6rem;color:var(--muted);text-decoration:none}
.det-url:hover{color:var(--text)}

.det-body{flex:1;overflow-y:auto;padding:32px 20px}
.det-inner{max-width:800px;margin:0 auto}
.det-title{font-family:var(--disp);font-size:1.65rem;font-weight:700;color:var(--hi);
  line-height:1.3;margin-bottom:16px;letter-spacing:.02em}
.det-meta-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;
  margin-bottom:22px;padding-bottom:16px;border-bottom:1px solid var(--bdr)}
.poc-btn{
  display:inline-flex;align-items:center;gap:6px;
  background:rgba(56,191,255,.08);color:var(--acc);
  border:1px solid rgba(56,191,255,.25);
  padding:8px 16px;border-radius:3px;text-decoration:none;
  font-family:var(--mono);font-weight:700;font-size:.7rem;letter-spacing:.04em;transition:.15s;
}
.poc-btn:hover{background:rgba(56,191,255,.15)}

/* markdown */
.det-inner h1{display:none}
.det-inner h2{
  font-family:var(--disp);font-size:1rem;font-weight:700;color:var(--acc);
  letter-spacing:.12em;text-transform:uppercase;
  border-bottom:1px solid var(--bdr);padding-bottom:6px;margin:30px 0 12px;
}
.det-inner h3{font-size:.92rem;font-weight:600;color:var(--hi);margin:16px 0 7px}
.det-inner p{line-height:1.8;margin-bottom:10px;color:var(--text)}
.det-inner ul,.det-inner ol{padding-left:20px;margin-bottom:10px;line-height:1.8}
.det-inner li{margin-bottom:4px;color:var(--text)}
.det-inner pre{
  background:#040c1a;border:1px solid var(--bdr2);border-left:2px solid var(--acc);
  border-radius:3px;padding:16px 16px 16px 18px;overflow-x:auto;margin:14px 0;position:relative;
}
.det-inner code{font-family:var(--mono);font-size:.78rem;color:var(--acc);line-height:1.7}
.det-inner :not(pre)>code{background:rgba(56,191,255,.07);padding:2px 5px;border-radius:2px;font-size:.78rem;color:var(--acc2)}
.det-inner blockquote{border-left:2px solid var(--bdr2);padding-left:12px;color:var(--muted);margin:10px 0}
.det-inner table{width:100%;border-collapse:collapse;margin:14px 0;font-size:.78rem}
.det-inner th{background:var(--surf2);padding:8px 10px;text-align:left;border:1px solid var(--bdr);
  color:var(--hi);font-family:var(--mono);font-size:.62rem;letter-spacing:.07em}
.det-inner td{padding:7px 10px;border:1px solid var(--bdr);color:var(--text)}
.det-inner strong{color:var(--hi)}
.copy-btn{
  position:absolute;top:8px;right:8px;background:var(--surf2);border:1px solid var(--bdr2);
  color:var(--muted);font-family:var(--mono);font-size:.58rem;padding:3px 7px;
  border-radius:2px;cursor:pointer;transition:.15s;
}
.copy-btn:hover{color:var(--acc);border-color:var(--acc)}

/* ════════════════════════════════
   MOBILE — bottom tab bar
════════════════════════════════ */
.mob-header{display:none}
.tab-bar{display:none}

@media(max-width:700px){
  .layout{flex-direction:column;height:100vh}
  .sidebar{display:none}   /* hide desktop sidebar */

  /* top bar */
  .mob-header{
    display:flex;align-items:center;gap:10px;
    padding:10px 14px;background:var(--surf);border-bottom:1px solid var(--bdr);
    flex-shrink:0;position:relative;
  }
  .mob-header::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
    background:linear-gradient(90deg,var(--acc),transparent 60%)}
  /* モバイル検索: mob-headerに統合 */
  .mob-header #mob-search-inline{
    flex:1;padding:7px 10px;background:var(--surface2);border:1px solid var(--bdr);
    color:var(--hi);border-radius:3px;outline:none;
    font-family:var(--mono);font-size:.72rem;caret-color:var(--acc);
  }
  .mob-header #mob-search-inline:focus{border-color:var(--acc)}
  .mob-header #mob-search-inline::placeholder{color:var(--muted)}
  .mob-logo{font-family:var(--disp);font-size:1.3rem;font-weight:700;
    color:var(--acc);letter-spacing:.1em;}

  /* feed takes full width */
  .main-feed{flex:1;overflow-y:auto;padding:10px 10px 80px}

  /* bottom tab bar */
  .tab-bar{
    display:flex;position:fixed;bottom:0;left:0;right:0;
    background:var(--surf);border-top:1px solid var(--bdr);z-index:100;
    height:58px;
  }
  .tab-btn{
    flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
    gap:3px;background:none;border:none;color:var(--muted);cursor:pointer;
    font-family:var(--mono);font-size:.5rem;letter-spacing:.06em;transition:.15s;
    border-top:2px solid transparent;padding:0;
  }
  .tab-btn svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:1.5}
  .tab-btn.active{color:var(--acc);border-top-color:var(--acc)}
  .tab-btn.active svg{opacity:1}

  /* mobile date drawer */
  .mob-drawer{
    display:none;position:fixed;bottom:58px;left:0;right:0;
    background:var(--surf);border-top:1px solid var(--bdr);
    max-height:50vh;overflow-y:auto;z-index:99;padding:8px;
  }
  .mob-drawer.open{display:block}
  /* PC幅に戻っても残留しないようdisplay:noneを保証 */
  @media(min-width:701px){
    .mob-drawer,.mob-drawer.open{display:none!important}
    .tab-bar{display:none!important}
    .mob-header{display:none!important}
  }
  .mob-drawer .date-item{font-size:.75rem;padding:10px 12px}
  .mob-filter-wrap{padding:8px;display:flex;gap:5px;flex-wrap:wrap;
    border-bottom:1px solid var(--bdr)}

  /* detail on mobile */
  #detail{bottom:58px}

  .stats-bar{display:none}
}

::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bdr2);border-radius:10px}
</style>
</head>
<body>

<!-- MOBILE HEADER -->
<div class="mob-header">
  <span class="mob-logo">CIPHER</span>
  <input type="text" id="mob-search-inline" placeholder="search..." autocomplete="off">
</div>

<!-- DESKTOP LAYOUT -->
<div class="layout">
  <nav class="sidebar">
    <div class="logo-wrap">
      <div class="logo-name">CIPHER</div>
      <div class="logo-sub">// THREAT INTELLIGENCE</div>
      <a href="log.html" class="logo-log-link">📋 調査ログ</a>
      <a href="#" class="logo-log-link" onclick="openTeamsModal();return false;">💬 Teams設定</a>
    </div>
    <div class="search-wrap">
      <input type="text" id="search-box-desk" placeholder="search intel..." autocomplete="off">
    </div>
    <div class="filter-wrap">
      <button class="cat-btn active" data-cat="ALL">ALL</button>
      <button class="cat-btn" data-cat="MALWARE">MAL</button>
      <button class="cat-btn" data-cat="INITIAL">INIT</button>
      <button class="cat-btn" data-cat="POST_EXP">POST</button>
      <button class="cat-btn" data-cat="AI_SEC">AI</button>
      <button class="cat-btn" data-cat="UNREAD">UNREAD</button>
      <button class="cat-btn" data-cat="FLAGGED">⚑ FLAG</button>
    </div>
    <div class="date-list" id="date-list"></div>
    <div class="stats-bar">
      <div class="stat"><span class="stat-val" id="total-count">0</span>TOTAL</div>
      <div class="stat"><span class="stat-val" id="today-count">0</span>TODAY</div>
      <div class="stat"><span class="stat-val" id="poc-count">0</span>POC</div>
      <div class="stat-updated">UPDATED &nbsp;<span id="last-updated">—</span></div>
    </div>
  </nav>

  <div class="main-feed">
    <div class="feed" id="feed"></div>
  </div>
</div>

<!-- MOBILE BOTTOM TAB BAR -->
<div class="tab-bar">
  <button class="tab-btn active" id="tab-feed" onclick="setTab('feed')">
    <svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h10"/></svg>FEED
  </button>
  <button class="tab-btn" id="tab-filter" onclick="setTab('filter')">
    <svg viewBox="0 0 24 24"><path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/></svg>FILTER
  </button>
  <button class="tab-btn" id="tab-dates" onclick="setTab('dates')">
    <svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>DATE
  </button>
  <button class="tab-btn" id="tab-log" onclick="location.href='log.html'">
    <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>LOG
  </button>
</div>

<!-- MOBILE DATE DRAWER -->
<div class="mob-drawer" id="mob-drawer">
  <div class="mob-filter-wrap" id="mob-filter-wrap"></div>
  <div id="mob-date-list"></div>
</div>

<!-- DETAIL VIEW -->

<!-- Teams settings modal -->
<div class="modal-overlay" id="teams-modal">
  <div class="modal">
    <h3>Microsoft Teams 連携</h3>
    <p>Incoming Webhook URL を設定すると、記事をTeamsチャンネルに投稿できます。<br>
    Teams → チャンネル → コネクタ → Incoming Webhook から取得してください。</p>
    <label>WEBHOOK URL</label>
    <input type="url" id="teams-webhook-input" placeholder="https://xxx.webhook.office.com/webhookb2/...">
    <div class="modal-btns">
      <button class="modal-btn" onclick="closeTeamsModal()">CANCEL</button>
      <button class="modal-btn primary" onclick="saveTeamsWebhook()">SAVE</button>
    </div>
    <div class="teams-status" id="teams-modal-status"></div>
  </div>
</div>
<div id="detail">
  <div class="det-header">
    <button class="back-btn" onclick="closeDetail()">← BACK</button>
    <div id="det-cat-tag"></div>
    <a id="det-source-url" class="det-url" href="#" target="_blank">[ SOURCE ]</a>
  </div>
  <div class="det-body">
    <div class="det-inner" id="det-body"></div>
  </div>
</div>

<script src="log.js"></script>
<script src="articles.js"></script>
<script>
const db = window.__ARTICLES__ || [];
let activeCat  = 'ALL';
let activeDate = 'all';
const today = new Date().toISOString().slice(0,10);

/* ── User state (deleted / flagged / read) via localStorage ── */
let userState = { read: {}, flagged: {}, deleted: {} };
const STATE_KEY = 'cipher-user-state';

async function loadUserState() {
  try {
    const raw = localStorage.getItem(STATE_KEY);
    if (raw) userState = JSON.parse(raw);
  } catch(e) { /* 初回または無効データ */ }
}

async function saveUserState() {
  try {
    localStorage.setItem(STATE_KEY, JSON.stringify(userState));
  } catch(e) {
    console.warn('userState save failed:', e);
  }
}

function isRead(url)    { return !!userState.read[url] }
function isFlagged(url) { return !!userState.flagged[url] }
function isDeleted(url) { return !!userState.deleted[url] }

async function markRead(url)   { userState.read[url] = true; await saveUserState(); }
async function toggleFlag(url) {
  if (userState.flagged[url]) delete userState.flagged[url];
  else userState.flagged[url] = true;
  await saveUserState();
}
async function deleteArticle(url) {
  userState.deleted[url] = true;
  await saveUserState();
}

function unreadCount() { return db.filter(a => !isRead(a.url) && !isDeleted(a.url)).length; }
function flaggedCount(){ return db.filter(a => isFlagged(a.url) && !isDeleted(a.url)).length; }

/* ── search sync (desktop + mobile share same state) ── */
const searchBox = document.getElementById('search-box-desk');
const mobSearchInline = document.getElementById('mob-search-inline');
if(searchBox) searchBox.oninput = () => { if(mobSearchInline) mobSearchInline.value = searchBox.value; cancelAnimationFrame(window._rafId); window._rafId = requestAnimationFrame(render); };
if(mobSearchInline) mobSearchInline.oninput = () => { if(searchBox) searchBox.value = mobSearchInline.value; cancelAnimationFrame(window._rafId); window._rafId = requestAnimationFrame(render); };

function getQuery(){ return (searchBox?.value || mobSearchInline?.value || '').toLowerCase(); }

function cvssClass(s){
  const n=parseFloat(s);
  if(isNaN(n))return'';
  if(n>=9)return'cvss-critical';if(n>=7)return'cvss-high';if(n>=4)return'cvss-medium';return'cvss-low';
}
function isPocValid(u){return u&&u.startsWith('http')}


/* ── Teams webhook ── */
const TEAMS_KEY = 'cipher_teams_webhook';
function getWebhook(){ return localStorage.getItem(TEAMS_KEY)||''; }
function saveTeamsWebhook(){
  const url = document.getElementById('teams-webhook-input').value.trim();
  if(!url){ showTeamsStatus('URL を入力してください', 'err'); return; }
  localStorage.setItem(TEAMS_KEY, url);
  showTeamsStatus('保存しました', 'ok');
  setTimeout(closeTeamsModal, 1000);
}
function openTeamsModal(){
  document.getElementById('teams-webhook-input').value = getWebhook();
  document.getElementById('teams-modal-status').className = 'teams-status';
  document.getElementById('teams-modal').classList.add('open');
}
function closeTeamsModal(){ document.getElementById('teams-modal').classList.remove('open'); }
function showTeamsStatus(msg, type){
  const el = document.getElementById('teams-modal-status');
  el.textContent = msg; el.className = 'teams-status '+type;
}
document.addEventListener('click', e => {
  if(e.target && e.target.id === 'teams-modal') closeTeamsModal();
});

async function postToTeams(article){
  const webhook = getWebhook();
  if(!webhook){ openTeamsModal(); return; }
  const btn = document.getElementById('det-teams-btn');
  if(btn){ btn.textContent='SENDING...'; btn.classList.add('sending'); }

  const cvssText = article.cvss_score ? ' | CVSS ' + article.cvss_score : '';
  const mitreText = (article.mitre_ids||[]).slice(0,3).join(', ');
  const summary = (article.summary_points||[]).map(function(p){ return '\u2022 '+p; }).join('\\n');

  const payload = {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      content: {
        '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
        type: 'AdaptiveCard',
        version: '1.4',
        body: [
          {
            type: 'Container',
            style: 'emphasis',
            items: [{
              type: 'TextBlock',
              text: '[' + article.category + ']' + cvssText,
              size: 'Small', color: 'Accent', weight: 'Bolder'
            }]
          },
          { type: 'TextBlock', text: article.title, size: 'Large', weight: 'Bolder', wrap: true },
          { type: 'TextBlock', text: summary, wrap: true, spacing: 'Small' },
          ...(mitreText ? [{ type: 'TextBlock', text: 'ATT&CK: ' + mitreText, size: 'Small', color: 'Good', spacing: 'Small' }] : [])
        ],
        actions: [
          { type: 'Action.OpenUrl', title: 'ソース記事を開く', url: article.url }
        ]
      }
    }]
  };

  try {
    await fetch(webhook, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
      mode: 'no-cors'
    });
    if(btn){ btn.textContent='SENT'; btn.classList.remove('sending'); }
    setTimeout(function(){ if(btn) btn.textContent='TEAMS'; }, 2000);
  } catch(err){
    if(btn){ btn.textContent='FAILED'; btn.classList.remove('sending'); }
    setTimeout(function(){ if(btn) btn.textContent='TEAMS'; }, 2000);
    console.error('Teams post error:', err);
  }
}

/* ── init ── */
async function init(){
  await loadUserState();
  document.getElementById('total-count').textContent = db.length;
  document.getElementById('today-count').textContent = db.filter(a=>a.date===today).length;
  document.getElementById('poc-count').textContent   = db.filter(a=>isPocValid(a.poc_url)).length;

  // 最終更新日時をlog.jsから取得
  const runLog = window.__RUN_LOG__ || [];
  const lastRun = runLog.length ? runLog[runLog.length-1].datetime_jst : '—';
  const luEl = document.getElementById('last-updated');
  if(luEl) luEl.textContent = lastRun;

  const counts={};
  db.forEach(a=>{counts[a.date]=(counts[a.date]||0)+1;});
  const dates=Object.keys(counts).sort().reverse();

  /* desktop date list */
  const dl=document.getElementById('date-list');
  const allEl=document.createElement('div');
  allEl.className='date-item active';allEl.dataset.date='all';
  allEl.innerHTML=`<span>ALL DATES</span><span class="date-badge">${db.length}</span>`;
  allEl.onclick=()=>setDate('all',allEl,'desk');
  dl.appendChild(allEl);
  dates.forEach(d=>{
    const el=document.createElement('div');
    el.className='date-item';el.dataset.date=d;
    const lbl=d===today?`${d} <span style="color:var(--acc);font-size:.52rem">●</span>`:d;
    el.innerHTML=`<span>${lbl}</span><span class="date-badge">${counts[d]}</span>`;
    el.onclick=()=>setDate(d,el,'desk');
    dl.appendChild(el);
  });

  /* mobile filter buttons */
  const mfw=document.getElementById('mob-filter-wrap');
  ['ALL','MALWARE','INITIAL','POST_EXP','AI_SEC'].forEach(cat=>{
    const b=document.createElement('button');
    b.className='cat-btn'+(cat==='ALL'?' active':'');b.dataset.cat=cat;
    b.textContent=cat==='ALL'?'ALL':cat==='POST_EXP'?'POST':cat==='MALWARE'?'MAL':cat==='INITIAL'?'INIT':'AI';
    b.onclick=()=>{
      document.querySelectorAll('.mob-filter-wrap .cat-btn,.filter-wrap .cat-btn').forEach(x=>x.classList.remove('active'));
      document.querySelectorAll(`[data-cat="${cat}"]`).forEach(x=>x.classList.add('active'));
      activeCat=cat;render();closeMobDrawer();
    };
    mfw.appendChild(b);
  });

  /* mobile date list */
  const mdl=document.getElementById('mob-date-list');
  const mallEl=document.createElement('div');
  mallEl.className='date-item active';mallEl.dataset.date='all';
  mallEl.innerHTML=`<span>ALL DATES</span><span class="date-badge">${db.length}</span>`;
  mallEl.onclick=()=>setDate('all',mallEl,'mob');
  mdl.appendChild(mallEl);
  dates.forEach(d=>{
    const el=document.createElement('div');
    el.className='date-item';el.dataset.date=d;
    el.innerHTML=`<span>${d}</span><span class="date-badge">${counts[d]}</span>`;
    el.onclick=()=>setDate(d,el,'mob');
    mdl.appendChild(el);
  });

  /* desktop category buttons */
  document.querySelectorAll('.filter-wrap .cat-btn').forEach(b=>{
    b.onclick=()=>{
      document.querySelectorAll('.filter-wrap .cat-btn,.mob-filter-wrap .cat-btn').forEach(x=>x.classList.remove('active'));
      document.querySelectorAll(`[data-cat="${b.dataset.cat}"]`).forEach(x=>x.classList.add('active'));
      activeCat=b.dataset.cat;render();
    };
  });

  render();
}

function setDate(d,el,mode){
  activeDate=d;
  const scope=mode==='mob'?'#mob-date-list':'#date-list';
  document.querySelectorAll(scope+' .date-item').forEach(i=>i.classList.remove('active'));
  el.classList.add('active');
  render();
  if(mode==='mob')closeMobDrawer();
}

function render(){
  const q=getQuery();
  const feed=document.getElementById('feed');
  feed.innerHTML='';
  // 未読バッジ数を更新
  const unreadEl = document.querySelector('.cat-btn[data-cat="UNREAD"]');
  if(unreadEl){ const n=unreadCount(); unreadEl.textContent = n > 0 ? `UNREAD ${n}` : 'UNREAD'; }
  const flagEl = document.querySelector('.cat-btn[data-cat="FLAGGED"]');
  if(flagEl){ const n=flaggedCount(); flagEl.textContent = n > 0 ? `⚑ ${n}` : '⚑ FLAG'; }

  const filtered=db.filter(a=>{
    if(isDeleted(a.url)) return false;
    if(activeCat==='UNREAD')  return !isRead(a.url);
    if(activeCat==='FLAGGED') return isFlagged(a.url);
    const mc=activeCat==='ALL'||a.category===activeCat;
    const md=activeDate==='all'||a.date===activeDate;
    const mq=!q||(a.title+(a.summary_points||[]).join(' ')+a.content).toLowerCase().includes(q);
    return mc&&md&&mq;
  });
  if(!filtered.length){feed.innerHTML='<div class="no-data">// NO INTELLIGENCE FOUND //</div>';return;}
  const groups={};
  filtered.forEach(a=>{(groups[a.date]=groups[a.date]||[]).push(a);});
  const frag=document.createDocumentFragment();
  Object.keys(groups).sort().reverse().forEach(date=>{
    const lbl=document.createElement('div');
    lbl.className='day-label';
    lbl.innerHTML=date+(date===today?' &nbsp;<span style="color:var(--acc);font-size:.55rem">TODAY</span>':'');
    frag.appendChild(lbl);
    groups[date].forEach(a=>{
      const card=document.createElement('div');
      card.className='card';card.dataset.cat=a.category;
      const pts=(a.summary_points||[]).slice(0,3);
      const sumHtml=pts.length?'<ul class="card-summary">'+pts.map(p=>`<li>${p}</li>`).join('')+'</ul>':`<div class="card-summary">${a.summary||''}</div>`;
      const cvssHtml=a.cvss_score?`<span class="cvss-badge ${cvssClass(a.cvss_score)}">CVSS ${a.cvss_score}</span>`:'';
      const mitreHtml=(a.mitre_ids||[]).slice(0,3).map(id=>`<span class="mitre-chip">${id}</span>`).join('');
      const sourceHost = (() => { try { return new URL(a.url).hostname.replace('www.',''); } catch(e){ return a.url; } })();
      const pocHtml=isPocValid(a.poc_url)?'<span class="poc-chip">⚡ PoC</span>':'';
      card.innerHTML=`
        <div class="card-meta">
          <span class="cat-tag" data-cat="${a.category}">${a.category}</span>
          <span class="card-date">${a.date}</span>${cvssHtml}
        </div>
        <div class="card-title">${a.title}</div>
        ${sumHtml}
        ${(mitreHtml||pocHtml)?`<div class="card-footer">${mitreHtml}${pocHtml}</div>`:''}
        <a href="${a.url}" target="_blank" class="card-source-link" title="${a.url}">📎 ${sourceHost}</a>`;
      // 未読スタイル
      if(!isRead(a.url)) card.classList.add('unread');
      if(isFlagged(a.url)) card.classList.add('flagged');

      // アクションボタン行
      const actions = document.createElement('div');
      actions.className = 'card-actions';
      actions.innerHTML = `
        <button class="act-btn flag-btn ${isFlagged(a.url)?'flagged':''}">${isFlagged(a.url)?'FLAG ●':'FLAG'}</button>
        <button class="act-btn delete-btn">DEL</button>
      `;
      actions.querySelector('.flag-btn').onclick = async e => {
        e.stopPropagation();
        await toggleFlag(a.url);
        render();
      };
      actions.querySelector('.delete-btn').onclick = async e => {
        e.stopPropagation();
        if(confirm(`「${a.title.slice(0,30)}...」を削除しますか？`)){
          await deleteArticle(a.url); render();
        }
      };
      card.appendChild(actions);
      card.onclick=()=>openDetail(a);
      // ソースリンクはカード全体のクリックイベントを止める
      card.querySelector('.card-source-link').onclick=e=>e.stopPropagation();
      frag.appendChild(card);
    });
  });
  feed.appendChild(frag);
}

async function openDetail(a){
  // 既読マーク
  await markRead(a.url);

  const body=document.getElementById('det-body');
  let metaHtml='';
  if(a.cvss_score) metaHtml+=`<span class="cvss-badge ${cvssClass(a.cvss_score)}" style="font-size:.68rem;padding:4px 10px">CVSS ${a.cvss_score}</span>`;
  (a.mitre_ids||[]).forEach(id=>{metaHtml+=`<span class="mitre-chip">${id}</span>`;});
  if(isPocValid(a.poc_url)) metaHtml+=`<a href="${a.poc_url}" target="_blank" class="poc-btn">⚡ PoC / Exploit Repository</a>`;

  const flagLabel = isFlagged(a.url) ? '⚑ フラグ解除' : '⚐ フラグ';
  body.innerHTML=`
    <div class="det-title">${a.title}</div>
    <div class="det-meta-row">
      <span class="cat-tag" data-cat="${a.category}" style="font-size:.66rem;padding:3px 10px">${a.category}</span>
      <span style="font-family:var(--mono);font-size:.62rem;color:var(--muted)">${a.date}</span>
      ${metaHtml}
    </div>
    <div class="det-action-bar">
      <button class="det-act-btn ${isFlagged(a.url)?'flagged':''}" id="det-flag-btn">${isFlagged(a.url)?'FLAG ●':'FLAG'}</button>
      <button class="det-act-btn delete-btn" id="det-delete-btn">DEL</button>
      <button class="det-act-btn teams-btn" id="det-teams-btn">TEAMS</button>
    </div>
    ${marked.parse(a.content)}
    <div style="margin-top:32px;padding-top:16px;border-top:1px solid var(--bdr)">
      <span style="font-family:var(--mono);font-size:.6rem;color:var(--muted);letter-spacing:.1em">// SOURCE ARTICLE</span><br>
      <a href="${a.url}" target="_blank" style="font-family:var(--mono);font-size:.75rem;color:var(--acc2);word-break:break-all;text-decoration:none;">${a.url}</a>
    </div>`;
  body.querySelectorAll('pre').forEach(pre=>{
    const btn=document.createElement('button');
    btn.className='copy-btn';btn.textContent='COPY';
    btn.onclick=e=>{
      e.stopPropagation();
      const txt=pre.querySelector('code')?.textContent||pre.textContent;
      navigator.clipboard.writeText(txt).then(()=>{btn.textContent='✓ OK';setTimeout(()=>btn.textContent='COPY',1800);});
    };
    pre.appendChild(btn);
  });
  document.getElementById('det-cat-tag').innerHTML=`<span class="cat-tag" data-cat="${a.category}" style="font-size:.66rem;padding:3px 10px">${a.category}</span>`;
  document.getElementById('det-source-url').href=a.url;

  document.getElementById('det-flag-btn').onclick = async () => {
    await toggleFlag(a.url);
    const fb = document.getElementById('det-flag-btn');
    if(fb){ fb.textContent = isFlagged(a.url)?'⚑ フラグ解除':'⚐ フラグ'; fb.classList.toggle('flagged', isFlagged(a.url)); }
    render();
  };
  document.getElementById('det-delete-btn').onclick = async () => {
    if(confirm(`「${a.title.slice(0,30)}...」を削除しますか？`)){
      await deleteArticle(a.url); closeDetail(); render();
    }
  };
  document.getElementById('det-teams-btn').onclick = () => postToTeams(a);

  document.getElementById('detail').classList.add('open');
  history.pushState({view:'detail'},'');
}
function closeDetail(){document.getElementById('detail').classList.remove('open'); render();}
window.onpopstate=()=>closeDetail();

/* ── mobile tab / drawer ── */
let drawerMode=null;
function isMobile(){ return window.innerWidth <= 700; }
function setTab(t){
  if(!isMobile()) return;
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+t)?.classList.add('active');
  if(t==='feed'){closeMobDrawer();}
  else if(t==='filter'||t==='dates'){
    if(drawerMode===t){closeMobDrawer();}
    else{drawerMode=t;document.getElementById('mob-drawer').classList.add('open');}
  }
}
function closeMobDrawer(){
  drawerMode=null;
  document.getElementById('mob-drawer').classList.remove('open');
  document.getElementById('tab-feed')?.classList.add('active');
  document.querySelectorAll('.tab-btn:not(#tab-feed)').forEach(b=>b.classList.remove('active'));
}
window.addEventListener('resize', ()=>{
  if(!isMobile()){
    closeMobDrawer();
    document.getElementById('mob-drawer').classList.remove('open');
  }
});

init();
</script>
</body>
</html>"""


def _build_log_html() -> str:
    return """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3CradialGradient id='g' cx='50%25' cy='40%25'%3E%3Cstop offset='0' stop-color='%2338bfff' stop-opacity='.9'/%3E%3Cstop offset='1' stop-color='%230a1628' stop-opacity='1'/%3E%3C/radialGradient%3E%3C/defs%3E%3Cpolygon points='16,2 28,9 28,23 16,30 4,23 4,9' fill='%230d1a2e' stroke='%2338bfff' stroke-width='1.5'/%3E%3Cpolygon points='16,6 24,10.5 24,21.5 16,26 8,21.5 8,10.5' fill='none' stroke='%2338bfff' stroke-width='.6' stroke-opacity='.4'/%3E%3Ctext x='16' y='21' text-anchor='middle' font-family='monospace' font-weight='700' font-size='13' fill='url(%23g)' letter-spacing='-1'%3EC%3C/text%3E%3Ccircle cx='16' cy='16' r='1.2' fill='%2338bfff' opacity='.7'/%3E%3Cline x1='16' y1='6' x2='16' y2='9' stroke='%2338bfff' stroke-width='.8' opacity='.5'/%3E%3Cline x1='16' y1='23' x2='16' y2='26' stroke='%2338bfff' stroke-width='.8' opacity='.5'/%3E%3Cline x1='4' y1='9' x2='6.5' y2='10.5' stroke='%2338bfff' stroke-width='.8' opacity='.5'/%3E%3Cline x1='27.5' y1='10.5' x2='28' y2='9' stroke='%2338bfff' stroke-width='.8' opacity='.5'/%3E%3C/svg%3E">
<title>CIPHER // RUN LOG</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700&family=Noto+Sans+JP:wght@300;400&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080d14;--surf:#0d1220;--surf2:#111a2e;--bdr:#162040;--bdr2:#1e3060;
  --text:#7a9ec4;--hi:#c8dff5;--muted:#1e3050;--acc:#38bfff;--acc2:#f0c040;
  --mono:'JetBrains Mono',monospace;--sans:'Noto Sans JP',sans-serif;--disp:'Rajdhani',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;padding:24px 16px 40px}
.page{max-width:720px;margin:0 auto}
.page-header{margin-bottom:28px;padding-bottom:16px;border-bottom:1px solid var(--bdr);position:relative}
.page-header::after{content:'';position:absolute;bottom:0;left:0;width:120px;height:1px;background:var(--acc)}
.back-link{
  display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:.65rem;
  color:var(--muted);text-decoration:none;border:1px solid var(--bdr2);
  padding:4px 10px;border-radius:2px;margin-bottom:14px;transition:.15s;
}
.back-link:hover{color:var(--acc);border-color:var(--acc)}
.page-title{font-family:var(--disp);font-size:1.8rem;font-weight:700;color:var(--acc);
  letter-spacing:.1em;text-shadow:0 0 20px rgba(56,191,255,.25)}
.page-sub{font-family:var(--mono);font-size:.6rem;color:var(--muted);letter-spacing:.15em;margin-top:4px}
.summary-row{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:24px}
.stat-card{background:var(--surf);border:1px solid var(--bdr);border-radius:4px;padding:14px;text-align:center}
.stat-card-val{font-family:var(--disp);font-size:1.6rem;font-weight:700;color:var(--acc);
  text-shadow:0 0 10px rgba(56,191,255,.25);display:block}
.stat-card-lbl{font-family:var(--mono);font-size:.55rem;color:var(--muted);letter-spacing:.1em;margin-top:3px}
.section-title{font-family:var(--mono);font-size:.62rem;letter-spacing:.15em;color:var(--muted);
  margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--bdr)}
.log-table{width:100%;border-collapse:collapse;font-size:.8rem}
.log-table th{
  background:var(--surf2);padding:9px 12px;text-align:left;
  border:1px solid var(--bdr);color:var(--hi);
  font-family:var(--mono);font-size:.6rem;letter-spacing:.08em;
}
.log-table td{padding:9px 12px;border:1px solid var(--bdr);color:var(--text)}
.log-table tr:hover td{background:var(--surf2)}
.log-table tr.today-row td{color:var(--hi)}
.badge-new{
  font-family:var(--mono);font-size:.55rem;background:rgba(56,191,255,.1);
  color:var(--acc);border:1px solid rgba(56,191,255,.2);
  padding:1px 6px;border-radius:2px;margin-left:6px;
}
.badge-zero{font-family:var(--mono);font-size:.55rem;color:var(--muted)}
.no-log{text-align:center;padding:60px 20px;font-family:var(--mono);color:var(--muted);font-size:.72rem}
@media(max-width:500px){
  .summary-row{grid-template-columns:1fr 1fr}
  .log-table th:last-child,.log-table td:last-child{display:none}
}
</style>
</head>
<body>
<div class="page">
  <div class="page-header">
    <a href="index.html" class="back-link">← CIPHER</a>
    <div class="page-title">RUN LOG</div>
    <div class="page-sub">// AI調査実行履歴</div>
  </div>
  <div class="summary-row" id="summary-row"></div>
  <div class="section-title">// 実行履歴（新しい順）</div>
  <div id="log-wrap"></div>
</div>
<script src="log.js"></script>
<script>
const log = (window.__RUN_LOG__ || []).slice().reverse();
const today = new Date().toISOString().slice(0,10);
const totalRuns = log.length;
const totalNew  = log.reduce((s,r)=>s+(r.new_articles||0),0);
const lastRun   = log[0]?.datetime_jst || '—';
document.getElementById('summary-row').innerHTML = `
  <div class="stat-card"><span class="stat-card-val">${totalRuns}</span><div class="stat-card-lbl">TOTAL RUNS</div></div>
  <div class="stat-card"><span class="stat-card-val">${totalNew}</span><div class="stat-card-lbl">ARTICLES COLLECTED</div></div>
  <div class="stat-card"><span class="stat-card-val" style="font-size:1rem;padding-top:4px">${lastRun}</span><div class="stat-card-lbl">LAST RUN (JST)</div></div>`;
const wrap = document.getElementById('log-wrap');
if(!log.length){
  wrap.innerHTML='<div class="no-log">// 実行ログがありません</div>';
} else {
  wrap.innerHTML = `<table class="log-table">
    <thead><tr><th>実行日時 (JST)</th><th>新規取得</th><th>累計件数</th></tr></thead>
    <tbody>${log.map(r=>{
      const isToday=r.datetime_jst?.startsWith(today);
      const nb=r.new_articles>0?`<span class="badge-new">+${r.new_articles}</span>`:`<span class="badge-zero">±0</span>`;
      return `<tr class="${isToday?'today-row':''}">
        <td>${r.datetime_jst}${isToday?'<span class="badge-new" style="margin-left:6px">TODAY</span>':''}</td>
        <td>${nb}</td><td>${r.total_articles??'—'}</td></tr>`;
    }).join('')}</tbody>
  </table>`;
}
</script>
</body>
</html>"""

# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    db = load_db()
    existing_urls = {a["url"] for a in db}
    new_data = fetch_and_analyze(existing_urls)
    db = update_db(db, new_data)
    run_log = load_run_log()
    run_log = append_run_log(run_log, len(new_data), len(db))
    generate_html(db, run_log)
