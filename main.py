"""
RED-TACTICAL INTELLIGENCE AGENT v3.0
=====================================
v3.0 fixes & improvements:
[CRITICAL] データ注入をJSONファイル分離方式に変更（HTMLへの直接埋め込みを廃止）
[CRITICAL] deepseek-r1の<think>タグ対応を強化（貪欲マッチを非貪欲に修正）
[CRITICAL] all_articles.json / index.htmlをGitHub Actionsで確実にコミットする想定に対応
[QUALITY]  攻撃者視点への強制変換プロンプト（防御寄りソースも攻撃手順に落とし込む）
[QUALITY]  コマンド例にフルオプション・ターゲット・パイプを必須化
[QUALITY]  検索ソースをセキュリティ特化ドメインへ誘導するクエリ設計
[QUALITY]  poc_url / cvss_score のバリデーション強化（"N/A"等を除外）
[QUALITY]  タイトル重複チェックで実質的な重複記事を排除
[UI]       summaryをHTML箇条書きで表示
[UI]       スキャンライン・グリッド・グロー等のターミナル風UIに刷新
"""

import os
import json
import re
import time
import hashlib
from tavily import TavilyClient
from groq import Groq
from datetime import datetime

# ─────────────────────────────────────────────
# 設定
# ─────────────────────────────────────────────
TAVILY_KEY  = os.getenv("TAVILY_API_KEY")
GROQ_KEY    = os.getenv("GROQ_API_KEY")
tavily      = TavilyClient(api_key=TAVILY_KEY)
groq_client = Groq(api_key=GROQ_KEY)

MASTER_DATA      = "all_articles.json"
OUTPUT_HTML      = "index.html"
MAX_DB_ENTRIES   = 200
MIN_REPORT_LEN   = 500    # 品質フィルタ
MAX_RETRIES      = 3
SLEEP_BETWEEN_REQ = 2.5  # Groq無料枠レート制限対策

PRIMARY_MODEL  = "deepseek-r1-distill-llama-70b"
FALLBACK_MODEL = "llama-3.3-70b-versatile"

# ─────────────────────────────────────────────
# 検索クエリ（セキュリティ研究ソースに誘導）
# ─────────────────────────────────────────────
SEARCH_CATEGORIES = {
    "MALWARE": [
        "malware technical analysis shellcode loader evasion technique site:github.com OR site:securelist.com OR site:unit42.paloaltonetworks.com",
        "new malware campaign persistence LOLBAS fileless 2026",
        "RAT backdoor C2 communication protocol obfuscation analysis",
    ],
    "INITIAL": [
        "CVE 2026 critical RCE exploit proof of concept published",
        "authentication bypass vulnerability exploit walkthrough writeup",
        "zero day exploit initial access broker attack chain 2026",
    ],
    "POST_EXP": [
        "Active Directory privilege escalation new technique kerberoasting RBCD 2026",
        "EDR bypass AV evasion Windows technique 2026 writeup",
        "lateral movement credential dumping LSASS new method",
    ],
    "AI_SEC": [
        "LLM prompt injection jailbreak exploit technique 2026",
        "MCP tool poisoning agentic AI attack vector 2026",
        "AI red team attack adversarial machine learning exploit",
    ],
}

MAX_RESULTS_PER_QUERY = 2

# ─────────────────────────────────────────────
# プロンプト（攻撃者視点への強制変換）
# ─────────────────────────────────────────────
CATEGORY_FOCUS = {
    "MALWARE":  "マルウェアのローダー機構・難読化アルゴリズム・C2通信プロトコル・永続化レジストリキーを攻撃者目線で詳述",
    "INITIAL":  "脆弱性のroot cause（バグの本質）・exploitの具体的トリガー条件・ターゲットバージョン・bypass条件を攻撃者目線で詳述",
    "POST_EXP": "権限昇格・横断的侵害・認証情報窃取の具体的ツールチェーンとコマンドを攻撃者目線で詳述",
    "AI_SEC":   "LLM/AIへの攻撃ペイロード例・bypass手法・影響範囲を攻撃者目線で詳述",
}

def build_prompt(content: str, category: str) -> str:
    focus = CATEGORY_FOCUS.get(category, "攻撃手法を詳述")
    return f"""You are an elite red team operator writing an internal technical intelligence report.
Your audience: red teamers who will actually use this to reproduce attacks. They need zero fluff.
Focus: {focus}

SOURCE ARTICLE:
{content[:9000]}

TASK:
Transform the above source (which may be written from a DEFENDER's perspective) into a RED TEAM OPERATOR'S technical report.
If the source is vague, infer the most likely technical mechanism from your knowledge and clearly label it "[推測]".

STRICT OUTPUT RULES:
1. Output ONLY a single valid JSON object. Absolutely NO text outside the JSON.
2. NO markdown fences (``` or ```json) wrapping the JSON.
3. All string values use \\n for newlines.
4. report field: full markdown, Japanese, with these exact sections:
   ## 概要
   ## 脆弱性・脅威の技術的メカニズム  ← root causeを詳述
   ## 攻撃シナリオ（ステップバイステップ）  ← 番号付きリスト、具体的アクション
   ## 実行コマンド  ← 実際のツール+フルオプション+ターゲット例。必ず ```bash コードブロック
   ## MITRE ATT&CK マッピング
   ## 検知シグネチャ・緩和策  ← Sigmaまたはyara snippetを含む

COMMAND EXAMPLES MUST BE CONCRETE. BAD: "impacket-secretsdump を使う". GOOD:
```bash
impacket-secretsdump -just-dc-ntlm DOMAIN/user:password@192.168.1.10 -outputfile hashes.txt
```

JSON SCHEMA (output exactly this structure):
{{
  "title": "客観的な日本語ニュース見出し（30字以内）",
  "summary_points": ["技術的要点1", "技術的要点2", "技術的要点3"],
  "poc_url": "GitHubやExploit-DBのURL、なければ空文字列のみ",
  "cvss_score": "数値のみ（例: 9.8）、なければ空文字列のみ",
  "mitre_ids": ["T1059.001"],
  "report": "## 概要\\n..."
}}"""

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
    return True

# ─────────────────────────────────────────────
# LLM呼び出し（モデルフォールバック付きリトライ）
# ─────────────────────────────────────────────
def call_llm(prompt: str) -> dict | None:
    for model in [PRIMARY_MODEL, FALLBACK_MODEL]:
        for attempt in range(MAX_RETRIES):
            try:
                resp = groq_client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=4096,
                    # json_objectモードはdeepseek-r1で不安定なため使用しない
                    # → プロンプトで制御し extract_json で取り出す
                )
                raw = resp.choices[0].message.content
                result = extract_json(raw)

                if result and validate_result(result):
                    print(f"    ✓ [{model}] attempt {attempt+1} — OK")
                    return result

                print(f"    ✗ [{model}] attempt {attempt+1} — 品質不足, retry...")
                time.sleep(2)

            except Exception as e:
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
# 情報収集メイン
# ─────────────────────────────────────────────
def fetch_and_analyze() -> list[dict]:
    print("=" * 50)
    print("  RED-INTEL AGENT v3.0 — 情報収集開始")
    print("=" * 50)

    new_articles: list[dict] = []
    seen_urls    = set()
    seen_title_hashes = set()

    for cat_id, queries in SEARCH_CATEGORIES.items():
        print(f"\n[{cat_id}] ───────────────────────")
        cat_count = 0

        for query in queries:
            try:
                results = tavily.search(
                    query=query,
                    search_depth="advanced",
                    max_results=MAX_RESULTS_PER_QUERY,
                    search_period="week",
                )["results"]

                for item in results:
                    url     = item.get("url", "")
                    content = item.get("content", "")

                    # 重複URL
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)

                    # コンテンツ不足
                    if len(content) < 400:
                        print(f"  skip (short content): {url[:60]}")
                        continue

                    print(f"  → {url[:70]}")

                    prompt = build_prompt(content, cat_id)
                    result = call_llm(prompt)

                    if result is None:
                        print(f"    ✗ 解析失敗 — skip")
                        continue

                    # タイトル重複チェック
                    th = title_hash(result["title"])
                    if th in seen_title_hashes:
                        print(f"    ✗ タイトル重複 — skip: {result['title'][:40]}")
                        continue
                    seen_title_hashes.add(th)

                    new_articles.append({
                        "date":         datetime.now().strftime("%Y-%m-%d"),
                        "category":     cat_id,
                        "title":        result["title"],
                        "summary_points": result.get("summary_points", []),
                        "poc_url":      result.get("poc_url", ""),
                        "cvss_score":   result.get("cvss_score", ""),
                        "mitre_ids":    result.get("mitre_ids", []),
                        "content":      result["report"],
                        "url":          url,
                    })
                    cat_count += 1
                    time.sleep(SLEEP_BETWEEN_REQ)

            except Exception as e:
                print(f"  ✗ Tavily検索エラー ({query[:40]}): {e}")
                continue

        print(f"  [{cat_id}] {cat_count} 件取得")

    print(f"\n{'='*50}")
    print(f"  完了: 合計 {len(new_articles)} 件")
    print(f"{'='*50}")
    return new_articles

# ─────────────────────────────────────────────
# DB更新
# ─────────────────────────────────────────────
def update_db(new_entries: list[dict]) -> list[dict]:
    db: list[dict] = []
    if os.path.exists(MASTER_DATA):
        try:
            with open(MASTER_DATA, "r", encoding="utf-8") as f:
                db = json.load(f)
        except Exception:
            db = []

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
# HTML生成
# ─────────────────────────────────────────────
# [FIX] データをHTMLに直接埋め込まず、articles.jsとして分離。
#       これによりPythonのraw文字列とのエスケープ衝突・
#       INSERT_DATA_HERE二重置換問題を根本的に解決する。
# index.htmlはarticles.jsをscript srcで読み込む構成。

def generate_html(db: list[dict]) -> None:
    # articles.js に書き出し
    articles_js_path = "articles.js"
    js_content = "window.__ARTICLES__ = " + json.dumps(db, ensure_ascii=False) + ";"
    with open(articles_js_path, "w", encoding="utf-8") as f:
        f.write(js_content)
    print(f"データ書き出し: {articles_js_path}")

    # index.html（articles.jsを読み込む）
    html = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RT-INTEL // RED TEAM INTELLIGENCE</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=IBM+Plex+Sans+JP:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:        #050810;
  --surface:   #090e1a;
  --surface2:  #0d1525;
  --border:    #0f2040;
  --border2:   #1a3060;
  --text:      #8ba8cc;
  --text-hi:   #c8dff5;
  --muted:     #2a4060;
  --green:     #00e5ff;
  --green2:    #00ff9d;
  --red:       #ff3a5e;
  --orange:    #ff8c00;
  --purple:    #9b59ff;
  --blue:      #2196f3;
  --MALWARE:   #ff3a5e;
  --INITIAL:   #ff8c00;
  --POST_EXP:  #9b59ff;
  --AI_SEC:    #00e5ff;
  --mono:      'Space Mono', monospace;
  --sans:      'IBM Plex Sans JP', sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{
  font-family:var(--sans);
  background:var(--bg);
  color:var(--text);
  display:flex;
  font-size:13px;
  /* スキャンライン */
  background-image:
    repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,229,255,0.012) 2px,
      rgba(0,229,255,0.012) 4px
    );
}

/* ── ターミナルグリッド背景 ── */
body::before{
  content:'';
  position:fixed;inset:0;
  background-image:
    linear-gradient(rgba(0,229,255,0.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,229,255,0.03) 1px,transparent 1px);
  background-size:40px 40px;
  pointer-events:none;
  z-index:0;
}

/* ── Sidebar ── */
nav{
  width:260px;
  background:var(--surface);
  border-right:1px solid var(--border);
  display:flex;
  flex-direction:column;
  flex-shrink:0;
  position:relative;
  z-index:10;
}
.logo{
  padding:18px 16px 14px;
  border-bottom:1px solid var(--border);
  position:relative;
}
.logo::after{
  content:'';
  position:absolute;
  bottom:0;left:0;right:0;
  height:1px;
  background:linear-gradient(90deg, var(--green), transparent);
}
.logo-mark{
  font-family:var(--mono);
  font-size:.65rem;
  color:var(--muted);
  letter-spacing:.2em;
  margin-bottom:6px;
}
.logo-title{
  font-family:var(--mono);
  font-size:1.1rem;
  font-weight:700;
  color:var(--green);
  letter-spacing:.12em;
  text-shadow:0 0 20px rgba(0,229,255,.4);
}
.logo-sub{
  font-size:.65rem;
  color:var(--muted);
  margin-top:3px;
  letter-spacing:.05em;
}
.search-wrap{padding:10px 12px;border-bottom:1px solid var(--border)}
#search-box{
  width:100%;
  padding:8px 12px 8px 30px;
  background:var(--bg);
  border:1px solid var(--border2);
  color:var(--text-hi);
  border-radius:4px;
  outline:none;
  font-family:var(--mono);
  font-size:.75rem;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' fill='%232a4060' viewBox='0 0 16 16'%3E%3Cpath d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z'/%3E%3C/svg%3E");
  background-repeat:no-repeat;
  background-position:10px center;
  transition:.2s;
}
#search-box:focus{border-color:var(--green);box-shadow:0 0 0 2px rgba(0,229,255,.1)}
#search-box::placeholder{color:var(--muted)}

.filter-wrap{padding:8px 10px;border-bottom:1px solid var(--border);display:flex;gap:5px;flex-wrap:wrap}
.cat-btn{
  padding:4px 10px;
  border-radius:3px;
  border:1px solid var(--border2);
  background:none;
  color:var(--muted);
  cursor:pointer;
  font-family:var(--mono);
  font-size:.62rem;
  font-weight:700;
  letter-spacing:.08em;
  transition:.15s;
}
.cat-btn:hover{color:var(--text-hi);border-color:var(--text)}
.cat-btn.active[data-cat="ALL"]{background:rgba(0,229,255,.12);border-color:var(--green);color:var(--green)}
.cat-btn.active[data-cat="MALWARE"]{background:rgba(255,58,94,.12);border-color:var(--MALWARE);color:var(--MALWARE)}
.cat-btn.active[data-cat="INITIAL"]{background:rgba(255,140,0,.12);border-color:var(--INITIAL);color:var(--INITIAL)}
.cat-btn.active[data-cat="POST_EXP"]{background:rgba(155,89,255,.12);border-color:var(--POST_EXP);color:var(--POST_EXP)}
.cat-btn.active[data-cat="AI_SEC"]{background:rgba(0,229,255,.12);border-color:var(--AI_SEC);color:var(--AI_SEC)}

.date-list{flex:1;overflow-y:auto;padding:8px}
.date-group-label{
  font-family:var(--mono);
  font-size:.58rem;
  color:var(--muted);
  letter-spacing:.12em;
  padding:8px 10px 4px;
}
.date-item{
  padding:8px 10px;
  border-radius:4px;
  cursor:pointer;
  font-family:var(--mono);
  font-size:.72rem;
  color:var(--muted);
  margin-bottom:2px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  transition:.15s;
  border:1px solid transparent;
}
.date-item:hover{background:var(--surface2);color:var(--text-hi);border-color:var(--border2)}
.date-item.active{
  background:var(--surface2);
  color:var(--green);
  border-color:var(--border2);
}
.date-badge{
  font-size:.6rem;
  background:var(--border);
  color:var(--muted);
  padding:2px 6px;
  border-radius:2px;
}

.stats-bar{
  padding:10px 14px;
  border-top:1px solid var(--border);
  display:grid;
  grid-template-columns:1fr 1fr 1fr;
  gap:6px;
}
.stat{
  font-family:var(--mono);
  font-size:.58rem;
  color:var(--muted);
  text-align:center;
}
.stat-val{
  display:block;
  font-size:.9rem;
  font-weight:700;
  color:var(--green);
  text-shadow:0 0 10px rgba(0,229,255,.3);
}

/* ── Feed ── */
main{flex:1;overflow-y:auto;padding:16px 18px;position:relative;z-index:1}
.feed{max-width:860px;margin:0 auto}
.day-label{
  font-family:var(--mono);
  font-size:.62rem;
  letter-spacing:.18em;
  color:var(--muted);
  text-transform:uppercase;
  padding:16px 2px 8px;
  border-bottom:1px solid var(--border);
  margin-bottom:10px;
  display:flex;
  align-items:center;
  gap:10px;
}
.day-label::before{content:'//';color:var(--green);opacity:.5}

/* ── Card ── */
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:5px;
  padding:16px 18px;
  margin-bottom:8px;
  cursor:pointer;
  transition:.18s;
  position:relative;
  overflow:hidden;
}
.card::before{
  content:'';
  position:absolute;
  left:0;top:0;bottom:0;
  width:2px;
  transition:.18s;
}
.card[data-cat="MALWARE"]::before{background:var(--MALWARE);box-shadow:0 0 8px var(--MALWARE)}
.card[data-cat="INITIAL"]::before{background:var(--INITIAL);box-shadow:0 0 8px var(--INITIAL)}
.card[data-cat="POST_EXP"]::before{background:var(--POST_EXP);box-shadow:0 0 8px var(--POST_EXP)}
.card[data-cat="AI_SEC"]::before{background:var(--AI_SEC);box-shadow:0 0 8px var(--AI_SEC)}
.card:hover{
  background:var(--surface2);
  border-color:var(--border2);
  transform:translateX(2px);
}
.card-meta{display:flex;align-items:center;gap:8px;margin-bottom:9px}
.cat-tag{
  font-family:var(--mono);
  font-size:.58rem;
  font-weight:700;
  padding:3px 8px;
  border-radius:2px;
  letter-spacing:.08em;
}
.cat-tag[data-cat="MALWARE"]{background:rgba(255,58,94,.15);color:var(--MALWARE);border:1px solid rgba(255,58,94,.3)}
.cat-tag[data-cat="INITIAL"]{background:rgba(255,140,0,.15);color:var(--INITIAL);border:1px solid rgba(255,140,0,.3)}
.cat-tag[data-cat="POST_EXP"]{background:rgba(155,89,255,.15);color:var(--POST_EXP);border:1px solid rgba(155,89,255,.3)}
.cat-tag[data-cat="AI_SEC"]{background:rgba(0,229,255,.12);color:var(--AI_SEC);border:1px solid rgba(0,229,255,.25)}
.card-date{font-family:var(--mono);font-size:.62rem;color:var(--muted)}
.cvss-badge{
  font-family:var(--mono);font-size:.6rem;font-weight:700;
  padding:2px 7px;border-radius:2px;margin-left:auto;
}
.cvss-critical{background:rgba(255,58,94,.15);color:#ff3a5e;border:1px solid rgba(255,58,94,.3)}
.cvss-high{background:rgba(255,140,0,.15);color:#ff8c00;border:1px solid rgba(255,140,0,.3)}
.cvss-medium{background:rgba(250,204,21,.15);color:#facc15;border:1px solid rgba(250,204,21,.3)}
.cvss-low{background:rgba(0,255,157,.1);color:#00ff9d;border:1px solid rgba(0,255,157,.2)}
.card-title{
  font-family:var(--sans);
  font-size:.95rem;
  font-weight:700;
  color:var(--text-hi);
  line-height:1.45;
  margin-bottom:10px;
}
.card-summary{
  font-size:.78rem;
  color:var(--text);
  line-height:1.7;
  list-style:none;
  padding:0;
}
.card-summary li{
  padding:2px 0 2px 14px;
  position:relative;
}
.card-summary li::before{
  content:'›';
  position:absolute;left:0;
  color:var(--green);
  font-weight:700;
}
.card-footer{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.mitre-chip{
  font-family:var(--mono);
  font-size:.58rem;
  background:rgba(155,89,255,.1);
  color:#b07aff;
  border:1px solid rgba(155,89,255,.2);
  padding:2px 7px;
  border-radius:2px;
}
.poc-chip{
  font-family:var(--mono);
  font-size:.58rem;
  background:rgba(0,255,157,.08);
  color:var(--green2);
  border:1px solid rgba(0,255,157,.2);
  padding:2px 7px;
  border-radius:2px;
  animation:pulse-poc 2s infinite;
}
@keyframes pulse-poc{0%,100%{opacity:1}50%{opacity:.6}}

.no-data{
  text-align:center;
  padding:80px 20px;
  font-family:var(--mono);
  color:var(--muted);
  font-size:.75rem;
  letter-spacing:.1em;
}

/* ── Detail View ── */
#detail{
  position:fixed;inset:0;
  background:var(--bg);
  z-index:100;
  display:flex;
  flex-direction:column;
  transform:translateX(100%);
  transition:transform .28s cubic-bezier(.4,0,.2,1);
}
#detail.open{transform:none}

.det-header{
  background:rgba(9,14,26,.95);
  backdrop-filter:blur(12px);
  border-bottom:1px solid var(--border);
  padding:12px 18px;
  display:flex;
  align-items:center;
  gap:12px;
  flex-shrink:0;
  position:relative;
}
.det-header::after{
  content:'';
  position:absolute;
  bottom:0;left:0;right:0;
  height:1px;
  background:linear-gradient(90deg,var(--green),transparent 60%);
}
.back-btn{
  background:none;
  border:1px solid var(--border2);
  color:var(--green);
  padding:6px 14px;
  border-radius:3px;
  cursor:pointer;
  font-family:var(--mono);
  font-size:.7rem;
  font-weight:700;
  transition:.15s;
  letter-spacing:.05em;
}
.back-btn:hover{background:rgba(0,229,255,.08)}
.det-url{
  margin-left:auto;
  font-family:var(--mono);
  font-size:.62rem;
  color:var(--muted);
  text-decoration:none;
}
.det-url:hover{color:var(--text)}

.det-body{flex:1;overflow-y:auto;padding:36px 24px}
.det-inner{max-width:820px;margin:0 auto}
.det-title{
  font-family:var(--sans);
  font-size:1.55rem;
  font-weight:700;
  color:var(--text-hi);
  line-height:1.35;
  margin-bottom:18px;
}
.det-meta-row{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  align-items:center;
  margin-bottom:24px;
  padding-bottom:18px;
  border-bottom:1px solid var(--border);
}
.poc-btn{
  display:inline-flex;
  align-items:center;
  gap:6px;
  background:rgba(0,255,157,.1);
  color:var(--green2);
  border:1px solid rgba(0,255,157,.3);
  padding:8px 18px;
  border-radius:3px;
  text-decoration:none;
  font-family:var(--mono);
  font-weight:700;
  font-size:.72rem;
  letter-spacing:.05em;
  transition:.15s;
}
.poc-btn:hover{background:rgba(0,255,157,.18);box-shadow:0 0 16px rgba(0,255,157,.2)}

/* Markdown レンダリング */
.det-inner h1{display:none}
.det-inner h2{
  font-family:var(--mono);
  font-size:.78rem;
  font-weight:700;
  color:var(--green);
  letter-spacing:.15em;
  text-transform:uppercase;
  border-bottom:1px solid var(--border);
  padding-bottom:7px;
  margin:32px 0 12px;
}
.det-inner h3{
  font-size:.88rem;
  font-weight:600;
  color:var(--text-hi);
  margin:18px 0 8px;
}
.det-inner p{line-height:1.8;margin-bottom:10px;color:var(--text)}
.det-inner ul,.det-inner ol{padding-left:20px;margin-bottom:10px;line-height:1.8}
.det-inner li{margin-bottom:4px;color:var(--text)}
.det-inner pre{
  background:#020610;
  border:1px solid var(--border2);
  border-left:2px solid var(--green);
  border-radius:4px;
  padding:18px 18px 18px 20px;
  overflow-x:auto;
  margin:14px 0;
  position:relative;
}
.det-inner code{
  font-family:var(--mono);
  font-size:.78rem;
  color:var(--green2);
  line-height:1.7;
}
.det-inner :not(pre)>code{
  background:rgba(0,229,255,.07);
  padding:2px 6px;
  border-radius:2px;
  font-size:.78rem;
  color:var(--green);
}
.det-inner blockquote{
  border-left:2px solid var(--border2);
  padding-left:14px;
  color:var(--muted);
  margin:10px 0;
}
.det-inner table{width:100%;border-collapse:collapse;margin:14px 0;font-size:.78rem}
.det-inner th{background:var(--surface2);padding:8px 12px;text-align:left;border:1px solid var(--border);color:var(--text-hi);font-family:var(--mono);font-size:.65rem;letter-spacing:.08em}
.det-inner td{padding:7px 12px;border:1px solid var(--border);color:var(--text)}
.det-inner strong{color:var(--text-hi)}

.copy-btn{
  position:absolute;
  top:10px;right:10px;
  background:var(--surface2);
  border:1px solid var(--border2);
  color:var(--muted);
  font-family:var(--mono);
  font-size:.6rem;
  padding:3px 8px;
  border-radius:2px;
  cursor:pointer;
  transition:.15s;
  letter-spacing:.05em;
}
.copy-btn:hover{color:var(--green);border-color:var(--green)}

::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:10px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}
</style>
</head>
<body>

<nav>
  <div class="logo">
    <div class="logo-mark">// THREAT INTELLIGENCE</div>
    <div class="logo-title">RT-INTEL</div>
    <div class="logo-sub">Red Team Operator Feed</div>
  </div>
  <div class="search-wrap">
    <input type="text" id="search-box" placeholder="search intel...">
  </div>
  <div class="filter-wrap">
    <button class="cat-btn active" data-cat="ALL">ALL</button>
    <button class="cat-btn" data-cat="MALWARE">MAL</button>
    <button class="cat-btn" data-cat="INITIAL">INIT</button>
    <button class="cat-btn" data-cat="POST_EXP">POST</button>
    <button class="cat-btn" data-cat="AI_SEC">AI</button>
  </div>
  <div class="date-group-label">// DATE FILTER</div>
  <div class="date-list" id="date-list"></div>
  <div class="stats-bar">
    <div class="stat"><span class="stat-val" id="total-count">0</span>TOTAL</div>
    <div class="stat"><span class="stat-val" id="today-count">0</span>TODAY</div>
    <div class="stat"><span class="stat-val" id="poc-count">0</span>PoC</div>
  </div>
</nav>

<main>
  <div class="feed" id="feed"></div>
</main>

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

<script src="articles.js"></script>
<script>
const db = window.__ARTICLES__ || [];
let activeCat  = 'ALL';
let activeDate = 'all';
const today = new Date().toISOString().slice(0,10);

function cvssClass(s) {
  const n = parseFloat(s);
  if (!isNaN(n)) {
    if (n >= 9.0) return 'cvss-critical';
    if (n >= 7.0) return 'cvss-high';
    if (n >= 4.0) return 'cvss-medium';
    return 'cvss-low';
  }
  return '';
}

function isPocValid(url) {
  return url && url.startsWith('http');
}

function init() {
  // 統計
  document.getElementById('total-count').textContent = db.length;
  document.getElementById('today-count').textContent = db.filter(a=>a.date===today).length;
  document.getElementById('poc-count').textContent   = db.filter(a=>isPocValid(a.poc_url)).length;

  // 日付リスト
  const counts = {};
  db.forEach(a => { counts[a.date] = (counts[a.date]||0)+1; });
  const dates = Object.keys(counts).sort().reverse();
  const list = document.getElementById('date-list');

  const allEl = document.createElement('div');
  allEl.className = 'date-item active'; allEl.dataset.date = 'all';
  allEl.innerHTML = `<span>ALL DATES</span><span class="date-badge">${db.length}</span>`;
  allEl.onclick = () => setDate('all', allEl);
  list.appendChild(allEl);

  dates.forEach(d => {
    const el = document.createElement('div');
    el.className = 'date-item'; el.dataset.date = d;
    const label = d === today ? `${d} <span style="color:var(--green);font-size:.55rem">● NEW</span>` : d;
    el.innerHTML = `<span>${label}</span><span class="date-badge">${counts[d]}</span>`;
    el.onclick = () => setDate(d, el);
    list.appendChild(el);
  });

  document.querySelectorAll('.cat-btn').forEach(b => {
    b.onclick = () => {
      document.querySelectorAll('.cat-btn').forEach(x=>x.classList.remove('active'));
      b.classList.add('active');
      activeCat = b.dataset.cat;
      render();
    };
  });
  document.getElementById('search-box').oninput = render;
  render();
}

function setDate(d, el) {
  activeDate = d;
  document.querySelectorAll('.date-item').forEach(i=>i.classList.remove('active'));
  el.classList.add('active');
  render();
}

function render() {
  const q = document.getElementById('search-box').value.toLowerCase();
  const feed = document.getElementById('feed');
  feed.innerHTML = '';

  const filtered = db.filter(a => {
    const matchCat  = activeCat === 'ALL' || a.category === activeCat;
    const matchDate = activeDate === 'all' || a.date === activeDate;
    const matchQ    = !q || (a.title + (a.summary_points||[]).join(' ') + a.content).toLowerCase().includes(q);
    return matchCat && matchDate && matchQ;
  });

  if (!filtered.length) {
    feed.innerHTML = '<div class="no-data">// NO INTELLIGENCE FOUND //</div>';
    return;
  }

  // 日付グループ
  const groups = {};
  filtered.forEach(a => { (groups[a.date]=groups[a.date]||[]).push(a); });

  Object.keys(groups).sort().reverse().forEach(date => {
    const lbl = document.createElement('div');
    lbl.className = 'day-label';
    lbl.innerHTML = date + (date===today ? ' &nbsp;<span style="color:var(--green);font-size:.58rem">TODAY</span>' : '');
    feed.appendChild(lbl);

    groups[date].forEach(a => {
      const card = document.createElement('div');
      card.className = 'card'; card.dataset.cat = a.category;

      // summary_pointsをliリストに
      const points = (a.summary_points||[]).slice(0,3);
      const summaryHtml = points.length
        ? '<ul class="card-summary">' + points.map(p=>`<li>${p}</li>`).join('') + '</ul>'
        : `<div class="card-summary">${a.summary||''}</div>`;

      const cvss = a.cvss_score;
      const cvssHtml = cvss
        ? `<span class="cvss-badge ${cvssClass(cvss)}">CVSS ${cvss}</span>`
        : '';

      const mitreHtml = (a.mitre_ids||[]).slice(0,3).map(id=>`<span class="mitre-chip">${id}</span>`).join('');
      const pocHtml   = isPocValid(a.poc_url) ? `<span class="poc-chip">⚡ PoC</span>` : '';

      card.innerHTML = `
        <div class="card-meta">
          <span class="cat-tag" data-cat="${a.category}">${a.category}</span>
          <span class="card-date">${a.date}</span>
          ${cvssHtml}
        </div>
        <div class="card-title">${a.title}</div>
        ${summaryHtml}
        ${(mitreHtml||pocHtml) ? `<div class="card-footer">${mitreHtml}${pocHtml}</div>` : ''}
      `;
      card.onclick = () => openDetail(a);
      feed.appendChild(card);
    });
  });
}

function openDetail(a) {
  const body = document.getElementById('det-body');

  const cvss = a.cvss_score;
  let metaHtml = '';
  if (cvss) metaHtml += `<span class="cvss-badge ${cvssClass(cvss)}" style="font-size:.7rem;padding:4px 10px">CVSS ${cvss}</span>`;
  (a.mitre_ids||[]).forEach(id => { metaHtml += `<span class="mitre-chip">${id}</span>`; });
  if (isPocValid(a.poc_url)) {
    metaHtml += `<a href="${a.poc_url}" target="_blank" class="poc-btn">⚡ PoC / Exploit Repository</a>`;
  }

  body.innerHTML = `
    <div class="det-title">${a.title}</div>
    <div class="det-meta-row">
      <span class="cat-tag" data-cat="${a.category}" style="font-size:.68rem;padding:4px 10px">${a.category}</span>
      <span style="font-family:var(--mono);font-size:.65rem;color:var(--muted)">${a.date}</span>
      ${metaHtml}
    </div>
    ${marked.parse(a.content)}
  `;

  // COPYボタン
  body.querySelectorAll('pre').forEach(pre => {
    const btn = document.createElement('button');
    btn.className = 'copy-btn'; btn.textContent = 'COPY';
    btn.onclick = e => {
      e.stopPropagation();
      const txt = pre.querySelector('code')?.textContent || pre.textContent;
      navigator.clipboard.writeText(txt).then(() => {
        btn.textContent = '✓ OK';
        setTimeout(() => btn.textContent = 'COPY', 1800);
      });
    };
    pre.appendChild(btn);
  });

  document.getElementById('det-cat-tag').innerHTML =
    `<span class="cat-tag" data-cat="${a.category}" style="font-size:.68rem;padding:4px 10px">${a.category}</span>`;
  document.getElementById('det-source-url').href = a.url;
  document.getElementById('detail').classList.add('open');
  history.pushState({view:'detail'}, '');
}

function closeDetail() {
  document.getElementById('detail').classList.remove('open');
}

window.onpopstate = () => closeDetail();
init();
</script>
</body>
</html>"""

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"HTML書き出し: {OUTPUT_HTML}")
    print("※ GitHub Actionsで index.html と articles.js の両方をコミットしてください")

# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    new_data = fetch_and_analyze()
    db = update_db(new_data)
    generate_html(db)
