"""
RED-TACTICAL INTELLIGENCE AGENT v3.1
=====================================
v3.1 消費量最適化（品質維持）:
[COST] search_depth: advanced(2cr) → basic(1cr) でTavilyクレジットを半減
       月間消費: ~480cr → ~240cr  (無料枠1,000crに対して余裕あり)
[COST] max_tokens: 4096 → 2000 でGroqトークン消費を約半減
       日次消費: ~100,000tok → ~50,000tok
[COST] 検索前にDBの既存URLをチェックし既知URLを除外してからLLM呼び出し
[COST] 1カテゴリあたりのクエリ数を3→2本に削減（重複しやすい3本目を削除）
       1回の実行上限: Tavily 16cr / Groq ~50,000tok
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
MIN_REPORT_LEN   = 300    # 品質フィルタ（max_tokens削減に合わせて調整）
MAX_RETRIES      = 3
SLEEP_BETWEEN_REQ = 2.5  # Groq無料枠レート制限対策

# deepseek-r1-distill-llama-70b は2025年9月に廃止済み
# llama-4-scout: TPD 500,000 (llama-3.3-70b-versatileの5倍) で余裕あり
PRIMARY_MODEL  = "meta-llama/llama-4-scout-17b-16e-instruct"
FALLBACK_MODEL = "llama-3.1-8b-instant"   # TPD 500,000、速度重視

# ─────────────────────────────────────────────
# 検索クエリ（セキュリティ研究ソースに誘導）
# ─────────────────────────────────────────────
SEARCH_CATEGORIES = {
    # クエリ数を3→2に削減。最も技術情報が濃いクエリを優先して残す
    "MALWARE": [
        "malware technical analysis shellcode loader evasion persistence 2026",
        "RAT backdoor C2 protocol obfuscation fileless LOLBAS",
    ],
    "INITIAL": [
        "CVE 2026 critical RCE exploit proof of concept published",
        "authentication bypass vulnerability exploit walkthrough writeup",
    ],
    "POST_EXP": [
        "Active Directory privilege escalation kerberoasting RBCD EDR bypass 2026",
        "lateral movement credential dumping LSASS new technique",
    ],
    "AI_SEC": [
        "LLM prompt injection jailbreak exploit technique 2026",
        "MCP tool poisoning agentic AI attack vector security",
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
    return f"""Red team operator report. Focus: {focus}
Transform source (may be defender-perspective) into attacker-perspective report. Label inferred details [推測].
Output ONLY valid JSON, no markdown fences, no extra text. Use \\n for newlines in strings.

Schema: {{"title":"日本語見出し30字以内","summary_points":["要点1","要点2","要点3"],"poc_url":"URL or empty","cvss_score":"数値 or empty","mitre_ids":["T1059.001"],"report":"## 概要\\n...\\n## 技術的メカニズム\\n...\\n## 攻撃手順\\n1. ...\\n## 実行コマンド\\n```bash\\n実際のコマンド+オプション+ターゲット例\\n```\\n## MITRE ATT&CK\\n...\\n## 検知・緩和策\\n..."}}

SOURCE:
{content[:5000]}"""

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
                    max_tokens=2000,  # 4096→2000 でGroqトークン消費を約半減
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
def fetch_and_analyze(existing_urls: set[str]) -> list[dict]:
    print("=" * 50)
    print("  RED-INTEL AGENT v3.1 — 情報収集開始")
    print("=" * 50)
    print(f"  既存DB URL数: {len(existing_urls)} 件（スキップ対象）")

    new_articles: list[dict] = []
    seen_urls         = set(existing_urls)   # 既存URLも重複チェックに含める
    seen_title_hashes = set()

    for cat_id, queries in SEARCH_CATEGORIES.items():
        print(f"\n[{cat_id}] ───────────────────────")
        cat_count = 0

        for query in queries:
            try:
                results = tavily.search(
                    query=query,
                    search_depth="advanced",    # basicだと動的サイトの本文が取れない
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

                    # advanced検索でもコンテンツが少ない場合はスキップ（動的サイト対策）
                    if len(content) < 600:
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
        "datetime_jst": datetime.now().strftime("%Y-%m-%d %H:%M"),
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
<title>VORTEX // THREAT INTELLIGENCE</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700&family=Noto+Sans+JP:wght@300;400;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:      #07100d;
  --surf:    #0c1712;
  --surf2:   #111f18;
  --bdr:     #1b3028;
  --bdr2:    #274840;
  --text:    #7aaa8e;
  --hi:      #d2edd8;
  --muted:   #2c4035;
  --acc:     #3dffa0;
  --acc2:    #f0c040;
  --MALWARE: #ff4455;
  --INITIAL: #f0c040;
  --POST_EXP:#b06aff;
  --AI_SEC:  #3dffa0;
  --mono: 'JetBrains Mono', monospace;
  --sans: 'Noto Sans JP', sans-serif;
  --disp: 'Rajdhani', sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:14px;min-height:100vh}

/* ── noise overlay ── */
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:999;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
  background-size:200px;opacity:.4}

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
  color:var(--acc);text-shadow:0 0 24px rgba(61,255,160,.35);line-height:1;
}
.logo-sub{font-family:var(--mono);font-size:.55rem;color:var(--muted);letter-spacing:.18em;margin-top:4px}
.logo-log-link{
  display:inline-block;margin-top:8px;font-family:var(--mono);font-size:.6rem;
  color:var(--muted);text-decoration:none;border:1px solid var(--bdr2);
  padding:3px 8px;border-radius:2px;transition:.15s;letter-spacing:.05em;
}
.logo-log-link:hover{color:var(--acc2);border-color:var(--acc2)}

.search-wrap{padding:10px 12px;border-bottom:1px solid var(--bdr)}
#search-box{
  width:100%;padding:8px 10px 8px 28px;background:var(--bg);
  border:1px solid var(--bdr2);color:var(--hi);border-radius:3px;
  outline:none;font-family:var(--mono);font-size:.72rem;transition:.2s;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%232c4035' viewBox='0 0 16 16'%3E%3Cpath d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:10px center;
}
#search-box:focus{border-color:var(--acc);box-shadow:0 0 0 2px rgba(61,255,160,.08)}
#search-box::placeholder{color:var(--muted)}

.filter-wrap{padding:8px 10px;border-bottom:1px solid var(--bdr);display:flex;gap:4px;flex-wrap:wrap}
.cat-btn{
  padding:3px 9px;border-radius:2px;border:1px solid var(--bdr2);
  background:none;color:var(--muted);cursor:pointer;
  font-family:var(--mono);font-size:.6rem;font-weight:700;letter-spacing:.06em;transition:.15s;
}
.cat-btn:hover{color:var(--hi);border-color:var(--text)}
.cat-btn.active[data-cat="ALL"]{background:rgba(61,255,160,.1);border-color:var(--acc);color:var(--acc)}
.cat-btn.active[data-cat="MALWARE"]{background:rgba(255,68,85,.1);border-color:var(--MALWARE);color:var(--MALWARE)}
.cat-btn.active[data-cat="INITIAL"]{background:rgba(240,192,64,.1);border-color:var(--INITIAL);color:var(--INITIAL)}
.cat-btn.active[data-cat="POST_EXP"]{background:rgba(176,106,255,.1);border-color:var(--POST_EXP);color:var(--POST_EXP)}
.cat-btn.active[data-cat="AI_SEC"]{background:rgba(61,255,160,.1);border-color:var(--AI_SEC);color:var(--AI_SEC)}

.date-list{flex:1;overflow-y:auto;padding:8px}
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
  text-shadow:0 0 8px rgba(61,255,160,.3)}

/* ── Main feed ── */
.main-feed{flex:1;overflow-y:auto;padding:16px}
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
  padding:15px 16px;margin-bottom:8px;cursor:pointer;transition:.18s;
  position:relative;overflow:hidden;
}
.card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px}
.card[data-cat="MALWARE"]::before{background:var(--MALWARE);box-shadow:0 0 6px var(--MALWARE)}
.card[data-cat="INITIAL"]::before{background:var(--INITIAL);box-shadow:0 0 6px var(--INITIAL)}
.card[data-cat="POST_EXP"]::before{background:var(--POST_EXP);box-shadow:0 0 6px var(--POST_EXP)}
.card[data-cat="AI_SEC"]::before{background:var(--AI_SEC);box-shadow:0 0 6px var(--AI_SEC)}
.card:hover{background:var(--surf2);border-color:var(--bdr2);transform:translateX(3px)}
.card:active{transform:translateX(1px)}

.card-meta{display:flex;align-items:center;gap:7px;margin-bottom:8px;flex-wrap:wrap}
.cat-tag{
  font-family:var(--mono);font-size:.58rem;font-weight:700;
  padding:2px 8px;border-radius:2px;letter-spacing:.06em;
}
.cat-tag[data-cat="MALWARE"]{background:rgba(255,68,85,.12);color:var(--MALWARE);border:1px solid rgba(255,68,85,.25)}
.cat-tag[data-cat="INITIAL"]{background:rgba(240,192,64,.12);color:var(--INITIAL);border:1px solid rgba(240,192,64,.25)}
.cat-tag[data-cat="POST_EXP"]{background:rgba(176,106,255,.12);color:var(--POST_EXP);border:1px solid rgba(176,106,255,.25)}
.cat-tag[data-cat="AI_SEC"]{background:rgba(61,255,160,.08);color:var(--AI_SEC);border:1px solid rgba(61,255,160,.2)}
.card-date{font-family:var(--mono);font-size:.6rem;color:var(--muted)}
.cvss-badge{
  font-family:var(--mono);font-size:.58rem;font-weight:700;
  padding:2px 7px;border-radius:2px;margin-left:auto;
}
.cvss-critical{background:rgba(255,68,85,.12);color:#ff4455;border:1px solid rgba(255,68,85,.3)}
.cvss-high{background:rgba(240,192,64,.12);color:#f0c040;border:1px solid rgba(240,192,64,.3)}
.cvss-medium{background:rgba(251,191,36,.12);color:#fbbf24;border:1px solid rgba(251,191,36,.3)}
.cvss-low{background:rgba(61,255,160,.08);color:#3dffa0;border:1px solid rgba(61,255,160,.2)}

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
  background:rgba(61,255,160,.07);color:var(--acc);
  border:1px solid rgba(61,255,160,.18);padding:2px 6px;border-radius:2px;
  animation:blink 2s infinite;
}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.55}}
.no-data{text-align:center;padding:80px 20px;font-family:var(--mono);color:var(--muted);font-size:.72rem;letter-spacing:.1em}

/* ── Detail overlay ── */
#detail{
  position:fixed;inset:0;background:var(--bg);z-index:200;
  display:flex;flex-direction:column;
  transform:translateX(100%);transition:transform .28s cubic-bezier(.4,0,.2,1);
}
#detail.open{transform:none}
.det-header{
  background:rgba(12,23,18,.96);backdrop-filter:blur(12px);
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
.back-btn:hover{background:rgba(61,255,160,.07)}
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
  background:rgba(61,255,160,.08);color:var(--acc);
  border:1px solid rgba(61,255,160,.25);
  padding:8px 16px;border-radius:3px;text-decoration:none;
  font-family:var(--mono);font-weight:700;font-size:.7rem;letter-spacing:.04em;transition:.15s;
}
.poc-btn:hover{background:rgba(61,255,160,.15);box-shadow:0 0 14px rgba(61,255,160,.15)}

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
  background:#030d07;border:1px solid var(--bdr2);border-left:2px solid var(--acc);
  border-radius:3px;padding:16px 16px 16px 18px;overflow-x:auto;margin:14px 0;position:relative;
}
.det-inner code{font-family:var(--mono);font-size:.78rem;color:var(--acc);line-height:1.7}
.det-inner :not(pre)>code{background:rgba(61,255,160,.07);padding:2px 5px;border-radius:2px;font-size:.78rem;color:var(--acc2)}
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
    display:flex;align-items:center;justify-content:space-between;
    padding:10px 14px;background:var(--surf);border-bottom:1px solid var(--bdr);
    flex-shrink:0;position:relative;
  }
  .mob-header::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
    background:linear-gradient(90deg,var(--acc),transparent 60%)}
  .mob-logo{font-family:var(--disp);font-size:1.3rem;font-weight:700;
    color:var(--acc);letter-spacing:.1em;text-shadow:0 0 16px rgba(61,255,160,.3)}
  .mob-search-btn{background:none;border:1px solid var(--bdr2);color:var(--text);
    padding:5px 10px;border-radius:2px;cursor:pointer;font-family:var(--mono);font-size:.65rem}

  /* collapsible search bar */
  .mob-search-wrap{
    display:none;padding:8px 12px;background:var(--surf);border-bottom:1px solid var(--bdr);
  }
  .mob-search-wrap.open{display:block}
  .mob-search-wrap #search-box{font-size:.8rem}

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
  .tab-btn.active svg{filter:drop-shadow(0 0 4px var(--acc))}

  /* mobile date drawer */
  .mob-drawer{
    display:none;position:fixed;bottom:58px;left:0;right:0;
    background:var(--surf);border-top:1px solid var(--bdr);
    max-height:50vh;overflow-y:auto;z-index:99;padding:8px;
  }
  .mob-drawer.open{display:block}
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
  <span class="mob-logo">VORTEX</span>
  <button class="mob-search-btn" onclick="toggleMobSearch()">SEARCH</button>
</div>
<div class="mob-search-wrap" id="mob-search-wrap">
  <input type="text" id="search-box" placeholder="search intel..." autocomplete="off">
</div>

<!-- DESKTOP LAYOUT -->
<div class="layout">
  <nav class="sidebar">
    <div class="logo-wrap">
      <div class="logo-name">VORTEX</div>
      <div class="logo-sub">// THREAT INTELLIGENCE FEED</div>
      <a href="log.html" class="logo-log-link">📋 調査ログ</a>
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

/* ── search sync (desktop + mobile share same state) ── */
const deskSearch = document.getElementById('search-box-desk');
const mobSearch  = document.getElementById('search-box');
if(deskSearch) deskSearch.oninput = e => { if(mobSearch) mobSearch.value = e.target.value; render(); };
if(mobSearch)  mobSearch.oninput  = e => { if(deskSearch) deskSearch.value = e.target.value; render(); };

function getQuery(){ return (deskSearch||mobSearch)?.value.toLowerCase() || ''; }

function cvssClass(s){
  const n=parseFloat(s);
  if(isNaN(n))return'';
  if(n>=9)return'cvss-critical';if(n>=7)return'cvss-high';if(n>=4)return'cvss-medium';return'cvss-low';
}
function isPocValid(u){return u&&u.startsWith('http')}

/* ── init ── */
function init(){
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
  const filtered=db.filter(a=>{
    const mc=activeCat==='ALL'||a.category===activeCat;
    const md=activeDate==='all'||a.date===activeDate;
    const mq=!q||(a.title+(a.summary_points||[]).join(' ')+a.content).toLowerCase().includes(q);
    return mc&&md&&mq;
  });
  if(!filtered.length){feed.innerHTML='<div class="no-data">// NO INTELLIGENCE FOUND //</div>';return;}
  const groups={};
  filtered.forEach(a=>{(groups[a.date]=groups[a.date]||[]).push(a);});
  Object.keys(groups).sort().reverse().forEach(date=>{
    const lbl=document.createElement('div');
    lbl.className='day-label';
    lbl.innerHTML=date+(date===today?' &nbsp;<span style="color:var(--acc);font-size:.55rem">TODAY</span>':'');
    feed.appendChild(lbl);
    groups[date].forEach(a=>{
      const card=document.createElement('div');
      card.className='card';card.dataset.cat=a.category;
      const pts=(a.summary_points||[]).slice(0,3);
      const sumHtml=pts.length?'<ul class="card-summary">'+pts.map(p=>`<li>${p}</li>`).join('')+'</ul>':`<div class="card-summary">${a.summary||''}</div>`;
      const cvssHtml=a.cvss_score?`<span class="cvss-badge ${cvssClass(a.cvss_score)}">CVSS ${a.cvss_score}</span>`:'';
      const mitreHtml=(a.mitre_ids||[]).slice(0,3).map(id=>`<span class="mitre-chip">${id}</span>`).join('');
      const pocHtml=isPocValid(a.poc_url)?'<span class="poc-chip">⚡ PoC</span>':'';
      card.innerHTML=`
        <div class="card-meta">
          <span class="cat-tag" data-cat="${a.category}">${a.category}</span>
          <span class="card-date">${a.date}</span>${cvssHtml}
        </div>
        <div class="card-title">${a.title}</div>
        ${sumHtml}
        ${(mitreHtml||pocHtml)?`<div class="card-footer">${mitreHtml}${pocHtml}</div>`:''}`;
      card.onclick=()=>openDetail(a);
      feed.appendChild(card);
    });
  });
}

function openDetail(a){
  const body=document.getElementById('det-body');
  let metaHtml='';
  if(a.cvss_score) metaHtml+=`<span class="cvss-badge ${cvssClass(a.cvss_score)}" style="font-size:.68rem;padding:4px 10px">CVSS ${a.cvss_score}</span>`;
  (a.mitre_ids||[]).forEach(id=>{metaHtml+=`<span class="mitre-chip">${id}</span>`;});
  if(isPocValid(a.poc_url)) metaHtml+=`<a href="${a.poc_url}" target="_blank" class="poc-btn">⚡ PoC / Exploit Repository</a>`;
  body.innerHTML=`
    <div class="det-title">${a.title}</div>
    <div class="det-meta-row">
      <span class="cat-tag" data-cat="${a.category}" style="font-size:.66rem;padding:3px 10px">${a.category}</span>
      <span style="font-family:var(--mono);font-size:.62rem;color:var(--muted)">${a.date}</span>
      ${metaHtml}
    </div>
    ${marked.parse(a.content)}`;
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
  document.getElementById('detail').classList.add('open');
  history.pushState({view:'detail'},'');
}
function closeDetail(){document.getElementById('detail').classList.remove('open');}
window.onpopstate=()=>closeDetail();

/* ── mobile tab / drawer ── */
let drawerMode=null;
function setTab(t){
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
function toggleMobSearch(){
  const w=document.getElementById('mob-search-wrap');
  w.classList.toggle('open');
  if(w.classList.contains('open')) document.getElementById('search-box')?.focus();
}
init();
</script>
</body>
</html>"""
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(index_html)
    print("HTML書き出し: index.html")

    # ── log.html ─────────────────────────────────
    log_html = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VORTEX // RUN LOG</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700&family=Noto+Sans+JP:wght@300;400&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#07100d;--surf:#0c1712;--surf2:#111f18;--bdr:#1b3028;--bdr2:#274840;
  --text:#7aaa8e;--hi:#d2edd8;--muted:#2c4035;--acc:#3dffa0;--acc2:#f0c040;
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
  letter-spacing:.1em;text-shadow:0 0 20px rgba(61,255,160,.25)}
.page-sub{font-family:var(--mono);font-size:.6rem;color:var(--muted);letter-spacing:.15em;margin-top:4px}
.summary-row{
  display:grid;grid-template-columns:repeat(3,1fr);gap:10px;
  margin-bottom:24px;
}
.stat-card{background:var(--surf);border:1px solid var(--bdr);border-radius:4px;padding:14px;text-align:center}
.stat-card-val{font-family:var(--disp);font-size:1.6rem;font-weight:700;color:var(--acc);
  text-shadow:0 0 10px rgba(61,255,160,.25);display:block}
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
  font-family:var(--mono);font-size:.55rem;background:rgba(61,255,160,.1);
  color:var(--acc);border:1px solid rgba(61,255,160,.2);
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
    <a href="index.html" class="back-link">← VORTEX</a>
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

// summary
const totalRuns   = log.length;
const totalNew    = log.reduce((s,r)=>s+(r.new_articles||0),0);
const lastRun     = log[0]?.datetime_jst || '—';
const summaryEl   = document.getElementById('summary-row');
summaryEl.innerHTML = `
  <div class="stat-card"><span class="stat-card-val">${totalRuns}</span><div class="stat-card-lbl">TOTAL RUNS</div></div>
  <div class="stat-card"><span class="stat-card-val">${totalNew}</span><div class="stat-card-lbl">ARTICLES COLLECTED</div></div>
  <div class="stat-card"><span class="stat-card-val" style="font-size:1rem;padding-top:4px">${lastRun}</span><div class="stat-card-lbl">LAST RUN (JST)</div></div>`;

// table
const wrap = document.getElementById('log-wrap');
if(!log.length){
  wrap.innerHTML='<div class="no-log">// 実行ログがありません</div>';
} else {
  let rows = log.map(r=>{
    const isToday = r.datetime_jst?.startsWith(today);
    const newBadge = r.new_articles > 0
      ? `<span class="badge-new">+${r.new_articles}</span>`
      : `<span class="badge-zero">±0</span>`;
    return `<tr class="${isToday?'today-row':''}">
      <td>${r.datetime_jst}${isToday?'<span class="badge-new" style="margin-left:6px">TODAY</span>':''}</td>
      <td>${newBadge}</td>
      <td>${r.total_articles ?? '—'}</td>
    </tr>`;
  }).join('');
  wrap.innerHTML = `<table class="log-table">
    <thead><tr><th>実行日時 (JST)</th><th>新規取得</th><th>累計件数</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}
</script>
</body>
</html>"""
    with open("log.html", "w", encoding="utf-8") as f:
        f.write(log_html)
    print("HTML書き出し: log.html")
    print("※ GitHub Actions で index.html / log.html / articles.js / log.js をコミットしてください")


# ─────────────────────────────────────────────
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
