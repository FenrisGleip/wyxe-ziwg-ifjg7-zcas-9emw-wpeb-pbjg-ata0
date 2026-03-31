"""
RED-TACTICAL INTELLIGENCE AGENT v2.0
=====================================
改善点:
- LLM: deepseek-r1-distill-llama-70b (推論特化モデル、無料)
- 段階的Chain-of-Thought分析で技術的深度を大幅向上
- 検索クエリの多層化・精緻化
- JSONパース失敗時のフォールバック＋リトライ処理
- CVSS/MITRE ATT&CK情報の自動抽出
- UIの全面刷新
"""

import os
import json
import re
import time
from tavily import TavilyClient
from groq import Groq
from datetime import datetime

# --- SETTINGS ---
TAVILY_KEY = os.getenv("TAVILY_API_KEY")
GROQ_KEY   = os.getenv("GROQ_API_KEY")
tavily     = TavilyClient(api_key=TAVILY_KEY)
groq_client = Groq(api_key=GROQ_KEY)

MASTER_DATA = "all_articles.json"

# deepseek-r1は推論(<think>タグ)を含む出力をするため、JSONを確実に抽出する必要がある
# 無料枠で最高品質: deepseek-r1-distill-llama-70b
PRIMARY_MODEL  = "deepseek-r1-distill-llama-70b"
FALLBACK_MODEL = "llama-3.3-70b-versatile"

# ============================================================
# 1. 検索クエリの多層化
# ============================================================
SEARCH_CATEGORIES = {
    "MALWARE": [
        "malware loader dropper technical analysis 2026",
        "ransomware new variant persistence mechanism evasion",
        "C2 framework implant new technique beacon",
    ],
    "INITIAL": [
        "CVE exploit proof of concept RCE 2026",
        "zero day vulnerability bypass authentication 2026",
        "initial access broker exploit kit new technique",
    ],
    "POST_EXP": [
        "Active Directory attack technique lateral movement 2026",
        "privilege escalation Windows Linux new method 2026",
        "credential dumping LSASS bypass EDR 2026",
    ],
    "AI_SEC": [
        "LLM jailbreak prompt injection attack 2026",
        "AI model attack adversarial exploit 2026",
        "MCP tool poisoning agentic AI security 2026",
    ],
}

MAX_RESULTS_PER_QUERY = 2   # クエリ数が増えた分、1クエリあたりを絞る
MIN_REPORT_LENGTH     = 400  # 品質フィルタの閾値を引き上げ

# ============================================================
# 2. プロンプト設計 (CoT + 構造化出力)
# ============================================================
def build_analysis_prompt(content: str, category: str) -> str:
    """
    deepseek-r1はchain-of-thoughtが得意。
    まず<think>で内部推論させてから、最終的にJSONのみを出力するよう指示する。
    """
    category_guidance = {
        "MALWARE":  "マルウェアの永続化・難読化・C2通信の技術的メカニズムに焦点を当てる",
        "INITIAL":  "脆弱性のroot cause、PoC再現手順、影響を受けるバージョンを明確にする",
        "POST_EXP": "横断的侵害・権限昇格の具体的なコマンド・ツールチェーンを記述する",
        "AI_SEC":   "攻撃ベクター・ペイロード例・LLMへの影響を技術的に説明する",
    }.get(category, "技術的な攻撃手法を詳細に分析する")

    return f"""You are a senior red team analyst with 15 years of experience in offensive security.
Your focus: {category_guidance}

Analyze the following threat intelligence source and produce a structured technical report.

STRICT REQUIREMENTS:
1. Title: Objective Japanese newspaper headline (no instructive phrasing).
2. Summary: 3 concise bullet points in Japanese highlighting key technical takeaways.
3. Report sections (Japanese):
   - ## 概要: Executive summary (3-5 sentences)
   - ## 技術的詳細: In-depth mechanism explanation with internals
   - ## 攻撃シナリオ・再現手順: Step-by-step attack chain (numbered)
   - ## 実行コマンド例: Concrete commands using real tools (curl, impacket, msfvenom, netexec, sliver, etc.) in fenced code blocks
   - ## MITRE ATT&CK マッピング: Relevant Tactic/Technique IDs (e.g., T1059.001)
   - ## 検知・緩和策: Detection rules (Sigma/Yara snippets preferred) and mitigations
4. Extract any GitHub PoC / exploit URLs into poc_url.
5. If CVSS score is mentioned, extract it into cvss_score.
6. Output ONLY valid JSON. No markdown fences, no preamble, no explanation outside JSON.

JSON schema:
{{
  "title": "string",
  "summary": "string (3 bullet points joined by \\n)",
  "poc_url": "string or empty",
  "cvss_score": "string or empty (e.g. 9.8)",
  "mitre_ids": ["T1059.001", "..."],
  "report": "full markdown report string"
}}

SOURCE:
{content[:9000]}
"""

# ============================================================
# 3. 堅牢なJSON抽出
# ============================================================
def extract_json_from_response(raw: str) -> dict | None:
    """
    deepseek-r1は<think>...</think>タグを出力した後にJSONを返す。
    複数のパターンで抽出を試みる。
    """
    # <think>タグを除去
    cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

    # パターン1: そのままパース
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # パターン2: 最初の { から最後の } を抽出
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # パターン3: ```json ... ``` ブロックを抽出
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    return None

# ============================================================
# 4. LLM呼び出し（リトライ付き）
# ============================================================
def call_llm(prompt: str, max_retries: int = 3) -> dict | None:
    models = [PRIMARY_MODEL, FALLBACK_MODEL]

    for model in models:
        for attempt in range(max_retries):
            try:
                response = groq_client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,   # 再現性を高めつつわずかに揺らぎを許容
                    max_tokens=4096,
                    # deepseek-r1はjson_objectモードが不安定なため、プロンプトで制御
                )
                raw = response.choices[0].message.content
                result = extract_json_from_response(raw)

                if result and result.get("title") and len(result.get("report", "")) >= MIN_REPORT_LENGTH:
                    print(f"  ✓ 解析成功 (model={model}, attempt={attempt+1})")
                    return result

                print(f"  ✗ 品質不足 (model={model}, attempt={attempt+1}) — retrying...")
                time.sleep(2)

            except Exception as e:
                print(f"  ✗ LLMエラー (model={model}, attempt={attempt+1}): {e}")
                time.sleep(3)

    return None

# ============================================================
# 5. 情報収集
# ============================================================
def fetch_and_analyze() -> list[dict]:
    print("=== 情報収集フェーズ開始 ===")
    new_articles = []
    seen_urls    = set()

    for cat_id, queries in SEARCH_CATEGORIES.items():
        print(f"\n[{cat_id}] 検索中...")
        cat_articles = []

        for query in queries:
            try:
                results = tavily.search(
                    query=query,
                    search_depth="advanced",
                    max_results=MAX_RESULTS_PER_QUERY,
                    # search_period="week" に広げることで鮮度と網羅性を両立
                    search_period="week",
                )["results"]

                for item in results:
                    url = item.get("url", "")
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)

                    print(f"  → 取得: {url[:70]}...")

                    # コンテンツが短すぎる場合はスキップ
                    content = item.get("content", "")
                    if len(content) < 300:
                        print(f"    ✗ コンテンツ不足 ({len(content)} chars) — skip")
                        continue

                    prompt  = build_analysis_prompt(content, cat_id)
                    result  = call_llm(prompt)

                    if result is None:
                        print(f"    ✗ 解析失敗 — skip")
                        continue

                    cat_articles.append({
                        "date":       datetime.now().strftime("%Y-%m-%d"),
                        "category":   cat_id,
                        "title":      result["title"],
                        "summary":    result.get("summary", ""),
                        "poc_url":    result.get("poc_url", ""),
                        "cvss_score": result.get("cvss_score", ""),
                        "mitre_ids":  result.get("mitre_ids", []),
                        "content":    result["report"],
                        "url":        url,
                    })

                    # Groq無料枠レート制限対策
                    time.sleep(2)

            except Exception as e:
                print(f"  ✗ Tavily検索エラー ({query}): {e}")
                continue

        new_articles.extend(cat_articles)
        print(f"  [{cat_id}] 完了: {len(cat_articles)} 件取得")

    print(f"\n=== 情報収集完了: 合計 {len(new_articles)} 件 ===")
    return new_articles

# ============================================================
# 6. DB更新 & HTML生成
# ============================================================
def update_db_and_ui(new_entries: list[dict]) -> None:
    # DB読み込み
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

    db = sorted(db, key=lambda x: x["date"], reverse=True)[:200]

    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    print(f"DB更新: {added} 件追加 / 合計 {len(db)} 件")

    # HTML生成
    _generate_html(db)
    print("index.html を生成しました。")

def _generate_html(db: list[dict]) -> None:
    db_json_str = json.dumps(db, ensure_ascii=False)

    html = r"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RT-INTEL</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
  :root {
    --bg:#0a0e17; --surface:#111827; --surface2:#1a2235; --border:#1e2d40;
    --text:#cdd5e0; --muted:#5a6a80; --green:#00ff87; --green-dim:#00c96a;
    --MALWARE:#ff4d6d; --INITIAL:#ff9f43; --POST_EXP:#a855f7; --AI_SEC:#38bdf8;
    --critical:#ff4d6d; --high:#ff9f43; --medium:#facc15; --low:#4ade80;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);display:flex;height:100vh;overflow:hidden;font-size:14px}

  /* ── Sidebar ── */
  nav{width:260px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0}
  .logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
  .logo-title{font-size:.75rem;font-weight:700;letter-spacing:.2em;color:var(--green);text-transform:uppercase}
  .logo-sub{font-size:.65rem;color:var(--muted);margin-top:3px}
  .search-wrap{padding:12px 14px;border-bottom:1px solid var(--border)}
  #search-box{width:100%;padding:9px 12px;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:7px;outline:none;font-size:.85rem;transition:.2s}
  #search-box:focus{border-color:var(--green);box-shadow:0 0 0 2px rgba(0,255,135,.08)}
  .filter-row{display:flex;gap:6px;padding:10px 14px;border-bottom:1px solid var(--border);flex-wrap:wrap}
  .cat-btn{padding:4px 10px;border-radius:20px;border:1px solid var(--border);background:none;color:var(--muted);cursor:pointer;font-size:.7rem;font-weight:600;letter-spacing:.05em;transition:.15s}
  .cat-btn:hover{color:#fff}
  .cat-btn.active{color:#000;font-weight:700}
  .cat-btn[data-cat="ALL"].active{background:var(--green);border-color:var(--green)}
  .cat-btn[data-cat="MALWARE"].active{background:var(--MALWARE);border-color:var(--MALWARE)}
  .cat-btn[data-cat="INITIAL"].active{background:var(--INITIAL);border-color:var(--INITIAL)}
  .cat-btn[data-cat="POST_EXP"].active{background:var(--POST_EXP);border-color:var(--POST_EXP)}
  .cat-btn[data-cat="AI_SEC"].active{background:var(--AI_SEC);border-color:var(--AI_SEC)}
  .date-list{flex:1;overflow-y:auto;padding:10px 10px}
  .date-item{padding:9px 12px;border-radius:7px;cursor:pointer;font-size:.82rem;color:var(--muted);margin-bottom:3px;display:flex;justify-content:space-between;align-items:center;transition:.15s}
  .date-item:hover{background:var(--surface2);color:var(--text)}
  .date-item.active{background:var(--surface2);color:var(--green);font-weight:600}
  .date-badge{font-size:.65rem;background:var(--border);padding:2px 7px;border-radius:10px}
  .stats-bar{padding:12px 14px;border-top:1px solid var(--border);display:flex;gap:14px}
  .stat{font-size:.7rem;color:var(--muted)}
  .stat span{color:var(--green);font-weight:700}

  /* ── Feed ── */
  main{flex:1;overflow-y:auto;padding:18px 20px}
  .feed{max-width:820px;margin:0 auto}
  .section-label{font-size:.65rem;font-weight:700;letter-spacing:.15em;color:var(--muted);text-transform:uppercase;margin:20px 0 10px;padding-left:4px}

  /* ── Card ── */
  .card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 20px;margin-bottom:10px;cursor:pointer;transition:.2s;position:relative;overflow:hidden}
  .card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
  .card[data-cat="MALWARE"]::before{background:var(--MALWARE)}
  .card[data-cat="INITIAL"]::before{background:var(--INITIAL)}
  .card[data-cat="POST_EXP"]::before{background:var(--POST_EXP)}
  .card[data-cat="AI_SEC"]::before{background:var(--AI_SEC)}
  .card:hover{border-color:#2a3a50;transform:translateY(-1px);box-shadow:0 4px 20px rgba(0,0,0,.4)}
  .card-meta{display:flex;align-items:center;gap:8px;margin-bottom:10px}
  .cat-tag{font-size:.65rem;font-weight:700;padding:3px 9px;border-radius:4px;letter-spacing:.08em;color:#000}
  .cat-tag[data-cat="MALWARE"]{background:var(--MALWARE)}
  .cat-tag[data-cat="INITIAL"]{background:var(--INITIAL)}
  .cat-tag[data-cat="POST_EXP"]{background:var(--POST_EXP)}
  .cat-tag[data-cat="AI_SEC"]{background:var(--AI_SEC)}
  .card-date{font-size:.72rem;color:var(--muted)}
  .cvss-badge{font-size:.65rem;font-weight:700;padding:2px 8px;border-radius:4px;margin-left:auto}
  .cvss-critical{background:rgba(255,77,109,.15);color:var(--critical);border:1px solid var(--critical)}
  .cvss-high{background:rgba(255,159,67,.15);color:var(--high);border:1px solid var(--high)}
  .cvss-medium{background:rgba(250,204,21,.15);color:var(--medium);border:1px solid var(--medium)}
  .cvss-low{background:rgba(74,222,128,.15);color:var(--low);border:1px solid var(--low)}
  .card-title{font-size:1rem;font-weight:700;color:#e6edf3;line-height:1.45;margin-bottom:9px}
  .card-summary{font-size:.82rem;color:var(--muted);line-height:1.65}
  .card-footer{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}
  .mitre-chip{font-size:.65rem;background:rgba(168,85,247,.12);color:#c084fc;border:1px solid rgba(168,85,247,.25);padding:2px 7px;border-radius:4px}
  .poc-chip{font-size:.65rem;background:rgba(0,255,135,.1);color:var(--green);border:1px solid rgba(0,255,135,.2);padding:2px 7px;border-radius:4px}

  /* ── Detail ── */
  #detail{position:fixed;inset:0;background:var(--bg);z-index:100;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .3s cubic-bezier(.4,0,.2,1)}
  #detail.open{transform:none}
  .det-header{background:rgba(17,24,39,.95);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:14px 20px;display:flex;align-items:center;gap:14px;flex-shrink:0;position:sticky;top:0}
  .back-btn{background:none;border:1px solid var(--border);color:var(--green);padding:7px 16px;border-radius:6px;cursor:pointer;font-size:.82rem;font-weight:600;transition:.15s}
  .back-btn:hover{background:var(--surface2)}
  .det-body{flex:1;overflow-y:auto;padding:40px 24px}
  .det-inner{max-width:800px;margin:0 auto}
  .det-title{font-size:1.6rem;font-weight:800;color:#e6edf3;line-height:1.35;margin-bottom:20px}
  .det-meta-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--border)}
  .poc-btn{display:inline-flex;align-items:center;gap:6px;background:var(--green);color:#000;padding:10px 20px;border-radius:7px;text-decoration:none;font-weight:700;font-size:.82rem;transition:.15s}
  .poc-btn:hover{background:var(--green-dim)}
  /* Markdown */
  .det-inner h1{display:none}
  .det-inner h2{font-size:1.05rem;font-weight:700;color:#e6edf3;border-bottom:1px solid var(--border);padding-bottom:8px;margin:36px 0 14px}
  .det-inner h3{font-size:.95rem;font-weight:600;color:var(--text);margin:20px 0 8px}
  .det-inner p{line-height:1.75;margin-bottom:12px;color:var(--text)}
  .det-inner ul,.det-inner ol{padding-left:22px;margin-bottom:12px;line-height:1.75}
  .det-inner li{margin-bottom:5px}
  .det-inner pre{background:#060d18;border:1px solid var(--border);border-radius:9px;padding:18px;overflow-x:auto;margin:16px 0;position:relative}
  .det-inner code{font-family:'SFMono-Regular',Consolas,'Courier New',monospace;font-size:.83rem;color:var(--green)}
  .det-inner :not(pre)>code{background:rgba(0,255,135,.07);padding:2px 6px;border-radius:4px;font-size:.82rem}
  .det-inner blockquote{border-left:3px solid var(--border);padding-left:14px;color:var(--muted);margin:12px 0}
  .det-inner table{width:100%;border-collapse:collapse;margin:16px 0;font-size:.82rem}
  .det-inner th{background:var(--surface2);padding:9px 12px;text-align:left;border:1px solid var(--border)}
  .det-inner td{padding:8px 12px;border:1px solid var(--border)}
  .copy-btn{position:absolute;top:10px;right:10px;background:var(--surface2);border:1px solid var(--border);color:var(--text);font-size:.65rem;padding:4px 9px;border-radius:5px;cursor:pointer;transition:.15s;font-family:inherit}
  .copy-btn:hover{background:var(--border);color:#fff}
  .no-data{text-align:center;padding:60px;color:var(--muted)}
  .no-data-icon{font-size:2.5rem;margin-bottom:12px}

  ::-webkit-scrollbar{width:5px;height:5px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:var(--border);border-radius:10px}
</style>
</head>
<body>
<nav>
  <div class="logo">
    <div class="logo-title">RT-INTEL</div>
    <div class="logo-sub">Red Team Intelligence Feed</div>
  </div>
  <div class="search-wrap">
    <input type="text" id="search-box" placeholder="🔍  キーワード検索...">
  </div>
  <div class="filter-row">
    <button class="cat-btn active" data-cat="ALL">ALL</button>
    <button class="cat-btn" data-cat="MALWARE">MALWARE</button>
    <button class="cat-btn" data-cat="INITIAL">INITIAL</button>
    <button class="cat-btn" data-cat="POST_EXP">POST_EXP</button>
    <button class="cat-btn" data-cat="AI_SEC">AI_SEC</button>
  </div>
  <div class="date-list" id="date-list"></div>
  <div class="stats-bar">
    <div class="stat">総件数 <span id="total-count">0</span></div>
    <div class="stat">本日 <span id="today-count">0</span></div>
  </div>
</nav>

<main>
  <div class="feed" id="feed"></div>
</main>

<div id="detail">
  <div class="det-header">
    <button class="back-btn" onclick="closeDetail()">← 戻る</button>
    <div id="det-cat-tag"></div>
  </div>
  <div class="det-body">
    <div class="det-inner" id="det-body"></div>
  </div>
</div>

<script>
const db = INSERT_DATA_HERE;
let activeCat = 'ALL';
let activeDate = 'all';
const today = new Date().toISOString().slice(0,10);

function cvssClass(s) {
  const n = parseFloat(s);
  if (n >= 9) return 'cvss-critical';
  if (n >= 7) return 'cvss-high';
  if (n >= 4) return 'cvss-medium';
  return 'cvss-low';
}

function init() {
  // Date list
  const counts = {};
  db.forEach(a => { counts[a.date] = (counts[a.date]||0)+1; });
  const dates = Object.keys(counts).sort().reverse();
  const list = document.getElementById('date-list');

  const allItem = document.createElement('div');
  allItem.className = 'date-item active'; allItem.dataset.date = 'all';
  allItem.innerHTML = `<span>すべて</span><span class="date-badge">${db.length}</span>`;
  allItem.onclick = () => setDate('all', allItem);
  list.appendChild(allItem);

  dates.forEach(d => {
    const el = document.createElement('div');
    el.className = 'date-item'; el.dataset.date = d;
    el.innerHTML = `<span>${d}</span><span class="date-badge">${counts[d]}</span>`;
    el.onclick = () => setDate(d, el);
    list.appendChild(el);
  });

  document.getElementById('total-count').textContent = db.length;
  document.getElementById('today-count').textContent = counts[today] || 0;

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

  let filtered = db.filter(a => {
    const matchCat  = activeCat === 'ALL' || a.category === activeCat;
    const matchDate = activeDate === 'all' || a.date === activeDate;
    const matchQ    = !q || (a.title+a.summary+a.content).toLowerCase().includes(q);
    return matchCat && matchDate && matchQ;
  });

  if (!filtered.length) {
    feed.innerHTML = '<div class="no-data"><div class="no-data-icon">📭</div>該当するインテリジェンスはありません</div>';
    return;
  }

  // 日付でグループ化
  const groups = {};
  filtered.forEach(a => { (groups[a.date] = groups[a.date]||[]).push(a); });
  Object.keys(groups).sort().reverse().forEach(date => {
    const label = document.createElement('div');
    label.className = 'section-label';
    label.textContent = date === today ? `${date}  (本日)` : date;
    feed.appendChild(label);

    groups[date].forEach(a => {
      const card = document.createElement('div');
      card.className = 'card'; card.dataset.cat = a.category;

      const summaryHtml = (a.summary||'').replace(/\n/g, '<br>');

      let cvssHtml = '';
      if (a.cvss_score) {
        cvssHtml = `<span class="cvss-badge ${cvssClass(a.cvss_score)}">CVSS ${a.cvss_score}</span>`;
      }

      let footerHtml = '';
      if (a.mitre_ids && a.mitre_ids.length) {
        footerHtml += a.mitre_ids.slice(0,4).map(id=>`<span class="mitre-chip">${id}</span>`).join('');
      }
      if (a.poc_url) footerHtml += `<span class="poc-chip">⚡ PoC Available</span>`;

      card.innerHTML = `
        <div class="card-meta">
          <span class="cat-tag" data-cat="${a.category}">${a.category}</span>
          <span class="card-date">${a.date}</span>
          ${cvssHtml}
        </div>
        <div class="card-title">${a.title}</div>
        <div class="card-summary">${summaryHtml}</div>
        ${footerHtml ? `<div class="card-footer">${footerHtml}</div>` : ''}
      `;
      card.onclick = () => openDetail(a);
      feed.appendChild(card);
    });
  });
}

function openDetail(a) {
  const body = document.getElementById('det-body');

  let metaHtml = '';
  if (a.cvss_score) metaHtml += `<span class="cvss-badge ${cvssClass(a.cvss_score)}">CVSS ${a.cvss_score}</span>`;
  if (a.mitre_ids && a.mitre_ids.length) {
    metaHtml += a.mitre_ids.map(id=>`<span class="mitre-chip">${id}</span>`).join('');
  }
  if (a.poc_url) metaHtml += `<a href="${a.poc_url}" target="_blank" class="poc-btn">⚡ PoCリポジトリを開く</a>`;

  body.innerHTML = `
    <div class="det-title">${a.title}</div>
    <div class="det-meta-row">${metaHtml}</div>
    ${marked.parse(a.content)}
    <hr style="border:0;border-top:1px solid var(--border);margin:40px 0 20px">
    <a href="${a.url}" target="_blank" style="color:var(--muted);font-size:.78rem;">📎 ソース元記事</a>
  `;

  // コードブロックにCOPYボタンを追加
  body.querySelectorAll('pre').forEach(pre => {
    const btn = document.createElement('button');
    btn.className = 'copy-btn'; btn.textContent = 'COPY';
    btn.onclick = (e) => {
      e.stopPropagation();
      const code = pre.querySelector('code');
      navigator.clipboard.writeText(code ? code.textContent : pre.textContent).then(() => {
        btn.textContent = '✓ DONE';
        setTimeout(() => btn.textContent = 'COPY', 1800);
      });
    };
    pre.style.position = 'relative';
    pre.appendChild(btn);
  });

  document.getElementById('det-cat-tag').innerHTML =
    `<span class="cat-tag" data-cat="${a.category}">${a.category}</span>`;

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

    final_html = html.replace("INSERT_DATA_HERE", db_json_str)
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(final_html)


# ============================================================
# Entry point
# ============================================================
if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
