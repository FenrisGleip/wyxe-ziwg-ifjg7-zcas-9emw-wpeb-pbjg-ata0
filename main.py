import os
import json
import re
import time
import base64
from tavily import TavilyClient
from groq import Groq
from datetime import datetime, timedelta

# --- SETTINGS ---
TAVILY_KEY = os.getenv("TAVILY_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")
tavily = TavilyClient(api_key=TAVILY_KEY)
groq = Groq(api_key=GROQ_KEY)

MASTER_DATA = "all_articles.json"

def fetch_and_analyze():
    # 検索クエリから厳格な日付を外し、最新情報を拾いやすくする
    categories = {
        "MALWARE": "latest malware technical analysis persistence 2026",
        "INITIAL": "new exploit POC initial access bypass 2026",
        "POST_EXP": "Active Directory lateral movement attack technique 2026",
        "AI_SEC": "LLM prompt injection jailbreak vulnerability 2026"
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        print(f"Searching for {cat_id}...")
        try:
            # search_depth="advanced" で過去1日(day)を指定
            search_res = tavily.search(query=q, search_depth="advanced", max_results=3, search_period="day")["results"]
            
            if not search_res:
                print(f"No results for {cat_id}")
                continue

            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                prompt = f"""
                あなたはレッドチームの専門家です。以下のソースを元に【日本語で】技術レポートを作成してください。
                
                【厳守事項】
                1. ソースにない情報は絶対に書かないこと（「印刷スプーラー」等の固定ネタは禁止）。
                2. タイトルは新聞の見出し風に「何が、どうなった」を具体的に書くこと。
                3. 内容とタイトルを完全に一致させること。
                4. 必ず以下のJSON形式で出力すること。

                {{
                  "title": "具体的かつ動的な日本語タイトル",
                  "summary": "3行の要約",
                  "report": "## 概要\\n... ## 攻撃手順\\n... ## 実行コマンド(OSCP形式)\\n... ## 検知・回避"
                }}

                ソース: {item['content'][:6000]}
                """
                
                try:
                    # モデル名は安定している llama-3.3-70b-versatile を推奨
                    response = groq.chat.completions.create(
                        model="llama-3.3-70b-versatile",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0, # 遊びをなくしソースに忠実にする
                        response_format={"type": "json_object"}
                    )
                    res_json = json.loads(response.choices[0].message.content)
                    
                    if not res_json.get("title") or len(res_json.get("report", "")) < 200:
                        continue

                    new_articles.append({
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "category": cat_id,
                        "title": res_json["title"],
                        "summary": res_json["summary"],
                        "content": res_json["report"],
                        "url": item['url']
                    })
                    print(f"Successfully generated: {res_json['title']}")
                    time.sleep(1)
                except Exception as e:
                    print(f"Groq Error: {e}")
                    continue
        except Exception as e:
            print(f"Tavily Error: {e}")
            
    return new_articles

def update_db_and_ui(new_entries):
    db = []
    if os.path.exists(MASTER_DATA):
        try:
            with open(MASTER_DATA, "r", encoding="utf-8") as f: db = json.load(f)
        except: db = []
    
    existing_urls = {a['url'] for a in db}
    for entry in new_entries:
        if entry['url'] not in existing_urls: db.append(entry)
    
    db = sorted(db, key=lambda x: x['date'], reverse=True)[:50] # 最大50件に制限して軽量化
    
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    db_json = json.dumps(db, ensure_ascii=False)
    db_base64 = base64.b64encode(db_json.encode('utf-8')).decode('utf-8')

    # UI側も表示不備を修正
    html_template = r'''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>RED-TACTICAL INVENTORY</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --accent: #f85149; --text: #c9d1d9; --border: #30363d; --green: #7ee787; }
        body { margin:0; font-family: -apple-system, system-ui, sans-serif; background:var(--bg); color:var(--text); line-height: 1.6; }
        header { position:sticky; top:0; background:rgba(13,17,23,0.9); backdrop-filter:blur(10px); border-bottom:1px solid var(--border); padding:15px; z-index:100; }
        #search-box { width:100%; box-sizing:border-box; background:#000; border:1px solid var(--border); color:var(--green); padding:12px; border-radius:8px; font-size:16px; font-family:monospace; outline:none; }
        main { padding:12px; max-width: 800px; margin: 0 auto; padding-bottom:100px; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; margin-bottom:15px; cursor:pointer; }
        .card:active { transform: scale(0.98); }
        .card-meta { font-size:0.75rem; color:var(--accent); font-weight:bold; margin-bottom:8px; display:flex; justify-content:space-between; }
        .card-title { font-weight:bold; font-size:1.15rem; line-height:1.4; color:#fff; margin-bottom:10px; border-left: 4px solid var(--accent); padding-left:12px; }
        .card-summary { font-size:0.85rem; color:#8b949e; line-height:1.5; }
        #detail-view { position:fixed; top:0; left:100%; width:100%; height:100%; background:var(--bg); transition: transform 0.3s cubic-bezier(0,0,0.2,1); z-index:1000; overflow-y:auto; }
        #detail-view.open { transform: translateX(-100%); }
        .detail-header { position:sticky; top:0; background:var(--card); padding:10px; border-bottom:1px solid var(--border); display:flex; align-items:center; }
        .back-btn { font-size:1.8rem; background:none; border:none; color:var(--accent); cursor:pointer; padding:0 20px; }
        .detail-body { padding:20px; font-size: 1rem; max-width: 800px; margin: 0 auto; }
        .detail-body h1, .detail-body h2 { color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:5px; margin-top:30px; }
        .detail-body pre { background:#000; padding:15px; border-radius:10px; border:1px solid var(--border); overflow-x:auto; position:relative; margin: 20px 0; }
        .detail-body code { color:var(--green); font-family:monospace; font-size:0.9rem; }
        .copy-btn { position:absolute; top:8px; right:8px; background:#21262d; border:1px solid var(--border); color:#fff; border-radius:5px; font-size:0.6rem; padding:5px 10px; cursor:pointer; }
    </style>
</head>
<body>
    <header><input type="text" id="search-box" placeholder="キーワードで検索..."></header>
    <main id="list"></main>
    <div id="detail-view">
        <div class="detail-header"><button class="back-btn" onclick="closeDetail()">←</button><div id="det-head" style="font-weight:bold; font-size:0.85rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"></div></div>
        <div class="detail-body" id="det-body"></div>
    </div>
    <script>
        function b64DecodeUnicode(str) {
            return decodeURIComponent(atob(str).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
        }
        try {
            const db = JSON.parse(b64DecodeUnicode("INSERT_BASE64_HERE"));
            function render() {
                const q = document.getElementById('search-box').value.toLowerCase();
                const list = document.getElementById('list');
                list.innerHTML = '';
                db.filter(a => (a.title + (a.summary || "") + (a.content || "")).toLowerCase().includes(q)).forEach(a => {
                    const el = document.createElement('div');
                    el.className = 'card';
                    el.innerHTML = `
                        <div class="card-meta"><span>${a.date}</span><span>${a.category}</span></div>
                        <div class="card-title">${a.title}</div>
                        <div class="card-summary">${a.summary}</div>`;
                    el.onclick = () => openDetail(a);
                    list.appendChild(el);
                });
            }
            function openDetail(a) {
                document.getElementById('det-head').innerText = a.title;
                document.getElementById('det-body').innerHTML = marked.parse(a.content || "") + `<hr style="border:0; border-top:1px solid var(--border); margin:40px 0;"><a href="${a.url}" target="_blank" style="color:var(--accent); font-size:0.8rem;">[Source]</a>`;
                document.querySelectorAll('pre').forEach(pre => {
                    const b = document.createElement('button');
                    b.className = 'copy-btn'; b.innerText = 'COPY';
                    b.onclick = (e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(pre.innerText.replace('COPY','')).then(() => {
                            b.innerText = 'DONE'; setTimeout(()=>b.innerText='COPY', 1000);
                        });
                    };
                    pre.appendChild(b);
                });
                document.getElementById('detail-view').classList.add('open');
                history.pushState({view:'detail'}, '');
            }
            function closeDetail() { document.getElementById('detail-view').classList.remove('open'); }
            window.onpopstate = closeDetail;
            document.getElementById('search-box').oninput = render;
            render();
        } catch(e) { console.error(e); }
    </script>
</body>
</html>
'''
    final_html = html_template.replace("INSERT_BASE64_HERE", db_base64)
    with open("index.html", "w", encoding="utf-8") as f: f.write(final_html)

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
