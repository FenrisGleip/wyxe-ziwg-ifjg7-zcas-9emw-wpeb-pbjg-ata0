import os
import json
import re
import time
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
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    categories = {
        "MALWARE": f'"{target_date}" malware "technical analysis" persistence 2026',
        "INITIAL": f'"{target_date}" "initial access" POC 2026',
        "POST_EXP": f'"{target_date}" "Active Directory" lateral movement 2026',
        "AI_SEC": f'"{target_date}" "LLM" "Prompt Injection" 2026'
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=2)["results"]
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                # 日本語で高品質な構造化データを要求
                prompt = f"""
                あなたはOSCP/レッドチームの専門家です。以下のソースから、実戦で使える「武器化レポート」を作成してください。
                必ず以下のMarkdown構造で出力してください。

                # Weapon_ID: [名称/CVE]
                ## 1. Tactical Flow
                ## 2. Requirements (環境/権限)
                ## 3. Exploit Payload (実行コマンド)
                ## 4. Detection Evasion (回避策)
                ## 5. Detection Rule (検知クエリ)

                URL: {item['url']}
                Content: {item['content'][:8000]}
                """
                
                try:
                    response = groq.chat.completions.create(
                        model="llama-3.1-8b-instant",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0
                    )
                    res_text = response.choices[0].message.content
                    if len(res_text) < 200: continue

                    title_match = re.search(r'Weapon_ID:\s*(.*)', res_text)
                    
                    new_articles.append({
                        "date": target_date,
                        "category": cat_id,
                        "title": title_match.group(1).strip() if title_match else "Tactical Intel",
                        "content": res_text,
                        "url": item['url']
                    })
                    time.sleep(2)
                except Exception as e: print(f"API Error: {e}"); continue
        except Exception as e: print(f"Search Error: {e}")
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
    
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    # 安全にJSONを埋め込む（エスケープ強化）
    json_payload = json.dumps(db, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("'", "\\u0027")

    html_template = r'''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>RT-TACTICAL DB</title>
    <script src="[https://cdn.jsdelivr.net/npm/marked/marked.min.js](https://cdn.jsdelivr.net/npm/marked/marked.min.js)"></script>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --accent: #f85149; --text: #c9d1d9; --border: #30363d; --green: #7ee787; }
        body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); -webkit-font-smoothing: antialiased; }
        header { position:sticky; top:0; background:rgba(13,17,23,0.9); backdrop-filter:blur(10px); border-bottom:1px solid var(--border); padding:12px; z-index:100; }
        #search-box { width:100%; box-sizing:border-box; background:#000; border:1px solid var(--border); color:var(--green); padding:12px; border-radius:8px; font-size:16px; outline:none; }
        
        main { padding:12px; padding-bottom:100px; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:16px; margin-bottom:12px; cursor:pointer; box-shadow: 0 4px 6px rgba(0,0,0,0.2); }
        .card:active { transform: scale(0.98); background: #1c2128; }
        .card-date { font-size:0.7rem; color:#8b949e; margin-bottom:4px; }
        .card-title { font-weight:bold; font-size:1rem; color:#adbac7; line-height:1.4; }

        #detail-view { position:fixed; top:0; right:-100%; width:100%; height:100%; background:var(--bg); transition: transform 0.3s cubic-bezier(0,0,0.2,1); z-index:1000; overflow-y:auto; }
        #detail-view.open { transform: translateX(-100%); }
        .detail-nav { position:sticky; top:0; background:var(--card); padding:10px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:10px; }
        .back-btn { font-size:1.8rem; background:none; border:none; color:var(--accent); cursor:pointer; padding:5px 15px; }
        
        /* Markdown Style */
        .detail-body { padding:20px; font-size: 0.95rem; line-height:1.7; }
        .detail-body h1, .detail-body h2 { color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:8px; margin-top:25px; }
        .detail-body pre { background:#000; padding:15px; border-radius:8px; border:1px solid var(--border); overflow-x:auto; font-family:monospace; margin:15px 0; position:relative; }
        .detail-body code { color:var(--green); background:rgba(0,0,0,0.3); padding:2px 4px; border-radius:4px; }
        .detail-body pre code { background:none; padding:0; }
        .copy-btn { position:absolute; top:8px; right:8px; background:#21262d; color:#fff; border:1px solid var(--border); padding:4px 8px; border-radius:4px; font-size:0.6rem; }
    </style>
</head>
<body>
    <header><input type="text" id="search-box" placeholder="Search Tactical Intel..."></header>
    <main id="list"></main>
    <div id="detail-view">
        <div class="detail-nav"><button class="back-btn" onclick="closeDetail()">←</button><div id="det-head" style="font-size:0.85rem; font-weight:bold; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"></div></div>
        <div class="detail-body" id="det-body"></div>
    </div>
    <script>
        const db = INSERT_JSON_HERE;
        let startX = 0;

        function render() {
            const q = document.getElementById('search-box').value.toLowerCase();
            const list = document.getElementById('list');
            list.innerHTML = '';
            db.filter(a => (a.title + a.content).toLowerCase().includes(q)).reverse().forEach(a => {
                const el = document.createElement('div');
                el.className = 'card';
                el.innerHTML = `<div class="card-date">${a.date}</div><div class="card-title">${a.title}</div>`;
                el.onclick = () => openDetail(a);
                list.appendChild(el);
            });
        }

        function openDetail(a) {
            document.getElementById('det-head').innerText = a.title;
            // Markdownレンダリングの実行
            document.getElementById('det-body').innerHTML = marked.parse(a.content) + 
                `<hr style="border:0; border-top:1px solid var(--border); margin:30px 0;">
                 <a href="${a.url}" target="_blank" style="color:var(--accent); font-size:0.8rem;">[Source Reference]</a>`;
            
            // コピーボタンの動的追加
            document.querySelectorAll('pre').forEach(pre => {
                const b = document.createElement('button');
                b.className = 'copy-btn'; b.innerText = 'COPY';
                b.onclick = (e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(pre.innerText.replace('COPY',''));
                    b.innerText = 'DONE'; setTimeout(()=>b.innerText='COPY', 1500);
                };
                pre.appendChild(b);
            });
            
            document.getElementById('detail-view').classList.add('open');
            history.pushState({view:'detail'}, '');
        }

        function closeDetail() { document.getElementById('detail-view').classList.remove('open'); }
        window.onpopstate = closeDetail;

        // Swipe to Close
        document.getElementById('detail-view').addEventListener('touchstart', e => startX = e.touches[0].clientX);
        document.getElementById('detail-view').addEventListener('touchend', e => {
            if (e.changedTouches[0].clientX - startX > 100) closeDetail();
        });

        document.getElementById('search-box').oninput = render;
        render();
    </script>
</body>
</html>
'''
    final_html = html_template.replace("INSERT_JSON_HERE", json_payload)
    with open("index.html", "w", encoding="utf-8") as f: f.write(final_html)

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
