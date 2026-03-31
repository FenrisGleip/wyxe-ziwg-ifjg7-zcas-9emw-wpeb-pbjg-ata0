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
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    categories = {
        "MALWARE": f'"{target_date}" malware "technical analysis" 2026',
        "INITIAL": f'"{target_date}" "initial access" POC 2026',
        "POST_EXP": f'"{target_date}" "Active Directory" exploitation 2026',
        "AI_SEC": f'"{target_date}" "Prompt Injection" LLM 2026'
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=2)["results"]
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                prompt = f"OSCPレベルの武器化レポートを作成せよ。Markdown形式。タイトルにWeapon_IDを含めること。内容: {item['content'][:8000]}"
                
                try:
                    response = groq.chat.completions.create(
                        model="llama-3.1-8b-instant",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0
                    )
                    res_text = response.choices[0].message.content
                    title_match = re.search(r'Weapon_ID:\s*(.*)', res_text)
                    
                    new_articles.append({
                        "date": target_date,
                        "title": title_match.group(1).strip() if title_match else "Tactical Intel",
                        "content": res_text,
                        "url": item['url']
                    })
                    time.sleep(1)
                except: continue
        except: continue
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
    
    # データをBase64化してJSの構文エラーを物理的に回避する
    db_json = json.dumps(db, ensure_ascii=False)
    db_base64 = base64.b64encode(db_json.encode('utf-8')).decode('utf-8')

    html_template = r'''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>RT-TACTICAL DB</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --accent: #f85149; --text: #c9d1d9; --border: #30363d; --green: #7ee787; }
        body { margin:0; font-family:-apple-system,system-ui,sans-serif; background:var(--bg); color:var(--text); -webkit-font-smoothing:antialiased; }
        header { position:sticky; top:0; background:rgba(13,17,23,0.9); backdrop-filter:blur(8px); border-bottom:1px solid var(--border); padding:12px; z-index:100; }
        #search-box { width:100%; box-sizing:border-box; background:#000; border:1px solid var(--border); color:var(--green); padding:12px; border-radius:8px; font-size:16px; outline:none; }
        main { padding:12px; padding-bottom:80px; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:16px; margin-bottom:12px; cursor:pointer; }
        .card:active { opacity:0.7; }
        .card-date { font-size:0.7rem; color:#8b949e; margin-bottom:4px; }
        .card-title { font-weight:bold; font-size:0.95rem; line-height:1.4; }

        #detail-view { position:fixed; top:0; right:-100%; width:100%; height:100%; background:var(--bg); transition: 0.3s cubic-bezier(0,0,0.2,1); z-index:1000; overflow-y:auto; }
        #detail-view.open { right: 0; }
        .detail-header { position:sticky; top:0; background:var(--card); padding:10px; border-bottom:1px solid var(--border); display:flex; align-items:center; }
        .back-btn { font-size:1.8rem; background:none; border:none; color:var(--accent); cursor:pointer; padding:0 15px; }
        .detail-body { padding:20px; font-size: 0.95rem; line-height:1.6; }
        .detail-body h1, .detail-body h2, .detail-body h3 { color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:5px; }
        .detail-body pre { background:#000; padding:15px; border-radius:8px; border:1px solid var(--border); overflow-x:auto; position:relative; }
        .detail-body code { color:var(--green); font-family:monospace; }
        .copy-btn { position:absolute; top:5px; right:5px; background:#21262d; border:1px solid var(--border); color:#fff; border-radius:4px; font-size:0.6rem; padding:4px 8px; }
    </style>
</head>
<body>
    <header><input type="text" id="search-box" placeholder="Search..."></header>
    <main id="list"></main>
    <div id="detail-view">
        <div class="detail-header"><button class="back-btn" onclick="closeDetail()">←</button><div id="det-head" style="font-weight:bold; font-size:0.8rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"></div></div>
        <div class="detail-body" id="det-body"></div>
    </div>
    <script>
        // Base64デコードしてデータを安全にパース
        const dbRaw = "INSERT_BASE64_HERE";
        const db = JSON.parse(decodeURIComponent(escape(atob(dbRaw))));

        function render() {
            const q = document.getElementById('search-box').value.toLowerCase();
            const list = document.getElementById('list');
            list.innerHTML = '';
            const filtered = db.filter(a => (a.title + a.content).toLowerCase().includes(q));
            if(filtered.length === 0) { list.innerHTML = '<p style="text-align:center; color:#8b949e;">No results found.</p>'; return; }
            filtered.reverse().forEach(a => {
                const el = document.createElement('div');
                el.className = 'card';
                el.innerHTML = `<div class="card-date">${a.date}</div><div class="card-title">${a.title}</div>`;
                el.onclick = () => openDetail(a);
                list.appendChild(el);
            });
        }

        function openDetail(a) {
            document.getElementById('det-head').innerText = a.title;
            document.getElementById('det-body').innerHTML = marked.parse(a.content) + `<br><a href="${a.url}" target="_blank" style="color:var(--accent); font-size:0.7rem;">[Source]</a>`;
            document.querySelectorAll('pre').forEach(pre => {
                const b = document.createElement('button');
                b.className = 'copy-btn'; b.innerText = 'COPY';
                b.onclick = (e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(pre.innerText.replace('COPY',''));
                    b.innerText = 'DONE'; setTimeout(()=>b.innerText='COPY', 1000);
                };
                pre.appendChild(b);
            });
            document.getElementById('detail-view').classList.add('open');
            history.pushState({view:'detail'}, '');
        }

        function closeDetail() { document.getElementById('detail-view').classList.remove('open'); }
        window.onpopstate = closeDetail;

        // Swipe back
        let startX = 0;
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
    final_html = html_template.replace("INSERT_BASE64_HERE", db_base64)
    with open("index.html", "w", encoding="utf-8") as f: f.write(final_html)

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
