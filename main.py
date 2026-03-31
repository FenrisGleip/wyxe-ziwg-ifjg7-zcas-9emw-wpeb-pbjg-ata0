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
    # 検索クエリの強化（PoCを明示的に探す）
    categories = {
        "MALWARE": "latest malware technical analysis persistence PoC 2026",
        "INITIAL": "new exploit POC initial access bypass vulnerability 2026",
        "POST_EXP": "Active Directory lateral movement impacket bloodhound technique 2026",
        "AI_SEC": "LLM prompt injection jailbreak PoC exploit 2026"
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=3, search_period="day")["results"]
            if not search_res: continue

            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                prompt = f"""
                あなたは高度なサイバー攻撃を研究するレッドチーム・アナリストです。
                以下のソースから情報を抽出し、技術者が即座に検証・再現できるレベルのレポートを作成してください。

                【出力ルール】
                1. タイトルは「～がどうなった」という指示文をそのまま書かず、新聞の見出しとして完結させること。
                   (悪い例：Windowsの脆弱性を突き特権昇格がどうなった)
                   (良い例：Windows印刷スプーラーに零日脆弱性、DLLインジェクションによる特権昇格が可能)
                2. 攻撃手順は抽象化せず、具体的なステップ(1, 2, 3...)で記述すること。
                3. 実行コマンドは、ツール名、引数、想定されるペイロードをOSCPレベルで具体的に書くこと。
                4. ソース内にGitHubやPoCのURLがある場合、必ず "poc_url" フィールドに抽出すること。
                5. 出力は必ず以下のJSON形式で行うこと。

                {{
                  "title": "具体的かつ自然な日本語見出し",
                  "summary": "3行の核心要約",
                  "poc_url": "ソース内のPoCリンク（なければ空）",
                  "report": "## 概要\\n... ## 再現手順(具体的)\\n... ## 実行コマンド\\n... ## 検知/回避"
                }}

                ソース: {item['content'][:6000]}
                """
                
                try:
                    response = groq.chat.completions.create(
                        model="llama-3.3-70b-versatile",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0,
                        response_format={"type": "json_object"}
                    )
                    res_json = json.loads(response.choices[0].message.content)
                    
                    if not res_json.get("title") or len(res_json.get("report", "")) < 300: continue

                    new_articles.append({
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "category": cat_id,
                        "title": res_json["title"],
                        "summary": res_json["summary"],
                        "poc_url": res_json.get("poc_url", ""),
                        "content": res_json["report"],
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
    
    db = sorted(db, key=lambda x: x['date'], reverse=True)[:100]
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    db_json = json.dumps(db, ensure_ascii=False)
    db_base64 = base64.b64encode(db_json.encode('utf-8')).decode('utf-8')

    html_template = r'''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RED-TACTICAL INTEL</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root { 
            --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
            --MALWARE: #f85149; --INITIAL: #f0883e; --POST_EXP: #a371f7; --AI_SEC: #58a6ff; --green: #7ee787;
        }
        body { margin:0; display:flex; font-family:-apple-system, sans-serif; background:var(--bg); color:var(--text); overflow:hidden; }
        
        /* Sidebar */
        nav { width: 260px; height: 100vh; background: #010409; border-right: 1px solid var(--border); display: flex; flex-direction: column; overflow-y: auto; }
        .sidebar-header { padding: 20px; border-bottom: 1px solid var(--border); }
        .sidebar-header h1 { font-size: 1.2rem; color: #fff; margin: 0 0 15px 0; }
        #search-box { width:100%; padding:10px; background:#000; border:1px solid var(--border); color:var(--green); border-radius:6px; font-family:monospace; box-sizing:border-box; }
        .date-links { padding: 10px; }
        .date-item { padding: 10px; cursor: pointer; border-radius: 6px; font-size: 0.9rem; color: #8b949e; }
        .date-item:hover { background: var(--card); color: #fff; }
        .date-item.active { background: var(--card); color: var(--green); border-left: 3px solid var(--green); }

        /* Main Content */
        main { flex: 1; height: 100vh; overflow-y: auto; padding: 20px; box-sizing: border-box; }
        .feed-container { max-width: 850px; margin: 0 auto; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; margin-bottom:15px; cursor:pointer; }
        .card:hover { border-color: #8b949e; }
        .cat-tag { font-size: 0.7rem; font-weight: bold; padding: 2px 8px; border-radius: 12px; margin-right: 10px; color: #fff; }
        .card-title { font-weight:bold; font-size:1.2rem; line-height:1.4; color:#fff; margin: 10px 0; }
        .card-summary { font-size: 0.85rem; color: #8b949e; }

        /* Detail View */
        #detail-view { position:fixed; top:0; right:-100%; width:100%; height:100%; background:var(--bg); transition: right 0.3s cubic-bezier(0,0,0.2,1); z-index:1000; overflow-y:auto; }
        #detail-view.open { right: 0; }
        .detail-header { position:sticky; top:0; background:rgba(22,27,34,0.9); backdrop-filter:blur(10px); padding:15px; border-bottom:1px solid var(--border); display:flex; align-items:center; }
        .back-btn { background:none; border:none; color:var(--green); font-size:1.5rem; cursor:pointer; padding: 0 20px; }
        .detail-content { max-width: 850px; margin: 0 auto; padding: 30px 20px; }
        .poc-link { display: inline-block; background: #238636; color: #fff; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold; margin: 20px 0; }
        
        /* Markdown Style */
        .detail-content h1, .detail-content h2 { border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-top: 40px; }
        .detail-content pre { background:#000; padding:20px; border-radius:10px; overflow-x:auto; border: 1px solid var(--border); position: relative; }
        .detail-content code { color:var(--green); font-family: 'Consolas', monospace; }
        .copy-btn { position:absolute; top:10px; right:10px; background:#21262d; border:1px solid var(--border); color:#fff; font-size:0.7rem; padding:5px 10px; border-radius:4px; cursor:pointer; }

        @media (max-width: 768px) {
            nav { display: none; } /* Mobile simplicity */
            #detail-view { width: 100%; }
        }
    </style>
</head>
<body>
    <nav>
        <div class="sidebar-header">
            <h1>RED-TACTICAL</h1>
            <input type="text" id="search-box" placeholder="grep...">
        </div>
        <div class="date-links" id="date-list">
            <div class="date-item active" onclick="filterDate('all')">All Intel</div>
        </div>
    </nav>
    <main>
        <div class="feed-container" id="feed"></div>
    </main>
    <div id="detail-view">
        <div class="detail-header"><button class="back-btn" onclick="closeDetail()">← BACK</button><span id="det-cat"></span></div>
        <div class="detail-content" id="det-body"></div>
    </div>

    <script>
        function b64DecodeUnicode(str) {
            return decodeURIComponent(atob(str).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
        }

        const db = JSON.parse(b64DecodeUnicode("INSERT_BASE64_HERE"));
        let currentDate = 'all';

        function initSidebar() {
            const dates = [...new Set(db.map(a => a.date))];
            const list = document.getElementById('date-list');
            dates.forEach(d => {
                const el = document.createElement('div');
                el.className = 'date-item';
                el.innerText = d;
                el.onclick = () => filterDate(d, el);
                list.appendChild(el);
            });
        }

        function filterDate(date, el) {
            currentDate = date;
            document.querySelectorAll('.date-item').forEach(i => i.classList.remove('active'));
            if(el) el.classList.add('active'); else document.querySelector('.date-item').classList.add('active');
            render();
        }

        function render() {
            const q = document.getElementById('search-box').value.toLowerCase();
            const feed = document.getElementById('feed');
            feed.innerHTML = '';
            
            db.filter(a => {
                const matchDate = currentDate === 'all' || a.date === currentDate;
                const matchSearch = (a.title + a.summary + a.content).toLowerCase().includes(q);
                return matchDate && matchSearch;
            }).forEach(a => {
                const el = document.createElement('div');
                el.className = 'card';
                el.innerHTML = `
                    <div style="display:flex; align-items:center;">
                        <span class="cat-tag" style="background:var(--${a.category})">${a.category}</span>
                        <span style="font-size:0.8rem; color:#8b949e;">${a.date}</span>
                    </div>
                    <div class="card-title">${a.title}</div>
                    <div class="card-summary">${a.summary}</div>
                `;
                el.onclick = () => openDetail(a);
                feed.appendChild(el);
            });
        }

        function openDetail(a) {
            const body = document.getElementById('det-body');
            let html = `<h1>${a.title}</h1>`;
            if(a.poc_url && a.poc_url !== "") {
                html += `<a href="${a.poc_url}" target="_blank" class="poc_link">🚀 VIEW PoC REPOSITORY</a>`;
            }
            html += marked.parse(a.content);
            html += `<hr style="border:0; border-top:1px solid var(--border); margin:40px 0;"><a href="${a.url}" target="_blank" style="color:var(--green);">[SOURCE ORIGINAL]</a>`;
            
            body.innerHTML = html;
            document.getElementById('det-cat').innerHTML = `<span class="cat-tag" style="background:var(--${a.category})">${a.category}</span>`;
            
            document.querySelectorAll('pre').forEach(pre => {
                const b = document.createElement('button');
                b.className = 'copy-btn'; b.innerText = 'COPY';
                b.onclick = () => {
                    navigator.clipboard.writeText(pre.innerText.replace('COPY','')).then(() => {
                        b.innerText = 'DONE'; setTimeout(()=>b.innerText='COPY', 1500);
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
        
        initSidebar();
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
