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
        "MALWARE": f'"{target_date}" malware technical analysis persistence 2026',
        "INITIAL": f'"{target_date}" initial access POC delivery 2026',
        "POST_EXP": f'"{target_date}" Active Directory attack PoC 2026',
        "AI_SEC": f'"{target_date}" Prompt Injection attack vector 2026'
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=3)["results"]
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                prompt = "あなたはレッドチーム・リサーチャーです。以下の情報を「武器化」し、Weapon_ID, Tactical_Flow, Target_Requirements, Exploit_Payload, Detection_Evasion, Detection_Rule の順で詳細にまとめなさい。具体的コマンドを含めること。\n\nURL: " + item['url'] + "\nContent: " + item['content'][:8000]
                
                try:
                    response = groq.chat.completions.create(
                        model="llama-3.1-8b-instant",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0
                    )
                    res_text = response.choices[0].message.content
                    if "SKIP" in res_text[:10]: continue

                    attack_id = re.search(r'T\d{4}(?:\.\d{3})?', res_text)
                    title_match = re.search(r'Weapon_ID: (.*)', res_text)
                    
                    new_articles.append({
                        "date": target_date,
                        "category": cat_id,
                        "title": title_match.group(1).strip() if title_match else "RAW_INTEL",
                        "attack_id": attack_id.group(0) if attack_id else "N/A",
                        "content": res_text,
                        "url": item['url']
                    })
                    time.sleep(1)
                except Exception as e:
                    print(f"Groq API Error: {e}")
                    continue
        except Exception as e:
            print(f"Search Error: {e}")
    return new_articles

def update_db_and_ui(new_entries):
    db = []
    if os.path.exists(MASTER_DATA):
        try:
            with open(MASTER_DATA, "r", encoding="utf-8") as f:
                db = json.load(f)
        except: db = []
    
    existing_urls = {a['url'] for a in db}
    for entry in new_entries:
        if entry['url'] not in existing_urls:
            db.append(entry)
    
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    json_payload = json.dumps(db)

    # 文字列の衝突を避けるため、シングルクォートのトリプルを使用し、外部変数として定義
    html_template = '''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>RT-TACTICAL | DATABASE</title>
    <style>
        :root { --bg: #05070a; --card: #0d1117; --accent: #f85149; --text: #c9d1d9; --border: #30363d; --green: #7ee787; }
        body { margin:0; font-family:monospace; background:var(--bg); color:var(--text); overflow-x:hidden; }
        header { position:sticky; top:0; background:var(--bg); border-bottom:1px solid var(--border); padding:15px; z-index:100; }
        #search-box { width:100%; box-sizing:border-box; background:#000; border:1px solid var(--border); color:var(--green); padding:12px; border-radius:8px; font-size:16px; }
        main { padding:15px; padding-bottom:80px; }
        .article-card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; margin-bottom:15px; cursor:pointer; }
        .meta { font-size:0.7rem; color:#8b949e; margin-bottom:8px; display:flex; justify-content:space-between; }
        .attack-id { color:var(--accent); font-weight:bold; }
        #detail-view { position:fixed; top:0; right:-100%; width:100%; height:100%; background:var(--bg); transition: 0.3s; z-index:1000; overflow-y:auto; }
        #detail-view.open { right: 0; }
        .detail-header { position:sticky; top:0; background:var(--card); padding:15px; border-bottom:1px solid var(--border); display:flex; align-items:center; }
        .back-btn { font-size:1.5rem; background:none; border:none; color:var(--accent); cursor:pointer; margin-right:15px; }
        .detail-content { padding:20px; white-space: pre-wrap; line-height: 1.6; }
        pre { background:#000; padding:15px; border-radius:8px; border:1px solid #333; overflow-x:auto; position:relative; white-space: pre; }
        .copy-btn { position:absolute; top:8px; right:8px; background:#21262d; color:#fff; border:0; padding:5px 10px; border-radius:4px; font-size:0.6rem; }
    </style>
</head>
<body>
    <header><input type="text" id="search-box" placeholder="Search Weapons..."></header>
    <main id="article-list"></main>
    <div id="detail-view">
        <div class="detail-header"><button class="back-btn" onclick="closeDetail()">←</button><div id="header-title"></div></div>
        <div class="detail-content" id="detail-body"></div>
    </div>
    <script>
        const db = REPLACE_THIS_WITH_JSON;
        function render() {
            const q = document.getElementById('search-box').value.toLowerCase();
            const list = document.getElementById('article-list');
            list.innerHTML = '';
            db.filter(a => (a.title + a.content).toLowerCase().includes(q)).reverse().forEach(a => {
                const card = document.createElement('div');
                card.className = 'article-card';
                card.innerHTML = `<div class="meta"><span>${a.date}</span><span class="attack-id">${a.attack_id}</span></div><div style="font-weight:bold;">${a.title}</div>`;
                card.onclick = () => openDetail(a);
                list.appendChild(card);
            });
        }
        function openDetail(a) {
            document.getElementById('header-title').innerText = a.title;
            document.getElementById('detail-body').innerHTML = a.content.replace(/\\n/g, '<br>');
            document.querySelectorAll('pre').forEach(p => {
                const b = document.createElement('button');
                b.className = 'copy-btn'; b.innerText = 'COPY';
                b.onclick = (e) => { e.stopPropagation(); navigator.clipboard.writeText(p.innerText.replace('COPY','')); b.innerText = 'DONE'; setTimeout(()=>b.innerText='COPY', 1500); };
                p.appendChild(b);
            });
            document.getElementById('detail-view').classList.add('open');
            window.history.pushState({details:true}, "");
        }
        function closeDetail() { document.getElementById('detail-view').classList.remove('open'); }
        window.onpopstate = closeDetail;
        document.getElementById('search-box').oninput = render;
        render();
    </script>
</body>
</html>
'''
    # 最終的な置換処理
    final_html = html_template.replace("REPLACE_THIS_WITH_JSON", json_payload)
    
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(final_html)

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
