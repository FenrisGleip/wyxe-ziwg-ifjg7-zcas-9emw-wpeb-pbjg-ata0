import os
import json
import re
import time
import base64
import urllib.parse
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
    # 実行日の前日のニュースを対象にする
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    categories = {
        "MALWARE": f'"{target_date}" malware technical analysis persistence',
        "INITIAL": f'"{target_date}" "initial access" exploit POC',
        "POST_EXP": f'"{target_date}" "Active Directory" attack movement',
        "AI_SEC": f'"{target_date}" LLM "Prompt Injection" attack'
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=2)["results"]
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                # 強力な日本語指定プロンプト
                prompt = f"""
                あなたは優秀なサイバーセキュリティ・アナリストです。以下の情報を【必ず日本語で】分析し、レッドチーム向けのリサーチレポートを作成してください。
                
                【出力ルール】
                1. タイトルは「Weapon_ID: [名称]」の形式にすること。
                2. セクション見出しは ## を使用すること。
                3. コマンドやコードは必ず ``` で囲むこと。
                
                【構成案】
                # Weapon_ID: [名称]
                ## 概要
                (何ができる攻撃か)
                ## 攻撃フロー
                (1. 2. 3. と手順を追って解説)
                ## 実行ペイロード / コマンド
                (OSCP等のラボでそのまま使える形式)
                ## 検知と回避策
                (防御側が注目すべきログや、攻撃側が施す回避工夫)

                ソース内容: {item['content'][:8000]}
                """
                
                try:
                    response = groq.chat.completions.create(
                        model="llama-3.1-8b-instant",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.2
                    )
                    res_text = response.choices[0].message.content
                    if len(res_text) < 300: continue

                    title_match = re.search(r'Weapon_ID:\s*(.*)', res_text)
                    
                    new_articles.append({
                        "date": target_date,
                        "category": cat_id,
                        "title": title_match.group(1).strip() if title_match else "技術インテリジェンス",
                        "content": res_text,
                        "url": item['url']
                    })
                    time.sleep(2) # レートリミット回避
                except: continue
        except: continue
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
    
    # 日付順（新しい順）にソート
    db = sorted(db, key=lambda x: x['date'], reverse=True)
    
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    # 日本語を壊さずにBase64化する最強の組み合わせ (URIエンコード -> Base64)
    db_json = json.dumps(db, ensure_ascii=False)
    db_encoded = urllib.parse.quote(db_json)
    db_base64 = base64.b64encode(db_encoded.encode('utf-8')).decode('utf-8')

    html_template = r'''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>RED-TACTICAL INTELLIGENCE</title>
    <script src="[https://cdn.jsdelivr.net/npm/marked/marked.min.js](https://cdn.jsdelivr.net/npm/marked/marked.min.js)"></script>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --accent: #f85149; --text: #c9d1d9; --border: #30363d; --green: #7ee787; }
        body { margin:0; font-family:-apple-system,BlinkMacSystemFont,sans-serif; background:var(--bg); color:var(--text); }
        header { position:sticky; top:0; background:rgba(13,17,23,0.95); backdrop-filter:blur(10px); border-bottom:1px solid var(--border); padding:15px; z-index:100; }
        #search-box { width:100%; box-sizing:border-box; background:#000; border:1px solid var(--border); color:var(--green); padding:12px; border-radius:8px; font-size:16px; font-family:monospace; }
        
        main { padding:12px; max-width: 800px; margin: 0 auto; padding-bottom:100px; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:18px; margin-bottom:15px; cursor:pointer; box-shadow: 0 4px 10px rgba(0,0,0,0.3); transition: 0.2s; }
        .card:active { transform: scale(0.97); opacity: 0.8; }
        .card-meta { font-size:0.75rem; color:#8b949e; display:flex; justify-content:space-between; margin-bottom:8px; }
        .cat-badge { border: 1px solid var(--accent); color: var(--accent); padding: 1px 6px; border-radius:4px; font-weight:bold; font-size: 0.65rem; }
        .card-title { font-weight:bold; font-size:1.05rem; line-height:1.4; color:#fff; }

        #detail-view { position:fixed; top:0; left:100%; width:100%; height:100%; background:var(--bg); transition: transform 0.3s cubic-bezier(0,0,0.2,1); z-index:1000; overflow-y:auto; }
        #detail-view.open { transform: translateX(-100%); }
        .detail-header { position:sticky; top:0; background:var(--card); padding:12px; border-bottom:1px solid var(--border); display:flex; align-items:center; }
        .back-btn { font-size:1.8rem; background:none; border:none; color:var(--accent); cursor:pointer; padding:0 20px; }
        .detail-body { padding:20px; font-size: 1rem; line-height:1.7; max-width: 800px; margin: 0 auto; }
        
        /* Markdown Style Adjustments */
        .detail-body h1, .detail-body h2 { color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:10px; margin-top:30px; }
        .detail-body pre { background:#000; padding:15px; border-radius:10px; border:1px solid var(--border); overflow-x:auto; position:relative; margin: 20px 0; }
        .detail-body code { color:var(--green); font-family: 'Consolas', monospace; font-size: 0.9rem; }
        .copy-btn { position:absolute; top:8px; right:8px; background:#21262d; border:1px solid var(--border); color:#fff; border-radius:5px; font-size:0.65rem; padding:5px 10px; cursor:pointer; }
    </style>
</head>
<body>
    <header><input type="text" id="search-box" placeholder="Search Intel (e.g. T1059)..."></header>
    <main id="list"></main>
    <div id="detail-view">
        <div class="detail-header"><button class="back-btn" onclick="closeDetail()">←</button><div id="det-head" style="font-weight:bold; font-size:0.85rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"></div></div>
        <div class="detail-body" id="det-body"></div>
    </div>
    <script>
        // 日本語マルチバイト対応のデコード処理
        try {
            const dbBase64 = "INSERT_BASE64_HERE";
            const dbDecoded = decodeURIComponent(atob(dbBase64));
            const db = JSON.parse(dbDecoded);

            function render() {
                const q = document.getElementById('search-box').value.toLowerCase();
                const list = document.getElementById('list');
                list.innerHTML = '';
                const filtered = db.filter(a => (a.title + a.content).toLowerCase().includes(q));
                
                if(filtered.length === 0) {
                    list.innerHTML = '<p style="text-align:center; margin-top:50px; color:#8b949e;">No intel found.</p>';
                    return;
                }

                filtered.forEach(a => {
                    const el = document.createElement('div');
                    el.className = 'card';
                    el.innerHTML = `
                        <div class="card-meta">
                            <span>${a.date}</span>
                            <span class="cat-badge">${a.category || 'INTEL'}</span>
                        </div>
                        <div class="card-title">${a.title}</div>`;
                    el.onclick = () => openDetail(a);
                    list.appendChild(el);
                });
            }

            function openDetail(a) {
                document.getElementById('det-head').innerText = a.title;
                document.getElementById('det-body').innerHTML = marked.parse(a.content) + 
                    `<hr style="border:0; border-top:1px solid var(--border); margin:40px 0;"><a href="${a.url}" target="_blank" style="color:var(--accent); font-size:0.8rem;">[ソースを確認する]</a>`;
                
                document.querySelectorAll('pre').forEach(pre => {
                    const b = document.createElement('button');
                    b.className = 'copy-btn'; b.innerText = 'COPY';
                    b.onclick = (e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(pre.innerText.replace('COPY','')).then(() => {
                            b.innerText = 'DONE'; setTimeout(()=>b.innerText='COPY', 1500);
                        });
                    };
                    pre.appendChild(b);
                });
                
                document.getElementById('detail-view').classList.add('open');
                history.pushState({view:'detail'}, '');
            }

            function closeDetail() {
                document.getElementById('detail-view').classList.remove('open');
            }

            window.onpopstate = () => closeDetail();

            let touchStartX = 0;
            document.getElementById('detail-view').addEventListener('touchstart', e => touchStartX = e.touches[0].clientX);
            document.getElementById('detail-view').addEventListener('touchend', e => {
                if (e.changedTouches[0].clientX - touchStartX > 100) closeDetail();
            });

            document.getElementById('search-box').oninput = render;
            render();
        } catch(e) {
            document.getElementById('list').innerHTML = '<p style="color:red; text-align:center;">データの読み込みに失敗しました。再ビルドしてください。</p>';
            console.error(e);
        }
    </script>
</body>
</html>
'''
    final_html = html_template.replace("INSERT_BASE64_HERE", db_base64)
    with open("index.html", "w", encoding="utf-8") as f: f.write(final_html)

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
