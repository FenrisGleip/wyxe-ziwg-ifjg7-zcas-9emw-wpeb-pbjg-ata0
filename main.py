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
    # より具体的な検索クエリ
    categories = {
        "MALWARE": f'"{target_date}" malware "technical analysis" persistence 2026',
        "INITIAL": f'"{target_date}" "initial access" POC "exploit-db" 2026',
        "POST_EXP": f'"{target_date}" "Active Directory" exploitation lateral 2026',
        "AI_SEC": f'"{target_date}" "LLM" "Prompt Injection" attack 2026'
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=2)["results"]
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                # 情報の質を極限まで高めるプロンプト
                prompt = f"""
                あなたはシニア・ペネトレーションテスターです。以下のソースを元に、レッドチームが即座に利用できる「実戦用レポート」を作成してください。
                解説は不要です。技術的な具体性（コマンド、コード、API名）のみに集中してください。

                【出力フォーマット】
                Weapon_ID: [CVE番号または攻撃名]
                ### 1. Tactical Flow
                (攻撃のステップを箇条書きまたは図で説明)
                ### 2. Requirements
                (対象OS、権限、依存環境)
                ### 3. Exploit Payload
                (実行可能なコマンドやPoCコード。変数は $TARGET 等で記述)
                ### 4. Detection Evasion
                (なぜEDR/AVを回避できるのか、どのAPIフックを避けているか等)
                ### 5. Detection Rule
                (Sigma, Yara, または調査すべきEventID)

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
                    if len(res_text) < 300: continue # 内容が薄い場合はスキップ

                    attack_id = re.search(r'T\d{4}(?:\.\d{3})?', res_text)
                    title_match = re.search(r'Weapon_ID:\s*(.*)', res_text)
                    
                    new_articles.append({
                        "date": target_date,
                        "category": cat_id,
                        "title": title_match.group(1).strip() if title_match else "Unknown Intel",
                        "attack_id": attack_id.group(0) if attack_id else "N/A",
                        "content": res_text,
                        "url": item['url']
                    })
                    time.sleep(2)
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
    
    # JSONのパースエラーを防ぐための処理
    json_payload = json.dumps(db, ensure_ascii=False).replace("'", "\\'")

    html_template = r'''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>RED-TACTICAL DB</title>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --accent: #f85149; --text: #c9d1d9; --border: #30363d; --green: #7ee787; --code-bg: #000; }
        body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); }
        header { position:sticky; top:0; background:rgba(13,17,23,0.9); backdrop-filter:blur(5px); border-bottom:1px solid var(--border); padding:12px; z-index:100; }
        #search-box { width:100%; box-sizing:border-box; background:#000; border:1px solid var(--border); color:var(--green); padding:10px; border-radius:6px; font-size:16px; outline:none; font-family:monospace; }
        main { padding:12px; padding-bottom:100px; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:15px; margin-bottom:12px; cursor:pointer; }
        .card-meta { font-size:0.7rem; color:#8b949e; margin-bottom:4px; display:flex; justify-content:space-between; }
        .card-title { font-weight:bold; font-size:0.95rem; line-height:1.4; color:#adbac7; }
        .id-badge { color:var(--accent); font-weight:bold; }

        #detail-view { position:fixed; top:0; right:-100%; width:100%; height:100%; background:var(--bg); transition: 0.3s cubic-bezier(0,0,0.2,1); z-index:1000; overflow-y:auto; }
        #detail-view.open { right: 0; }
        .detail-header { position:sticky; top:0; background:var(--card); padding:12px; border-bottom:1px solid var(--border); display:flex; align-items:center; }
        .back-btn { font-size:1.5rem; background:none; border:none; color:var(--accent); padding:0 15px; cursor:pointer; }
        .detail-body { padding:20px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Consolas', monospace; font-size: 0.9rem; line-height:1.5; }
        
        h3 { color:var(--accent); font-size:1rem; border-bottom:1px solid #30363d; padding-bottom:5px; margin-top:25px; }
        pre { background:var(--code-bg); padding:15px; border-radius:6px; border:1px solid var(--border); overflow-x:auto; position:relative; margin: 10px 0; }
        code { color: var(--green); }
        .copy-btn { position:absolute; top:5px; right:5px; background:#21262d; color:#fff; border:1px solid #30363d; border-radius:4px; font-size:0.6rem; padding:4px 8px; cursor:pointer; }
    </style>
</head>
<body>
    <header><input type="text" id="search-box" placeholder="grep -i 'exploit' inventory.db..."></header>
    <main id="list"></main>
    <div id="detail-view">
        <div class="detail-header"><button class="back-btn" onclick="closeDetail()">←</button><div id="det-head" style="font-size:0.8rem; font-weight:bold; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"></div></div>
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
                el.innerHTML = `<div class="card-meta"><span>${a.date}</span><span class="id-badge">${a.attack_id}</span></div><div class="card-title">${a.title}</div>`;
                el.onclick = () => openDetail(a);
                list.appendChild(el);
            });
        }

        function openDetail(a) {
            document.getElementById('det-head').innerText = a.title;
            // 簡易マークダウン変換: ### を見出しに、``` を pre/code に
            let html = a.content
                .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
                .replace(/^### (.*$)/gim, '<h3>$1</h3>')
                .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code><button class="copy-btn" onclick="copyCode(this)">COPY</button></pre>');
            
            document.getElementById('det-body').innerHTML = html + `<br><a href="${a.url}" target="_blank" style="color:var(--accent); font-size:0.7rem;">[Original Source]</a>`;
            document.getElementById('detail-view').classList.add('open');
            history.pushState({details:true}, "");
        }

        function copyCode(btn) {
            const code = btn.previousSibling.innerText;
            navigator.clipboard.writeText(code);
            btn.innerText = 'DONE'; setTimeout(() => btn.innerText = 'COPY', 1500);
        }

        function closeDetail() { document.getElementById('detail-view').classList.remove('open'); }
        window.onpopstate = closeDetail;

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
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(final_html)

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
