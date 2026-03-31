import os
import json
import re
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
        "MALWARE": f'"{target_date}" malware "technical analysis" (persistence OR evasion) 2026',
        "INITIAL": f'"{target_date}" (initial access OR "ClickFix") POC "delivery" 2026',
        "POST_EXP": f'"{target_date}" (Credential Access OR "Lateral Movement") attack PoC 2026',
        "AI_SEC": f'"{target_date}" (Prompt Injection OR "Model Inversion") attack vector 2026'
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=5)["results"]
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                prompt = f"""
                あなたはOSCP/CRTO保有のレッドチーム・リードです。
                ソースを解析し、以下の項目に従って「武器化」してください。
                技術詳細がない場合は「SKIP」と出力せよ。

                1. **Weapon_ID**: [CVE/通称] Target -> Method
                2. **Tactical_Flow**: 攻撃ステップのASCII ART。
                3. **Target_Requirements**: 必要環境（OS、権限等）の表。
                4. **Exploit_Payload**: `export TARGET=...` から始まる実戦コマンド群。
                5. **Detection_Evasion**: 回避ロジックの詳述。
                6. **Detection_Rule**: 検知用クエリ。

                URL: {item['url']}
                Content: {item['content'][:9000]}
                """
                # モデルを 8b に変更（高速かつリミットが緩い）
                response = groq.chat.completions.create(
                    model="llama-3.1-8b-instant", 
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0
                )
                #response = groq.chat.completions.create(
                #    model="llama-3.3-70b-versatile",
                #    messages=[{"role": "user", "content": prompt}],
                #    temperature=0.0
                #)
                res_text = response.choices[0].message.content
                if "SKIP" in res_text[:10]: continue

                attack_id = re.search(r'T\d{4}(?:\.\d{3})?', res_text)
                title = re.search(r'Weapon_ID\*\*: (.*)', res_text)
                
                new_articles.append({
                    "date": target_date,
                    "category": cat_id,
                    "title": title.group(1).strip() if title else "RAW_INTEL",
                    "attack_id": attack_id.group(0) if attack_id else "N/A",
                    "content": res_text,
                    "url": item['url']
                })
        except Exception as e: print(f"Error: {e}")
    return new_articles

def update_db_and_ui(new_entries):
    db = []
    if os.path.exists(MASTER_DATA):
        with open(MASTER_DATA, "r", encoding="utf-8") as f: db = json.load(f)
    
    existing_urls = {a['url'] for a in db}
    for entry in new_entries:
        if entry['url'] not in existing_urls: db.append(entry)
    
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    # --- モバイル最適化 UI (Swipeable & Responsive) ---
    html_content = f"""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>RT-TACTICAL | MOBILE</title>
        <style>
            :root {{ --bg: #05070a; --card: #0d1117; --accent: #f85149; --text: #c9d1d9; --border: #30363d; --green: #7ee787; }}
            body {{ margin:0; font-family:'Consolas', monospace; background:var(--bg); color:var(--text); overflow-x:hidden; -webkit-tap-highlight-color: transparent; }}
            
            /* ヘッダー固定 */
            header {{ position:sticky; top:0; background:var(--bg); border-bottom:1px solid var(--border); padding:15px; z-index:100; }}
            #search-box {{ width:100%; box-sizing:border-box; background:#000; border:1px solid var(--border); color:var(--green); padding:12px; border-radius:8px; font-size:16px; /* iOSズーム防止 */ }}
            
            /* 記事リスト */
            main {{ padding:15px; padding-bottom:80px; }}
            .article-card {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; margin-bottom:15px; transition:0.2s; cursor:pointer; }}
            .article-card:active {{ transform: scale(0.98); background:#161b22; }}
            .meta {{ font-size:0.7rem; color:#8b949e; margin-bottom:8px; display:flex; justify-content:space-between; }}
            .attack-id {{ color:var(--accent); font-weight:bold; }}

            /* モバイル詳細ドロワー */
            #detail-view {{ position:fixed; top:0; right:-100%; width:100%; height:100%; background:var(--bg); transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1); z-index:1000; overflow-y:auto; display:flex; flex-direction:column; }}
            #detail-view.open {{ transform: translateX(-100%); }}
            
            .detail-header {{ position:sticky; top:0; background:var(--card); padding:15px; border-bottom:1px solid var(--border); display:flex; align-items:center; }}
            .back-btn {{ font-size:1.5rem; background:none; border:none; color:var(--accent); cursor:pointer; margin-right:15px; }}
            
            .detail-content {{ padding:20px; line-height:1.6; }}
            h3 {{ font-size:0.9rem; color:var(--accent); text-transform:uppercase; border-left:3px solid var(--accent); padding-left:10px; margin:25px 0 15px; }}
            pre {{ background:#000; padding:15px; border-radius:8px; border:1px solid #333; overflow-x:auto; font-size:0.8rem; position:relative; }}
            code {{ color:var(--green); }}
            
            .copy-btn {{ position:absolute; top:8px; right:8px; background:#21262d; color:#fff; border:0; padding:5px 10px; border-radius:4px; font-size:0.6rem; }}
            
            table {{ width:100%; border-collapse:collapse; font-size:0.75rem; margin:15px 0; }}
            th, td {{ border:1px solid var(--border); padding:8px; text-align:left; }}
            
            /* タブ切り替え（PC向けスプリット用） */
            @media (min-width: 768px) {{
                #detail-view {{ flex-direction:row; }}
                .detail-pane {{ width:50%; height:100%; overflow-y:auto; border-right:1px solid var(--border); }}
            }}
        </style>
    </head>
    <body>
        <header>
            <input type="text" id="search-box" placeholder="Search Weapons...">
        </header>
        <main id="article-list"></main>

        <div id="detail-view">
            <div class="detail-header">
                <button class="back-btn" onclick="closeDetail()">←</button>
                <div id="header-title" style="font-size:0.9rem; font-weight:bold; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"></div>
            </div>
            <div class="detail-content" id="detail-body"></div>
        </div>

        <script>
            const db = {json_payload};
            let startX = 0;

            function render() {{
                const q = document.getElementById('search-box').value.toLowerCase();
                const list = document.getElementById('article-list');
                list.innerHTML = '';

                db.filter(a => (a.title + a.content).toLowerCase().includes(q)).reverse().forEach(a => {{
                    const card = document.createElement('div');
                    card.className = 'article-card';
                    card.innerHTML = `
                        <div class="meta">
                            <span>${{a.date}}</span>
                            <span class="attack-id">${{a.attack_id}}</span>
                        </div>
                        <div style="font-weight:bold; font-size:1.1rem; color:#fff;">${{a.title}}</div>
                    `;
                    card.onclick = () => openDetail(a);
                    list.appendChild(card);
                }});
            }}

            function openDetail(a) {{
                const view = document.getElementById('detail-view');
                document.getElementById('header-title').innerText = a.title;
                document.getElementById('detail-body').innerHTML = `
                    <div style="font-size:0.7rem; color:#8b949e; margin-bottom:20px;">CATEGORY: ${{a.category}} | ID: ${{a.attack_id}}</div>
                    ${{a.content}}
                    <div style="margin-top:40px; font-size:0.7rem; opacity:0.3;">SRC: ${{a.url}}</div>
                `;
                
                document.querySelectorAll('pre').forEach(p => {{
                    const b = document.createElement('button');
                    b.className = 'copy-btn'; b.innerText = 'COPY';
                    b.onclick = (e) => {{
                        e.stopPropagation();
                        navigator.clipboard.writeText(p.innerText.replace('COPY',''));
                        b.innerText = 'DONE'; setTimeout(()=>b.innerText='COPY', 1500);
                    }};
                    p.appendChild(b);
                }});
                
                view.classList.add('open');
                window.history.pushState({{details:true}}, ""); // ブラウザの戻るボタン対応
            }}

            function closeDetail() {{ 
                document.getElementById('detail-view').classList.remove('open');
            }}

            // スワイプで閉じる処理
            document.getElementById('detail-view').addEventListener('touchstart', e => startX = e.touches[0].clientX);
            document.getElementById('detail-view').addEventListener('touchend', e => {{
                let endX = e.changedTouches[0].clientX;
                if (endX - startX > 100) closeDetail(); // 右スワイプで閉じる
            }});

            window.onpopstate = closeDetail;
            document.getElementById('search-box').oninput = render;
            render();
        </script>
    </body>
    </html>
    """
    with open("index.html", "w", encoding="utf-8") as f: f.write(html_content)

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
