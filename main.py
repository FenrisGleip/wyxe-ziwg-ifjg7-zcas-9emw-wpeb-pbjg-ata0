import os
import json
import re
from tavily import TavilyClient
from groq import Groq
from datetime import datetime, timedelta

# API設定
TAVILY_KEY = os.getenv("TAVILY_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")
tavily = TavilyClient(api_key=TAVILY_KEY)
groq = Groq(api_key=GROQ_KEY)

MASTER_DATA = "all_articles.json"

def fetch_and_analyze():
    # 実行日の前日分を対象にする（2026年3月のコンテキストを維持）
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    
    categories = {
        "MALWARE": f'"{target_date}" (RAT OR malware) technical deep-dive "persistence" "evasion" TTPs',
        "INITIAL": f'"{target_date}" (initial access OR "ClickFix" OR "phishing") delivery "POC" 2026',
        "POST_EXP": f'"{target_date}" (Active Directory OR "post-exploitation" OR "injection") technique PoC',
        "AI_SEC": f'"{target_date}" (Prompt Injection OR "AI Agent" OR "LLM jailbreak") attack vector 2026'
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=4)["results"]
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                # 技術者による技術者のためのプロンプト
                prompt = f"""
                あなたはOSCP/CRTO/GCFAを保有し、妥協を許さないシニア・レッドチーム・リサーチャーです。
                以下のソースを「実戦で即座に使用可能な攻撃モジュール」として再構成してください。
                【制約】2026年3月の最新情報でない、または具体的コマンドやAPI/レジストリ等の技術詳細が皆無な場合は「SKIP」と出力せよ。

                【出力必須項目（HTML形式）】
                1. **Title**: [CVE番号/通称] ターゲットOS/アプリ -> 攻撃の核心メカニズム (30文字以内)
                2. <h3>[0] Prerequisites</h3> (OSビルド、パッチレベル、必要権限、依存ツールを表で)
                3. <h3>[1] Strategic Advantage</h3> (なぜ既存のEDR/AVを回避できるのか、既存手法との決定的な違いを1行で)
                4. <h3>[2] Attack Execution (The Kill Chain)</h3> 
                   - 変数定義(`export TARGET=...`)を含む、ターミナルにコピペして実行可能なコマンドシーケンス。
                   - ペイロードの構造（どのバイトをどう書き換えるか、どのAPIを叩くか）の詳述。
                5. <h3>[3] Technical Deep-Dive</h3> 
                   - 悪用するWindows API/Linux System Call、書き換えるレジストリパス/構成ファイル。
                6. <h3>[4] IoC & Detection Hunter</h3>
                   - SHA256, IP, Domain, Mutex, Registry Path。
                   - SIEMで検知するための具体的なクエリ条件。

                【禁止】「ソースを参照」「適切な対策」等の一般論は一切不要。具体的数値とコードのみを出力せよ。

                URL: {item['url']}
                Content: {item['content'][:9000]}
                """
                
                response = groq.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0
                )
                res_text = response.choices[0].message.content
                if "SKIP" in res_text[:10] or len(res_text) < 700: continue

                # メタデータ抽出
                attack_id = re.search(r'T\d{4}(?:\.\d{3})?', res_text)
                tags = re.findall(r'#(\w+)', res_text)
                title_match = re.search(r'Title\*\*: (.*)', res_text)
                title = title_match.group(1).strip() if title_match else f"[{cat_id}] Raw Intelligence"

                new_articles.append({
                    "date": target_date,
                    "category": cat_id,
                    "title": title,
                    "attack_id": attack_id.group(0) if attack_id else "N/A",
                    "tags": list(set(tags)) if tags else [cat_id, "2026_Exploit"],
                    "content": res_text.split("1. **Title**")[1] if "1. **Title**" in res_text else res_text,
                    "url": item['url']
                })
        except Exception as e: print(f"Error: {e}")
    return new_articles

def update_db_and_ui(new_entries):
    db = []
    if os.path.exists(MASTER_DATA):
        with open(MASTER_DATA, "r", encoding="utf-8") as f:
            db = json.load(f)
    
    existing_urls = {a['url'] for a in db}
    for entry in new_entries:
        if entry['url'] not in existing_urls: db.append(entry)
    
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    json_payload = json.dumps(db)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <title>RT-INTEL: WEAPONIZED DATABASE</title>
        <style>
            :root {{ --bg: #0a0c10; --side: #010409; --card: #161b22; --text: #d1d7dd; --accent: #f85149; --border: #30363d; --code: #000; --green: #7ee787; }}
            body {{ margin: 0; display: flex; font-family: 'Consolas', 'Monaco', monospace; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }}
            
            #sidebar {{ width: 160px; background: var(--side); border-right: 1px solid var(--border); overflow-y: auto; padding: 15px; flex-shrink: 0; }}
            #sidebar h2 {{ font-size: 0.7rem; color: #8b949e; letter-spacing: 2px; text-transform: uppercase; border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
            
            main {{ flex-grow: 1; overflow-y: auto; padding: 30px; position: relative; }}
            .search-bar {{ position: sticky; top: -30px; background: var(--bg); padding: 10px 0 25px; z-index: 100; }}
            #search-box {{ width: 100%; padding: 15px; background: #000; border: 1px solid var(--accent); color: var(--green); border-radius: 4px; font-family: inherit; }}
            
            .article-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: 18px; margin-bottom: 12px; cursor: pointer; border-left: 4px solid var(--border); }}
            .article-card:hover {{ border-color: var(--accent); background: #1c2128; }}
            .meta {{ font-size: 0.7rem; color: #8b949e; margin-bottom: 8px; display: flex; gap: 15px; }}
            .att-id {{ color: var(--accent); font-weight: bold; }}
            
            #detail-view {{ position: fixed; top: 0; right: -100%; width: 75%; height: 100%; background: #0d1117; border-left: 2px solid var(--accent); transition: 0.3s; z-index: 1000; padding: 40px; overflow-y: auto; box-shadow: -20px 0 60px rgba(0,0,0,0.8); }}
            #detail-view.open {{ right: 0; }}
            .close-btn {{ background: var(--accent); color: #fff; border: 0; padding: 8px 20px; cursor: pointer; font-weight: bold; margin-bottom: 30px; }}
            
            h3 {{ color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 5px; font-size: 1.1rem; margin-top: 2em; }}
            pre {{ background: var(--code); padding: 20px; border-radius: 4px; border: 1px solid #333; overflow-x: auto; position: relative; }}
            code {{ color: var(--green); font-family: 'Fira Code', monospace; line-height: 1.5; }}
            .copy-btn {{ position: absolute; top: 10px; right: 10px; padding: 5px 10px; background: #333; color: #fff; border: 0; cursor: pointer; border-radius: 3px; font-size: 0.7rem; }}
            .copy-btn:hover {{ background: var(--accent); }}
            
            .tag {{ color: #58a6ff; font-size: 0.7rem; margin-right: 8px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 0.85rem; }}
            th, td {{ border: 1px solid var(--border); padding: 10px; text-align: left; }}
            th {{ background: #161b22; }}
        </style>
    </head>
    <body>
        <nav id="sidebar">
            <h2>RT-WEAPONS</h2>
            <div id="nav-list"></div>
        </nav>
        <main>
            <div class="search-bar">
                <input type="text" id="search-box" placeholder="grep -i [keyword] articles.db...">
            </div>
            <div id="article-list"></div>
        </main>
        <div id="detail-view">
            <button class="close-btn" onclick="closeDetail()">EXIT_VIEW</button>
            <div id="detail-content"></div>
        </div>

        <script>
            const articles = {json_payload};
            function render() {{
                const query = document.getElementById('search-box').value.toLowerCase();
                const list = document.getElementById('article-list');
                const nav = document.getElementById('nav-list');
                list.innerHTML = ''; nav.innerHTML = '';

                articles.filter(a => (a.title + a.content).toLowerCase().includes(query)).reverse().forEach(a => {{
                    const card = document.createElement('div');
                    card.className = 'article-card';
                    card.style.borderLeftColor = getCatColor(a.category);
                    card.innerHTML = `
                        <div class="meta">
                            <span>[${{a.date}}]</span>
                            <span class="att-id">${{a.attack_id}}</span>
                            <span>${{a.category}}</span>
                        </div>
                        <div style="font-weight:bold; font-size:1rem; color:#fff;">${{a.title}}</div>
                    `;
                    card.onclick = () => openDetail(a);
                    list.appendChild(card);
                    
                    const n = document.createElement('div');
                    n.style.cssText = "font-size:0.6rem; padding:8px; border-bottom:1px solid #21262d; cursor:pointer; color:#8b949e";
                    n.innerText = "> " + a.title.substring(0, 20);
                    n.onclick = () => openDetail(a);
                    nav.appendChild(n);
                }});
            }}

            function getCatColor(cat) {{
                return {{ MALWARE:'#f85149', INITIAL:'#1f6feb', POST_EXP:'#8957e5', AI_SEC:'#238636' }}[cat] || '#ccc';
            }}

            function openDetail(a) {{
                const content = document.getElementById('detail-content');
                content.innerHTML = `
                    <div style="font-size:0.8rem; color:var(--accent); font-weight:bold;"># MISSION_DETAILS: ${{a.category}}</div>
                    <h1 style="margin:10px 0; font-size:1.8rem; border:0; color:#fff;">${{a.title}}</h1>
                    <div style="margin-bottom:20px;">${{a.tags.map(t => '<span class="tag">#'+t+'</span>').join('')}}</div>
                    <div class="body">${{a.content}}</div>
                    <div style="margin-top:50px; font-size:0.7rem; opacity:0.3;">SRC: ${{a.url}}</div>
                `;
                content.querySelectorAll('pre').forEach(block => {{
                    const btn = document.createElement('button');
                    btn.className = 'copy-btn'; btn.innerText = 'COPY';
                    btn.onclick = () => {{
                        const raw = block.innerText.replace('COPY', '');
                        navigator.clipboard.writeText(raw);
                        btn.innerText = 'DONE'; setTimeout(() => btn.innerText='COPY', 2000);
                    }};
                    block.appendChild(btn);
                }});
                document.getElementById('detail-view').classList.add('open');
            }}
            function closeDetail() {{ document.getElementById('detail-view').classList.remove('open'); }}
            document.getElementById('search-box').addEventListener('input', render);
            render();
        </script>
    </body>
    </html>
    """
    with open("index.html", "w", encoding="utf-8") as f: f.write(html_content)

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
