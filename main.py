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
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    categories = {
        "MALWARE": f'"{target_date}" (RAT OR malware) technical analysis "persistence" "evasion" TTPs',
        "INITIAL": f'"{target_date}" (initial access OR "ClickFix" OR phishing) technique "new" "delivery"',
        "POST_EXP": f'"{target_date}" (Active Directory OR "post-exploitation" OR "lateral movement") attack technique PoC',
        "AI_SEC": f'"{target_date}" (Prompt Injection OR "LLM jailbreak" OR "AI Agent" OR "indirect injection") attack defense'
    }
    
    combined_data = []
    for cat_id, q in categories.items():
        try:
            res = tavily.search(query=q, search_depth="advanced", max_results=3)["results"]
            for item in res:
                combined_data.append({**item, "category_id": cat_id})
        except: pass

    if not combined_data: return []

    articles_data = []
    for i, res in enumerate(combined_data):
        cat_id = res['category_id']
        prompt = f"""
        あなたはシニア・レッドチーム・オペレーターです。2026年3月の最新情報を解析してください。
        技術的詳細（レジストリ、API、PoCコード）を具体的に記述してください。
        
        【出力形式】
        - 記事の内容はHTML形式(<h3>, <pre>, <ul>等)で出力。
        - 最後に【TAGS】として、関連する技術キーワード（例：#WMI, #EDR_Evasion, #C2, #Python）をカンマ区切りで5つ程度出力してください。

        ソース: {res['url']}
        """
        
        try:
            response = groq.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            raw_content = response.choices[0].message.content
            if "SKIP" in raw_content[:10]: continue

            # タグの抽出
            tags = []
            tag_match = re.search(r'【TAGS】(.*)', raw_content)
            if tag_match:
                tags = [t.strip().replace('#', '') for t in tag_match.group(1).split(',')]
                raw_content = raw_content.replace(tag_match.group(0), '') # 本文からタグ指示を消去

            articles_data.append({
                "date": target_date,
                "category": cat_id,
                "title": f"[{cat_id}] " + (re.search(r'#\d+\s+.*?\n', raw_content).group(0) if re.search(r'#\d+\s+.*?\n', raw_content) else "Latest Intel"),
                "content": raw_content,
                "url": res['url'],
                "tags": tags
            })
        except: pass
    return articles_data

def update_database(new_articles):
    # マスターデータの更新
    all_data = []
    if os.path.exists(MASTER_DATA):
        with open(MASTER_DATA, "r", encoding="utf-8") as f:
            all_data = json.load(f)
    
    # 重複URLチェック
    existing_urls = {a['url'] for a in all_data}
    for na in new_articles:
        if na['url'] not in existing_urls:
            all_data.append(na)
    
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(all_data, f, ensure_ascii=False, indent=2)

def generate_portal():
    # 検索機能付きの index.html を生成
    with open(MASTER_DATA, "r", encoding="utf-8") as f:
        data = json.dumps(json.load(f))

    portal_html = f"""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <title>RT-Intel Portal & Search</title>
        <style>
            :root {{ --bg: #0d1117; --card: #161b22; --text: #c9d1d9; --accent: #58a6ff; --border: #30363d; }}
            body {{ background: var(--bg); color: var(--text); font-family: sans-serif; padding: 40px; }}
            #search-box {{ width: 100%; padding: 15px; font-size: 1.2rem; background: #010409; border: 1px solid var(--border); color: #fff; border-radius: 8px; margin-bottom: 20px; }}
            .filter-tags {{ margin-bottom: 30px; }}
            .tag-btn {{ padding: 5px 12px; margin: 4px; background: #21262d; border: 1px solid var(--border); color: var(--text); cursor: pointer; border-radius: 15px; font-size: 0.8rem; }}
            .tag-btn.active {{ background: var(--accent); color: #fff; }}
            .article-item {{ background: var(--card); border: 1px solid var(--border); padding: 20px; margin-bottom: 15px; border-radius: 6px; cursor: pointer; transition: 0.2s; }}
            .article-item:hover {{ border-color: var(--accent); }}
            .item-meta {{ font-size: 0.8rem; color: #8b949e; margin-bottom: 8px; }}
            .badge {{ padding: 2px 8px; border-radius: 4px; font-weight: bold; margin-right: 10px; font-size: 0.7rem; }}
            .MALWARE {{ background: #f85149; color: #fff; }}
            .INITIAL {{ background: #1f6feb; color: #fff; }}
            .POST_EXP {{ background: #8957e5; color: #fff; }}
            .AI_SEC {{ background: #238636; color: #fff; }}
            #detail-view {{ position: fixed; top: 0; right: -100%; width: 70%; height: 100%; background: var(--bg); border-left: 1px solid var(--border); transition: 0.4s; overflow-y: auto; padding: 40px; box-shadow: -10px 0 30px rgba(0,0,0,0.5); }}
            #detail-view.open {{ right: 0; }}
            pre {{ background: #000; padding: 15px; color: #7ee787; border-radius: 5px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>RED TEAM INTELLIGENCE REPOSITORY</h1>
        <input type="text" id="search-box" placeholder="Search keywords, CVE, malware name...">
        <div id="tag-container" class="filter-tags"></div>
        <div id="results"></div>

        <div id="detail-view">
            <button onclick="closeDetail()" style="background:var(--primary); color:#fff; border:0; padding:10px 20px; cursor:pointer;">CLOSE</button>
            <div id="detail-content"></div>
        </div>

        <script>
            const data = {data};
            let currentFilter = 'ALL';

            function render() {{
                const query = document.getElementById('search-box').value.toLowerCase();
                const container = document.getElementById('results');
                container.innerHTML = '';

                const filtered = data.filter(a => {{
                    const matchText = (a.title + a.content + a.tags.join(' ')).toLowerCase().includes(query);
                    const matchTag = currentFilter === 'ALL' || a.category === currentFilter || a.tags.includes(currentFilter);
                    return matchText && matchTag;
                }});

                filtered.reverse().forEach(a => {{
                    const div = document.createElement('div');
                    div.className = 'article-item';
                    div.innerHTML = `
                        <div class="item-meta">
                            <span class="badge ${{a.category}}">${{a.category}}</span>
                            <span>${{a.date}}</span> | <span>Tags: ${{a.tags.join(', ')}}</span>
                        </div>
                        <div style="font-weight:bold; font-size:1.1rem;">${{a.title}}</div>
                    `;
                    div.onclick = () => openDetail(a);
                    container.appendChild(div);
                }});
            }}

            function openDetail(a) {{
                const detail = document.getElementById('detail-view');
                document.getElementById('detail-content').innerHTML = `
                    <div style="margin-top:20px;">
                        <span class="badge ${{a.category}}">${{a.category}}</span> ${{a.date}}
                        <h2 style="color:var(--accent);">${{a.title}}</h2>
                        <hr style="border:0; border-top:1px solid #30363d; margin:20px 0;">
                        ${{a.content}}
                        <p>Source: <a href="${{a.url}}" target="_blank" style="color:var(--accent);">${{a.url}}</a></p>
                    </div>
                `;
                detail.classList.add('open');
            }}
            function closeDetail() {{ document.getElementById('detail-view').classList.remove('open'); }}

            document.getElementById('search-box').oninput = render;
            
            // タグの初期化
            const tags = ['ALL', 'MALWARE', 'INITIAL', 'POST_EXP', 'AI_SEC'];
            const tagContainer = document.getElementById('tag-container');
            tags.forEach(t => {{
                const btn = document.createElement('button');
                btn.className = 'tag-btn';
                btn.innerText = t;
                btn.onclick = () => {{ currentFilter = t; render(); }};
                tagContainer.appendChild(btn);
            }});

            render();
        </script>
    </body>
    </html>
    """
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(portal_html)

if __name__ == "__main__":
    new_articles = fetch_and_analyze()
    update_database(new_articles)
    generate_portal()
