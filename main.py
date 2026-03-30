import os
import sys
from tavily import TavilyClient
from groq import Groq
from datetime import datetime, timedelta

# API設定
TAVILY_KEY = os.getenv("TAVILY_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")
tavily = TavilyClient(api_key=TAVILY_KEY)
groq = Groq(api_key=GROQ_KEY)

def fetch_and_analyze():
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    queries = [
        f'site:bleepingcomputer.com OR site:thehackernews.com "exploit" OR "PoC" after:{yesterday}',
        f'site:unit42.paloaltonetworks.com OR site:mandiant.com "TTPs" after:{yesterday}',
        f'latest "initial access" OR "EDR evasion" writeup 2026 after:{yesterday}'
    ]
    
    raw_results = []
    for q in queries:
        try:
            res = tavily.search(query=q, search_depth="advanced", max_results=4)["results"]
            raw_results.extend(res)
        except: pass

    if not raw_results: return ""

    unique_results = {res['url']: res for res in raw_results}.values()
    articles_data = [] # 記事データを構造化して保持

    for i, res in enumerate(unique_results):
        prompt = f"""あなたはシニア・レッドチーム・リサーチャーです。以下の構成でHTML(articleタグ)を作成してください。
        構成: 1.記事概要 2.攻撃グループ 3.攻撃が刺さる条件 4.攻撃概要 5.攻撃で得られる結果 
        6.攻撃再現手順(環境準備, ツール準備, 攻撃実行) 7.対策 
        ※各項目は <h3> で作成し、コマンドは <pre><code> で記述。
        ソース: {res['url']} 内容: {res['content'][:7000]}"""
        
        try:
            response = groq.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            # 記事タイトルを抽出（AIが作成した最初の見出しなどを利用）
            title = f"Intelligence #{i+1}" 
            content = response.choices[0].message.content
            articles_data.append({"id": f"art-{i}", "title": title, "content": content, "url": res['url']})
        except: pass
    return articles_data

def update_web_pages(articles):
    date_str = datetime.now().strftime("%Y-%m-%d")
    os.makedirs("archive", exist_ok=True)
    
    # サイドバーのリンク作成
    sidebar_links = "".join([f'<a href="#{a["id"]}">{a["title"]}</a>' for a in articles])
    # メインコンテンツの作成
    main_content = "".join([
        f'<section id="{a["id"]}" class="card"><h2>{a["title"]}</h2>{a["content"]}'
        f'<p><small>Source: <a href="{a["url"]}" target="_blank">{a["url"]}</a></small></p></section>' 
        for a in articles
    ])

    # 1. 個別アーカイブページの作成（モダンUI）
    if articles:
        daily_template = f"""
        <!DOCTYPE html>
        <html lang="ja">
        <head>
            <meta charset="UTF-8">
            <title>RT-Intel | {date_str}</title>
            <style>
                :root {{ --bg: #0f111a; --card-bg: #1a1c2e; --text: #e0e6ed; --primary: #ff3e3e; --secondary: #00f2ff; --border: #2d314d; }}
                body {{ margin: 0; display: flex; font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }}
                /* Sidebar */
                nav {{ width: 280px; background: #0a0b14; border-right: 1px solid var(--border); padding: 20px; overflow-y: auto; flex-shrink: 0; }}
                nav h1 {{ font-size: 1.2rem; color: var(--primary); border-bottom: 2px solid var(--primary); padding-bottom: 10px; }}
                nav a {{ display: block; padding: 12px; color: #8892b0; text-decoration: none; border-radius: 6px; margin-bottom: 5px; font-size: 0.9rem; transition: 0.2s; }}
                nav a:hover {{ background: var(--card-bg); color: var(--secondary); }}
                /* Main Content */
                main {{ flex-grow: 1; overflow-y: auto; padding: 40px; scroll-behavior: smooth; }}
                .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 30px; margin-bottom: 40px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
                h2 {{ color: var(--secondary); margin-top: 0; font-size: 1.8rem; border-bottom: 1px solid var(--border); padding-bottom: 15px; }}
                h3 {{ color: var(--primary); margin-top: 25px; font-size: 1.1rem; text-transform: uppercase; letter-spacing: 1px; }}
                pre {{ background: #000; border-radius: 8px; padding: 20px; border: 1px solid #333; overflow-x: auto; color: #50fa7b; font-family: 'Fira Code', monospace; }}
                code {{ font-family: inherit; }}
                a {{ color: var(--secondary); text-decoration: none; }}
                .back-btn {{ display: inline-block; margin-bottom: 20px; color: var(--primary); font-weight: bold; }}
            </style>
        </head>
        <body>
            <nav>
                <h1>RT-DISPATCH</h1>
                <p><small>{date_str}</small></p>
                <a href="../index.html" class="back-btn">← PORTAL HOME</a>
                <hr style="border: 0; border-top: 1px solid var(--border); margin: 20px 0;">
                {sidebar_links}
            </nav>
            <main>
                {main_content}
            </main>
        </body>
        </html>
        """
        with open(f"archive/{date_str}.html", "w", encoding="utf-8") as f:
            f.write(daily_template)

    # 2. index.html (ポータル) はシンプルに維持
    files = sorted([f for f in os.listdir("archive") if f.endswith(".html")], reverse=True)
    links = "".join([f'<li><a href="archive/{f}">{f.replace(".html", "")} - Intelligence Report</a></li>' for f in files])

    index_template = f"""
    <html><head><meta charset='UTF-8'><title>RT Intelligence Portal</title>
    <style>
        body {{ background:#0f111a; color:#e0e6ed; font-family:sans-serif; padding:100px; display:flex; justify-content:center; }}
        .container {{ max-width: 600px; width: 100%; }}
        h1 {{ color:#ff3e3e; font-size:2.5rem; border-left: 5px solid #ff3e3e; padding-left: 20px; }}
        ul {{ list-style:none; padding:0; margin-top:50px; }}
        li {{ background:#1a1c2e; margin-bottom:10px; border-radius:8px; border:1px solid #2d314d; transition: 0.3s; }}
        li:hover {{ border-color: #00f2ff; transform: translateX(10px); }}
        a {{ display:block; padding:20px; color:#00f2ff; text-decoration:none; }}
    </style></head>
    <body>
        <div class="container">
            <h1>RT-INTEL<br>ARCHIVE</h1>
            <ul>{links}</ul>
        </div>
    </body></html>
    """
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(index_template)

if __name__ == "__main__":
    articles = fetch_and_analyze()
    update_web_pages(articles)
