import os
import sys
import re
from tavily import TavilyClient
from groq import Groq
from datetime import datetime, timedelta

# API設定
TAVILY_KEY = os.getenv("TAVILY_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")
tavily = TavilyClient(api_key=TAVILY_KEY)
groq = Groq(api_key=GROQ_KEY)

def fetch_and_analyze():
    # 実行時点の「前日」をターゲット（UTC 0時実行を想定）
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    
    # 日付フィルタリングをクエリレベルで強制
    queries = [
        f'site:bleepingcomputer.com OR site:thehackernews.com "exploit" OR "PoC" after:{target_date}',
        f'site:unit42.paloaltonetworks.com OR site:mandiant.com "TTPs" after:{target_date}',
        f'site:github.com "exploit" OR "PoC" "2026" after:{target_date}',
        f'latest "initial access" OR "EDR evasion" writeup after:{target_date}'
    ]
    
    raw_results = []
    for q in queries:
        try:
            res = tavily.search(query=q, search_depth="advanced", max_results=5)["results"]
            raw_results.extend(res)
        except: pass

    if not raw_results: return []

    unique_results = {res['url']: res for res in raw_results}.values()
    articles_data = []

    for i, res in enumerate(unique_results):
        # AIプロンプトの強化：日付チェック、タイトル形式、PoCリンク/コードの強制
        prompt = f"""
        あなたはシニア・レッドチーム・リサーチャーです。提供されたソースを解析し、以下の指示を厳守してHTML形式で出力してください。

        【厳守事項】
        1. 記事の日付が {target_date} 前後であることを確認し、古い記事は無視してください。
        2. タイトルは「#1 [概要を端的に表す短い文（言い切り）]」という形式にしてください。
        3. PoC（概念実証）のコード、あるいはGitHub等のPoCリンクがソースにある場合は、必ずそのまま掲載してください。
        
        【構成】
        - 記事概要
        - 攻撃グループ
        - 攻撃が刺さる条件
        - 攻撃概要
        - 攻撃で得られる結果
        - 攻撃再現手順（環境準備、ツール準備、攻撃実行）
        - 対策
        
        ソースURL: {res['url']}
        ソース内容: {res['content'][:7000]}
        """
        
        try:
            response = groq.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            raw_content = response.choices[0].message.content
            
            # AIが生成したテキストからタイトルを抽出（#1 ... の形式）
            title_match = re.search(r'#\d+\s+.*?(?=<)', raw_content)
            title = title_match.group(0) if title_match else f"#{i+1} 最新の脅威解析"
            
            articles_data.append({
                "id": f"art-{i}", 
                "title": title, 
                "content": raw_content, 
                "url": res['url']
            })
        except: pass
    return articles_data

def update_web_pages(articles):
    date_str = datetime.now().strftime("%Y-%m-%d")
    os.makedirs("archive", exist_ok=True)
    
    sidebar_links = "".join([f'<a href="#{a["id"]}">{a["title"]}</a>' for a in articles])
    main_content = "".join([
        f'<section id="{a["id"]}" class="card">{a["content"]}'
        f'<p class="src-link">Source: <a href="{a["url"]}" target="_blank">{a["url"]}</a></p></section>' 
        for a in articles
    ])

    if articles:
        daily_template = f"""
        <!DOCTYPE html>
        <html lang="ja">
        <head>
            <meta charset="UTF-8">
            <title>RT-Intel | {date_str}</title>
            <style>
                :root {{ --bg: #0b0e14; --card-bg: #151921; --text: #c9d1d9; --primary: #f85149; --secondary: #58a6ff; --border: #30363d; --sidebar-w: 320px; }}
                body {{ margin: 0; display: flex; font-family: -apple-system, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }}
                
                /* Resizable Sidebar */
                #sidebar {{ width: var(--sidebar-w); min-width: 200px; max-width: 600px; background: #010409; border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; }}
                #resizer {{ width: 5px; cursor: col-resize; background: transparent; transition: 0.2s; }}
                #resizer:hover, #resizer:active {{ background: var(--secondary); }}
                
                .nav-content {{ padding: 20px; overflow-y: auto; flex-grow: 1; }}
                nav h1 {{ font-size: 1.1rem; color: var(--primary); margin: 0 0 20px 0; border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
                nav a {{ display: block; padding: 10px; color: #8b949e; text-decoration: none; border-radius: 6px; font-size: 0.85rem; margin-bottom: 4px; line-height: 1.4; }}
                nav a:hover {{ background: #161b22; color: var(--secondary); }}
                
                /* Content Area */
                main {{ flex-grow: 1; overflow-y: auto; padding: 40px; scroll-behavior: smooth; background: #0d1117; }}
                .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 30px; margin-bottom: 50px; line-height: 1.8; }}
                h1, h2, h3 {{ color: var(--primary); border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
                pre {{ background: #000; padding: 16px; border-radius: 6px; border: 1px solid #30363d; overflow-x: auto; color: #7ee787; font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; }}
                code {{ font-family: inherit; }}
                .src-link {{ font-size: 0.8rem; color: #8b949e; margin-top: 20px; border-top: 1px solid #21262d; padding-top: 10px; }}
                a {{ color: var(--secondary); }}
            </style>
        </head>
        <body>
            <nav id="sidebar">
                <div class="nav-content">
                    <h1>RT-INTEL DISPATCH</h1>
                    <a href="../index.html" style="color: var(--primary); font-weight: bold;">← PORTAL HOME</a>
                    <hr style="border:0; border-top:1px solid var(--border); margin:15px 0;">
                    {sidebar_links}
                </div>
            </nav>
            <div id="resizer"></div>
            <main id="main-content">
                {main_content}
            </main>

            <script>
                const sidebar = document.getElementById('sidebar');
                const resizer = document.getElementById('resizer');
                resizer.addEventListener('mousedown', (e) => {{
                    document.addEventListener('mousemove', resize);
                    document.addEventListener('mouseup', stopResize);
                }});
                function resize(e) {{ sidebar.style.width = e.pageX + 'px'; }}
                function stopResize() {{
                    document.removeEventListener('mousemove', resize);
                    document.removeEventListener('mouseup', stopResize);
                }}
            </script>
        </body>
        </html>
        """
        with open(f"archive/{date_str}.html", "w", encoding="utf-8") as f:
            f.write(daily_template)

    # index.html (Portal)
    files = sorted([f for f in os.listdir("archive") if f.endswith(".html")], reverse=True)
    links = "".join([f'<li><a href="archive/{f}">{f.replace(".html", "")} - Intelligence Report</a></li>' for f in files])
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(f"<html><head><meta charset='UTF-8'><style>body{{background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:100px;}} li{{margin-bottom:10px;}} a{{color:#58a6ff; text-decoration:none; font-size:1.2rem;}}</style></head><body><h1>RT-INTEL ARCHIVE</h1><ul>{links}</ul></body></html>")

if __name__ == "__main__":
    articles = fetch_and_analyze()
    update_web_pages(articles)
