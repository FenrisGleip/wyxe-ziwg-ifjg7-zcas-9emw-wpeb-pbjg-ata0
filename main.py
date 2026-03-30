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
    # 実行日の「前日」をターゲット
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    
    queries = [
        f'"{target_date}" (exploit OR PoC OR "proof of concept") site:github.com OR site:gist.github.com',
        f'"{target_date}" (vulnerability OR "0-day") site:bleepingcomputer.com OR site:thehackernews.com',
        f'new CVE exploit code "{target_date}"',
        f'Dark Web leak ransomware "{target_date}"'
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
    valid_count = 1 # ナンバリング用カウンタ

    for res in unique_results:
        # AIプロンプト：PoCのリンク特定とコード抽出を最優先
        prompt = f"""
        あなたはシニア・エクスプロイト開発者です。以下のソースから2026年3月の最新情報を解析してください。

        【厳守事項】
        1. 2026年3月の記事でない場合は「SKIP」とだけ出力。
        2. タイトルは「#{valid_count} [タイトル]」とし、必ず1から連番にすること。
        3. 【PoC情報】という項目を新設し、以下のいずれかを記載してください：
           - GitHubのPoCリポジトリへの「直接リンク」（ソース記事URLは不可）
           - 記事内にコードがある場合はその「コードブロック」
           - 見つからない場合は「PoC未公開」と記載
        4. 【構成】記事概要、攻撃グループ、刺さる条件、攻撃概要、得られる結果、攻撃再現手順(環境/ツール/実行)、対策。

        ソースURL: {res['url']}
        ソース内容: {res['content'][:8000]}
        """
        
        try:
            response = groq.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            raw_content = response.choices[0].message.content
            
            if "SKIP" in raw_content[:10]:
                continue
            
            # タイトルを抽出（AIが生成したものを利用）
            title_search = re.search(r'#\d+\s+.*?(?=\n|<)', raw_content)
            title = title_search.group(0).strip() if title_search else f"#{valid_count} 最新脅威解析"
            
            articles_data.append({
                "id": f"art-{valid_count}", 
                "title": title, 
                "content": raw_content, 
                "url": res['url']
            })
            valid_count += 1 # 成功時のみカウントアップ
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
                :root {{ --bg: #0d1117; --card-bg: #161b22; --text: #c9d1d9; --primary: #f85149; --secondary: #58a6ff; --border: #30363d; }}
                body {{ margin: 0; display: flex; font-family: sans-serif; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }}
                
                /* 操作性を改善したサイドバー */
                #sidebar {{ width: 250px; min-width: 150px; max-width: 500px; background: #010409; border-right: 1px solid var(--border); overflow-y: auto; flex-shrink: 0; padding: 15px; }}
                #resizer {{ width: 12px; cursor: col-resize; background: transparent; margin-left: -6px; z-index: 10; }}
                #resizer:hover {{ background: rgba(88, 166, 255, 0.3); border-right: 2px solid var(--secondary); }}
                
                main {{ flex-grow: 1; overflow-y: auto; padding: 40px; scroll-behavior: smooth; background: #0d1117; }}
                .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 30px; margin-bottom: 50px; }}
                h1, h2, h3 {{ color: var(--primary); border-bottom: 1px solid #21262d; padding-bottom: 5px; }}
                pre {{ background: #000; padding: 15px; border-radius: 6px; color: #7ee787; font-family: monospace; border: 1px solid #333; overflow-x: auto; }}
                nav a {{ display: block; padding: 8px; color: #8b949e; text-decoration: none; border-bottom: 1px solid #21262d; font-size: 0.85rem; line-height: 1.4; }}
                nav a:hover {{ color: var(--secondary); background: #161b22; }}
            </style>
        </head>
        <body>
            <nav id="sidebar">
                <h2 style="font-size:1rem;">RT-DISPATCH</h2>
                <a href="../index.html" style="color:var(--primary); font-weight:bold;">← PORTAL HOME</a>
                <hr style="border:0; border-top:1px solid var(--border); margin:10px 0;">
                {sidebar_links}
            </nav>
            <div id="resizer"></div>
            <main id="main">
                {main_content}
            </main>

            <script>
                const sidebar = document.getElementById('sidebar');
                const resizer = document.getElementById('resizer');
                resizer.addEventListener('mousedown', (e) => {{
                    document.body.style.cursor = 'col-resize';
                    document.addEventListener('mousemove', onMouseMove);
                    document.addEventListener('mouseup', onMouseUp);
                }});
                function onMouseMove(e) {{
                    sidebar.style.width = e.clientX + 'px';
                }}
                function onMouseUp() {{
                    document.body.style.cursor = 'default';
                    document.removeEventListener('mousemove', onMouseMove);
                }}
            </script>
        </body>
        </html>
        """
        with open(f"archive/{date_str}.html", "w", encoding="utf-8") as f:
            f.write(daily_template)

    # index.html (Portal)
    files = sorted([f for f in os.listdir("archive") if f.endswith(".html")], reverse=True)
    links = "".join([f'<li><a href="archive/{f}" style="color:#58a6ff; text-decoration:none;">{f.replace(".html", "")} - Report</a></li>' for f in files])
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(f"<html><body style='background:#0d1117;color:#c9d1d9;padding:50px;'><h1>RT-ARCHIVE</h1><ul>{links}</ul></body></html>")

if __name__ == "__main__":
    articles = fetch_and_analyze()
    update_web_pages(articles)
