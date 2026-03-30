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
    # 実行日の「前日」をターゲットに設定（2026-03-29等）
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    
    # クエリの強化：PoC、Exploit、Dark Webリーク報告、0-dayをターゲット
    # 過去の記事を排除するため検索キーワードに日付と "new" を含める
    queries = [
        f'"{target_date}" (exploit OR PoC OR vulnerability) site:bleepingcomputer.com OR site:thehackernews.com',
        f'"{target_date}" site:github.com (exploit OR PoC OR "0-day")',
        f'"{target_date}" (dark web leak OR underground forum) ransomware OR malware intel',
        f'new CVE "{target_date}" reproduction PoC code'
    ]
    
    raw_results = []
    for q in queries:
        try:
            # search_depth="advanced" でより深い情報を取得
            res = tavily.search(query=q, search_depth="advanced", max_results=5)["results"]
            raw_results.extend(res)
        except: pass

    if not raw_results: return []

    # URL重複排除
    unique_results = {res['url']: res for res in raw_results}.values()
    articles_data = []

    for i, res in enumerate(unique_results):
        # AIへの指示：日付の厳守、タイトルの個別化、PoCの徹底調査
        prompt = f"""
        あなたは高度なレッドチーム・アナリストです。以下のソースを解析し、2026年3月の最新情報である場合のみ、HTML形式で出力してください。

        【最優先指示】
        1. 記事が古い（2022年〜2025年など）場合は、出力を「SKIP」の1文字だけにしてください。
        2. タイトルは「#{i+1} [攻撃手法や脆弱性の内容を15文字程度で言い切り形式で記述]」としてください（例：#1 Citrix RCEのPoC公開）。
        3. 脆弱性に関する内容なら、GitHub、Gist、ブログ内のコード等、PoCの所在を徹底的に探し、リンクまたはコードを【攻撃再現手順】に記載してください。

        【構成】
        - 記事概要
        - 攻撃グループ
        - 攻撃が刺さる条件
        - 攻撃概要
        - 攻撃で得られる結果
        - 攻撃再現手順（環境準備、ツール準備、攻撃実行）
        - 対策

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
            
            # 古い記事のフィルタリング
            if "SKIP" in raw_content[:10]:
                continue
            
            # タイトルの抽出（AIが生成した #1 [タイトル] を探す）
            title_search = re.search(r'#\d+\s+.*?(?=\s|<)', raw_content)
            title = title_search.group(0).strip() if title_search else f"#{i+1} 最新インテリジェンス"
            
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
                :root {{ --bg: #0d1117; --card-bg: #161b22; --text: #c9d1d9; --primary: #f85149; --secondary: #58a6ff; --border: #30363d; }}
                body {{ margin: 0; display: flex; font-family: sans-serif; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }}
                
                /* 可動サイドバーのスタイル */
                #sidebar {{ width: 350px; min-width: 200px; background: #010409; border-right: 1px solid var(--border); overflow-y: auto; flex-shrink: 0; padding: 20px; }}
                #resizer {{ width: 8px; cursor: col-resize; background: #21262d; border-right: 1px solid var(--border); }}
                #resizer:hover {{ background: var(--secondary); }}
                
                main {{ flex-grow: 1; overflow-y: auto; padding: 40px; scroll-behavior: smooth; }}
                .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 30px; margin-bottom: 50px; }}
                h1, h2, h3 {{ color: var(--primary); }}
                pre {{ background: #000; padding: 20px; border-radius: 6px; overflow-x: auto; color: #7ee787; font-family: monospace; border: 1px solid #333; }}
                nav a {{ display: block; padding: 12px; color: #8b949e; text-decoration: none; border-bottom: 1px solid #21262d; font-size: 0.9rem; }}
                nav a:hover {{ color: var(--secondary); background: #161b22; }}
            </style>
        </head>
        <body>
            <nav id="sidebar">
                <h2 style="font-size:1.2rem;">RT-DISPATCH</h2>
                <a href="../index.html" style="color:var(--primary); font-weight:bold;">← PORTAL HOME</a>
                <hr style="border:0; border-top:1px solid var(--border); margin:20px 0;">
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
                    document.addEventListener('mousemove', onMouseMove);
                    document.addEventListener('mouseup', onMouseUp);
                }});
                function onMouseMove(e) {{
                    const newWidth = e.clientX;
                    if (newWidth > 150 && newWidth < 800) {{
                        sidebar.style.width = newWidth + 'px';
                    }}
                }}
                function onMouseUp() {{
                    document.removeEventListener('mousemove', onMouseMove);
                }}
            </script>
        </body>
        </html>
        """
        with open(f"archive/{date_str}.html", "w", encoding="utf-8") as f:
            f.write(daily_template)

    # index.html 更新
    files = sorted([f for f in os.listdir("archive") if f.endswith(".html")], reverse=True)
    links = "".join([f'<li><a href="archive/{f}" style="color:#58a6ff; font-size:1.2rem; text-decoration:none;">{f.replace(".html", "")} - Intelligence Report</a></li>' for f in files])
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(f"<html><head><meta charset='UTF-8'></head><body style='background:#0d1117;color:#c9d1d9;padding:100px;'><h1>RT-INTEL ARCHIVE</h1><ul>{links}</ul></body></html>")

if __name__ == "__main__":
    articles = fetch_and_analyze()
    update_web_pages(articles)
