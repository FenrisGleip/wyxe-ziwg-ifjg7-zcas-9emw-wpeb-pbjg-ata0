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
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    
    # 検索クエリ（技術と動向を混合）
    queries = [
        f'"{target_date}" site:github.com (exploit OR PoC OR bypass) "2026"',
        f'"{target_date}" (unhooking OR "direct syscalls" OR "EDR evasion") technical writeup',
        f'"{target_date}" (APT OR "threat actor") campaign report "{target_date}"',
        f'new CVE exploit code "{target_date}"'
    ]
    
    combined_data = []
    for q in queries:
        try:
            res = tavily.search(query=q, search_depth="advanced", max_results=5)["results"]
            category = "TECH" if "exploit" in q or "github" in q else "TREND"
            for item in res:
                combined_data.append({**item, "category": category})
        except: pass

    if not combined_data: return []

    unique_results = {res['url']: res for res in combined_data}.values()
    articles_data = []
    valid_count = 1

    for res in unique_results:
        # 【重要】HTML構造を維持させるための詳細なプロンプト
        prompt = f"""
        あなたは高度なサイバーセキュリティアナリストです。以下のソースを解析し、レッドチーム向けのレポートを作成してください。
        2026年3月の情報でない場合は「SKIP」と出力してください。

        【出力形式の厳守】
        - 以下の項目を必ず <h3> などのHTMLタグで囲み、読みやすく構造化してください。
        - 改行には <br> または <p> を使用してください。
        - コードやコマンドは必ず <pre><code> 形式で出力してください。

        【構成案】
        1. タイトル: #数字 [{res['category']}] [内容の短い言い切り]
        2. <h3>重要度</h3> [Critical/High/Medium/Low]
        3. <h3>攻撃の文脈</h3> (背景、攻撃フェーズ)
        4. <h3>技術詳細/PoC</h3> (手法の仕組み。PoCのURLや生コードをここに記載)
        5. <h3>攻撃再現手順</h3> 
           - <b>[環境準備]</b> ...
           - <b>[ツール準備]</b> ...
           - <b>[攻撃実行]</b> <pre><code>具体的なコマンド</code></pre>
        6. <h3>対策</h3> (検知・防御策)

        ソース: {res['url']}
        内容: {res['content'][:8000]}
        """
        
        try:
            response = groq.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            raw_content = response.choices[0].message.content
            if "SKIP" in raw_content[:10] or len(raw_content) < 300: continue
            
            # タイトル抽出
            title_search = re.search(r'#\d+\s+\[.*?\]\s+.*?(?=\n|<)', raw_content)
            title = title_search.group(0).strip() if title_search else f"#{valid_count} [{res['category']}] Analysis"
            
            articles_data.append({
                "id": f"art-{valid_count}", 
                "title": title, 
                "content": raw_content, 
                "url": res['url'],
                "cat": res['category']
            })
            valid_count += 1
        except: pass
    return articles_data

def update_web_pages(articles):
    date_str = datetime.now().strftime("%Y-%m-%d")
    os.makedirs("archive", exist_ok=True)
    
    sidebar_links = ""
    for a in articles:
        color = "#f85149" if a['cat'] == "TECH" else "#aff5b4"
        sidebar_links += f'<a href="#{a["id"]}" style="border-left: 3px solid {color};">{a["title"]}</a>'

    main_content = "".join([
        f'<section id="{a["id"]}" class="card {"tech-card" if a["cat"]=="TECH" else "trend-card"}">{a["content"]}'
        f'<hr style="border:0; border-top:1px solid #30363d; margin-top:30px;">'
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
                :root {{ --bg: #0d1117; --card-bg: #161b22; --text: #c9d1d9; --primary: #f85149; --trend: #aff5b4; --secondary: #58a6ff; --border: #30363d; }}
                body {{ margin: 0; display: flex; font-family: "Segoe UI", Tahoma, sans-serif; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }}
                
                #sidebar {{ width: 140px; min-width: 60px; max-width: 600px; background: #010409; border-right: 1px solid var(--border); overflow-y: auto; flex-shrink: 0; padding: 10px; }}
                #resizer {{ width: 15px; cursor: col-resize; background: transparent; margin-left: -8px; z-index: 10; }}
                #resizer:hover {{ border-right: 3px solid var(--secondary); }}
                
                main {{ flex-grow: 1; overflow-y: auto; padding: 30px; scroll-behavior: smooth; }}
                .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 30px; margin-bottom: 50px; line-height: 1.7; }}
                .tech-card {{ border-top: 4px solid var(--primary); }}
                .trend-card {{ border-top: 4px solid var(--trend); }}
                
                h1 {{ font-size: 1.8rem; color: #fff; margin-bottom: 30px; }}
                h2 {{ font-size: 1.5rem; color: var(--secondary); border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
                h3 {{ color: #8b949e; margin-top: 1.5em; border-left: 3px solid var(--secondary); padding-left: 10px; font-size: 1.1rem; }}
                
                pre {{ background: #000; padding: 20px; border-radius: 6px; color: #7ee787; font-family: "Consolas", monospace; border: 1px solid #333; overflow-x: auto; margin: 15px 0; }}
                code {{ font-family: inherit; }}
                nav a {{ display: block; padding: 10px; color: #8b949e; text-decoration: none; border-bottom: 1px solid #21262d; font-size: 0.75rem; }}
                nav a:hover {{ color: var(--secondary); background: #161b22; }}
                .src-link {{ font-size: 0.75rem; opacity: 0.6; }}
            </style>
        </head>
        <body>
            <nav id="sidebar">
                <a href="../index.html" style="color:var(--secondary); font-weight:bold;">← HOME</a>
                <div style="font-size:0.6rem; color:#555; margin: 10px 0;">RED: TECH / GRN: TREND</div>
                {sidebar_links}
            </nav>
            <div id="resizer"></div>
            <main id="main">
                <h1>RT-INTEL DISPATCH <small style="font-size:0.9rem; color:#555;">{date_str}</small></h1>
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
                function onMouseMove(e) {{ sidebar.style.width = e.clientX + 'px'; }}
                function onMouseUp() {{ document.body.style.cursor = 'default'; document.removeEventListener('mousemove', onMouseMove); }}
            </script>
        </body>
        </html>
        """
        with open(f"archive/{date_str}.html", "w", encoding="utf-8") as f:
            f.write(daily_template)

    # index.html (ポータル) も一応更新
    files = sorted([f for f in os.listdir("archive") if f.endswith(".html")], reverse=True)
    links = "".join([f'<li><a href="archive/{f}" style="color:#58a6ff; text-decoration:none;">{f.replace(".html", "")} - Report</a></li>' for f in files])
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(f"<html><body style='background:#0d1117;color:#c9d1d9;padding:50px;'><h1>RT-ARCHIVE</h1><ul>{links}</ul></body></html>")

if __name__ == "__main__":
    articles = fetch_and_analyze()
    update_web_pages(articles)
