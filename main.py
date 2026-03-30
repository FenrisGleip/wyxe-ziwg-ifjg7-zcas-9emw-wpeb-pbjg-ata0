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
    
    # ニュースサイトを排除し、技術詳細・コード・研究レポートに特化
    queries = [
        f'"{target_date}" site:github.com (exploit OR PoC OR bypass) "2026"',
        f'"{target_date}" site:packetstormsecurity.com OR site:exploit-db.com',
        f'"{target_date}" (unhooking OR "direct syscalls" OR "EDR evasion") technical writeup',
        f'"{target_date}" (Active Directory OR Kerberos) attack technique PoC',
        f'"{target_date}" site:googleprojectzero.blogspot.com OR site:zscaler.com/blogs'
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
    valid_count = 1

    for res in unique_results:
        # AIプロンプト：技術的でないものは「SKIP」
        prompt = f"""
        あなたはOSCP/CRTOを保有するシニア・ペネトレーションテスターです。
        以下のソースから、2026年3月の最新の「攻撃手法」を解析してください。

        【採用基準】
        - 単なる事件ニュース（誰がハックされた等）は「SKIP」と出力して捨ててください。
        - 脆弱性の悪用コード(PoC)、新しいバイパス手法、具体的なコマンド、ツール、または技術的な仕組みが含まれるものだけを採用してください。

        【構成】
        1. タイトル: #数字 [攻撃対象と手法を言い切り形式で]
        2. 攻撃グループ: 判明している場合のみ。
        3. 攻撃が刺さる条件: OSビルド、パッチ番号、設定等。
        4. 攻撃概要: なぜ既存のセキュリティ製品を回避できるのか、どのAPIや論理の隙間を突いているのかを技術的に詳述。
        5. PoC情報: 
           - ソース内の「生コード」をそのまま抜粋するか、GitHubの「RawデータURL」を記載。
           - コードがない場合は、攻撃を再現するための具体的なコマンドライン(CLI)を生成。
        6. 再現手順: [環境準備][ツール準備][攻撃実行]に分け、そのままコピペして動くように記述。
        7. 対策: どのイベントログを監視すべきか、どのレジストリ/ポリシーで封じるか。

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
            
            if "SKIP" in raw_content[:10] or len(raw_content) < 300:
                continue
            
            title_search = re.search(r'#\d+\s+.*?(?=\n|<)', raw_content)
            title = title_search.group(0).strip() if title_search else f"#{valid_count} 技術解析"
            
            articles_data.append({
                "id": f"art-{valid_count}", 
                "title": title, 
                "content": raw_content, 
                "url": res['url']
            })
            valid_count += 1
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
                body {{ margin: 0; display: flex; font-family: "Segoe UI", sans-serif; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }}
                
                /* サイドバーをさらに狭く設定 */
                #sidebar {{ width: 160px; min-width: 80px; max-width: 500px; background: #010409; border-right: 1px solid var(--border); overflow-y: auto; flex-shrink: 0; padding: 10px; }}
                #resizer {{ width: 15px; cursor: col-resize; background: transparent; margin-left: -7px; z-index: 10; }}
                #resizer:hover {{ border-right: 3px solid var(--secondary); }}
                
                main {{ flex-grow: 1; overflow-y: auto; padding: 30px; scroll-behavior: smooth; background: #0d1117; }}
                .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px; padding: 25px; margin-bottom: 40px; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }}
                h1, h2, h3 {{ color: var(--primary); border-bottom: 1px solid #21262d; margin-top: 1.5em; }}
                pre {{ background: #000; padding: 20px; border-radius: 4px; color: #7ee787; font-family: "Consolas", monospace; border: 1px solid #333; overflow-x: auto; line-height: 1.4; }}
                nav a {{ display: block; padding: 10px; color: #8b949e; text-decoration: none; border-bottom: 1px solid #21262d; font-size: 0.75rem; word-wrap: break-word; }}
                nav a:hover {{ color: var(--secondary); background: #161b22; }}
            </style>
        </head>
        <body>
            <nav id="sidebar">
                <a href="../index.html" style="color:var(--primary); font-weight:bold;">← HOME</a>
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
                function onMouseMove(e) {{ sidebar.style.width = e.clientX + 'px'; }}
                function onMouseUp() {{ document.body.style.cursor = 'default'; document.removeEventListener('mousemove', onMouseMove); }}
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
