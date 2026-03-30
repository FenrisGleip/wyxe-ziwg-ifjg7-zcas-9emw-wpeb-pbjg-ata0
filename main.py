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
    
    # 1. 技術レポート用クエリ（手法・PoC・バイパス）
    tech_queries = [
        f'"{target_date}" site:github.com (exploit OR PoC OR bypass) "2026"',
        f'"{target_date}" (unhooking OR "direct syscalls" OR "EDR evasion") technical writeup',
        f'"{target_date}" site:packetstormsecurity.com OR site:exploit-db.com'
    ]
    
    # 2. 脅威動向用クエリ（キャンペーン・APT・リーク・統計）
    intel_queries = [
        f'"{target_date}" (APT OR "threat actor") campaign "initial access"',
        f'"{target_date}" ransomware leak site monitoring report',
        f'"{target_date}" site:mandiant.com OR site:crowdstrike.com/blog "threat intelligence"'
    ]
    
    combined_data = []
    
    # 技術と動向、それぞれから収集
    for category, queries in [("TECH", tech_queries), ("TREND", intel_queries)]:
        for q in queries:
            try:
                res = tavily.search(query=q, search_depth="advanced", max_results=4)["results"]
                for item in res:
                    combined_data.append({**item, "category": category})
            except: pass

    if not combined_data: return []

    unique_results = {res['url']: res for res in combined_data}.values()
    articles_data = []
    valid_count = 1

    for res in unique_results:
        # カテゴリに応じたプロンプトの調整
        category_type = "技術詳細・再現手順" if res['category'] == "TECH" else "攻撃トレンド・戦略動向"
        
        prompt = f"""
        あなたはOSCP/CRTOを保有し、かつCTI（脅威インテリジェンス）に精通したアナリストです。
        以下のソースを解析し、2026年3月の最新情報である場合のみ、詳細なレポートを作成してください。

        【重要：カテゴリ別指示】
        - 記事が「{category_type}」に該当しない、または2026年3月の情報でない場合は「SKIP」と出力。
        - ニュースの要約ではなく、レッドチームが明日から使える「具体的な知見」を抽出してください。

        【構成】
        1. タイトル: #数字 [{res['category']}] [内容を言い切り形式で]
        2. 重要度: Critical/High/Medium/Low
        3. 攻撃の文脈: どのグループが、どのフェーズ（偵察/潜入/横展開）で使っているか。
        4. 技術詳細/PoC: 
           - TECHの場合: 生コード、GitHubのRaw URL、または再現コマンドを必ず記載。
           - TRENDの場合: C2インフラの特徴、悪用されている正規サービス、観測されたIoC。
        5. 再現/観測手順: [Red Team: 再現方法] または [Blue Team: 観測方法]。
        6. 対策: 具体的かつ実戦的な防御策。

        ソースURL: {res['url']}
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
            
            title_search = re.search(r'#\d+\s+.*?(?=\n|<)', raw_content)
            title = title_search.group(0).strip() if title_search else f"#{valid_count} [{res['category']}] 解析"
            
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
    
    # カテゴリ別に色分けしたサイドバーリンク
    sidebar_links = ""
    for a in articles:
        color = "#f85149" if a['cat'] == "TECH" else "#aff5b4"
        sidebar_links += f'<a href="#{a["id"]}" style="border-left: 3px solid {color};">{a["title"]}</a>'

    main_content = "".join([
        f'<section id="{a["id"]}" class="card {"tech-card" if a["cat"]=="TECH" else "trend-card"}">{a["content"]}'
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
                body {{ margin: 0; display: flex; font-family: "Inter", sans-serif; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }}
                
                /* サイドバー：極小設定 */
                #sidebar {{ width: 140px; min-width: 60px; max-width: 600px; background: #010409; border-right: 1px solid var(--border); overflow-y: auto; flex-shrink: 0; padding: 10px; }}
                #resizer {{ width: 15px; cursor: col-resize; background: transparent; margin-left: -8px; z-index: 10; }}
                #resizer:hover {{ border-right: 3px solid var(--secondary); }}
                
                main {{ flex-grow: 1; overflow-y: auto; padding: 30px; scroll-behavior: smooth; }}
                .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px; padding: 25px; margin-bottom: 40px; position: relative; }}
                .tech-card {{ border-top: 4px solid var(--primary); }}
                .trend-card {{ border-top: 4px solid var(--trend); }}
                
                h1, h2, h3 {{ color: var(--text); margin-top: 1.5em; }}
                pre {{ background: #000; padding: 20px; border-radius: 4px; color: #7ee787; font-family: "Consolas", monospace; border: 1px solid #333; overflow-x: auto; }}
                nav a {{ display: block; padding: 8px; color: #8b949e; text-decoration: none; border-bottom: 1px solid #21262d; font-size: 0.7rem; overflow: hidden; }}
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
                <header style="margin-bottom:40px;">
                    <h1 style="border:0; font-size:2rem; margin:0;">RT-INTEL DISPATCH</h1>
                    <p style="color:#555;">Target Date: {date_str}</p>
                </header>
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

    # index.html
    files = sorted([f for f in os.listdir("archive") if f.endswith(".html")], reverse=True)
    links = "".join([f'<li><a href="archive/{f}" style="color:#58a6ff; text-decoration:none;">{f.replace(".html", "")} - Intelligence Report</a></li>' for f in files])
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(f"<html><body style='background:#0d1117;color:#c9d1d9;padding:50px;'><h1>RT-ARCHIVE</h1><ul>{links}</ul></body></html>")

if __name__ == "__main__":
    articles = fetch_and_analyze()
    update_web_pages(articles)
