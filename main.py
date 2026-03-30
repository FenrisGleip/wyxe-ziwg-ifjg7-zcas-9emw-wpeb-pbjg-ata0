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
    # 日本時間 9:00 (UTC 0:00) 実行時に前日の記事をターゲットにする
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    queries = [
        f'site:bleepingcomputer.com OR site:thehackernews.com "exploit" OR "PoC" after:{yesterday}',
        f'site:unit42.paloaltonetworks.com OR site:mandiant.com "TTPs" after:{yesterday}',
        f'site:github.com "redteam" OR "exploit" OR "bypass" after:{yesterday}',
        f'latest "initial access" OR "EDR evasion" writeup 2026 after:{yesterday}'
    ]
    
    raw_results = []
    for q in queries:
        try:
            res = tavily.search(query=q, search_depth="advanced", max_results=4)["results"]
            raw_results.extend(res)
        except: pass

    if not raw_results:
        return ""

    unique_results = {res['url']: res for res in raw_results}.values()
    reports_html = ""
    for res in unique_results:
        prompt = f"""あなたはシニア・レッドチーム・オペレーターです。以下のソースを元に再現マニュアルを作成してください。
        構成: 1.記事概要 2.攻撃グループ 3.攻撃が刺さる条件 4.攻撃概要 5.攻撃で得られる結果 
        6.攻撃再現手順(環境準備, ツール準備, 攻撃実行) 7.対策 
        不明な点は「不明」と記載し、コマンドは具体的かつ詳細に。
        ソース: {res['url']} 内容: {res['content'][:7000]}
        出力はHTMLの<article>タグのみ、日本語で記述してください。"""
        
        try:
            response = groq.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            reports_html += f"<article style='background:#111; padding:25px; margin-bottom:40px; border-left:5px solid #d32f2f; border-bottom:1px solid #333;'>{response.choices[0].message.content}<p><small>Source: <a href='{res['url']}' target='_blank' style='color:#03a9f4;'>{res['url']}</a></small></p></article>"
        except: pass
    return reports_html

def update_web_pages(content):
    date_str = datetime.now().strftime("%Y-%m-%d")
    os.makedirs("archive", exist_ok=True)
    
    # 1. 個別アーカイブページの作成
    if content:
        daily_template = f"""
        <html><head><meta charset='UTF-8'><title>RT-Report: {date_str}</title>
        <style>body{{background:#0c0c0c;color:#cfd8dc;font-family:monospace;padding:30px;line-height:1.6;}} 
        h1{{color:#ff5252;border-bottom:2px solid #ff5252;}} article h2, article h3{{color:#ff5252;}}
        pre{{background:#000;color:#00e676;padding:15px;border:1px dashed #00e676;overflow-x:auto;}}
        a{{color:#03a9f4; text-decoration:none;}}</style></head>
        <body><h1>INTEL REPORT: {date_str}</h1><p><a href='../index.html'>[ BACK TO PORTAL ]</a></p>{content}</body></html>
        """
        with open(f"archive/{date_str}.html", "w", encoding="utf-8") as f:
            f.write(daily_template)

    # 2. index.html (ポータル) の生成
    # archiveフォルダ内のHTMLファイルを日付順にリスト化
    links = []
    files = sorted([f for f in os.listdir("archive") if f.endswith(".html")], reverse=True)
    for f in files:
        display_date = f.replace(".html", "")
        links.append(f"<li><span style='color:#666;'>[{display_date}]</span> <a href='archive/{f}' style='color:#03a9f4; font-size:1.2em;'>Intelligence Report & Reproduction Guide</a></li>")

    index_template = f"""
    <html><head><meta charset='UTF-8'><title>RT Intelligence Portal</title>
    <style>body{{background:#0a0a0a;color:#eee;font-family:monospace;padding:50px;}} 
    h1{{color:#d32f2f; font-size:2.5em; border-bottom:3px solid #d32f2f; padding-bottom:10px;}} 
    ul{{list-style:none; padding:0;}} li{{margin-bottom:20px; padding:10px; border-bottom:1px solid #222;}}
    .footer{{margin-top:100px; color:#444; font-size:0.8em; text-align:center;}}</style></head>
    <body>
        <h1>:: RED TEAM INTELLIGENCE PORTAL ::</h1>
        <p style='color:#888;'>Logged in: Guest | Automated Monitoring: ACTIVE</p>
        <div style='margin-top:40px;'>
            <h3>[ ARCHIVED REPORTS ]</h3>
            <ul>{"".join(links) if links else "<li>No reports available yet.</li>"}</ul>
        </div>
        <div class='footer'>--- END OF DATABASE INTERFACE ---</div>
    </body></html>
    """
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(index_template)

if __name__ == "__main__":
    report_content = fetch_and_analyze()
    update_web_pages(report_content)
