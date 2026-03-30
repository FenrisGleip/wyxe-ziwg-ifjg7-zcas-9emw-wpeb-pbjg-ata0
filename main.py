import os
import sys
from tavily import TavilyClient
from groq import Groq
from datetime import datetime, timedelta

# APIキーの取得
TAVILY_KEY = os.getenv("TAVILY_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")

if not TAVILY_KEY or not GROQ_KEY:
    print("Error: APIキーが設定されていません。")
    sys.exit(1)

tavily = TavilyClient(api_key=TAVILY_KEY)
groq = Groq(api_key=GROQ_KEY)

def fetch_and_analyze():
    # UTC 0時実行を考慮し、前日分をターゲットにする
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    
    # 1. 1日約30クレジットを使い切るための多角的クエリ (10個)
    # 特定ドメインを指定しつつ、最新手法(PoC/Evasion)を狙い撃つ
    queries = [
        f'site:bleepingcomputer.com "vulnerability" OR "exploit" after:{yesterday}',
        f'site:thehackernews.com "attack" OR "malware" after:{yesterday}',
        f'site:darkreading.com "threat intelligence" after:{yesterday}',
        f'site:unit42.paloaltonetworks.com OR site:mandiant.com after:{yesterday}',
        f'site:crowdstrike.com/blog OR site:sentinelone.com/blog after:{yesterday}',
        f'site:microsoft.com/en-us/security/blog after:{yesterday}',
        f'site:gist.github.com "red team" OR "exploit" after:{yesterday}',
        f'site:reddit.com/r/netsec "writeup" OR "PoC" after:{yesterday}',
        f'latest EDR evasion "unhooking" OR "indirect syscalls" after:{yesterday}',
        f'new initial access vector "phishing" OR "mfa bypass" 2026 after:{yesterday}'
    ]
    
    raw_results = []
    print(f"Searching for intelligence since {yesterday}...")
    
    for q in queries:
        try:
            # 1クエリあたり3件取得 = 合計30件程度。月間約1000クレジットに最適化
            res = tavily.search(query=q, search_depth="advanced", max_results=3)["results"]
            raw_results.extend(res)
        except Exception as e:
            print(f"Search Error for {q}: {e}")

    if not raw_results:
        return f"<p style='color: #666;'>{yesterday} 以降の新規レポートは見は見つかりませんでした。</p>"

    # URL重複の排除
    unique_results = {res['url']: res for res in raw_results}.values()

    reports_html = ""
    for res in unique_results:
        # 2. AIによるエクスプロイト深掘り解析
        prompt = f"""
        あなたは世界トップクラスのレッドチーム・リサーチャーです。
        以下の最新記事を読み、技術的な「差分」と「再現手順」を抽出してください。

        【ソース】
        URL: {res['url']}
        内容: {res['content'][:7000]}

        【必須解析項目】
        1. **技術的差分**: 従来の手法（既知のCVEや一般的な攻撃）と比較して、何が新しいのか？（APIの使いかた、難読化、論理の飛躍など）
        2. **再現実装 (Deep Dive)**: 記事にコードがない場合でも、あなたの知識から、その手法を検証するための「具体的なコマンド」や「PoCコード(Python/C#/C++/PowerShell等)」を詳細に生成してください。
        3. **攻撃パス**: 初期侵入からC2通信、あるいは権限昇格に至るまでのフローを技術的に解説してください。
        
        全て日本語で出力し、技術用語は適切に英語を併記してください。
        出力はHTMLの <article> タグのみ。
        """

        try:
            response = groq.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You provide high-end, actionable red team intelligence with specific PoC code."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            reports_html += f"<article style='background: #fff; border: 1px solid #ddd; border-left: 8px solid #d32f2f; padding: 30px; margin-bottom: 50px; box-shadow: 0 4px 12px rgba(0,0,0,0.05);'>{response.choices[0].message.content}</article>"
        except Exception as e:
            print(f"AI Analysis Error: {e}")

    return reports_html

def save_as_html(content):
    date_str = datetime.now().strftime("%Y-%m-%d")
    html_template = f"""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <meta name="robots" content="noindex, nofollow">
        <title>RT-INTEL: {date_str}</title>
        <style>
            body {{ font-family: 'Segoe UI', 'Consolas', monospace; background: #121212; color: #e0e0e0; padding: 40px; line-height: 1.6; }}
            .container {{ max-width: 1100px; margin: 0 auto; }}
            header {{ border-bottom: 4px solid #d32f2f; margin-bottom: 40px; padding-bottom: 20px; }}
            h1 {{ font-size: 2.5em; color: #ff5252; margin: 0; }}
            article {{ background: #1e1e1e !important; color: #e0e0e0 !important; border: 1px solid #333 !important; }}
            h3 {{ color: #ff5252; border-bottom: 1px solid #444; padding-bottom: 10px; }}
            pre {{ background: #000; color: #00ff00; padding: 20px; border-radius: 4px; border: 1px solid #333; overflow-x: auto; }}
            code {{ font-family: 'Consolas', monospace; }}
            .meta {{ color: #aaa; font-size: 0.9em; }}
            a {{ color: #448aff; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>RED TEAM DAILY INTELLIGENCE</h1>
                <p class="meta">Analysis Period: Since {date_str} (Targeting High-End Vendor Reports & Exploits)</p>
            </header>
            <main>{content}</main>
            <div class="footer" style="text-align:center; margin-top:50px; color:#555;">&copy; 2026 Red Team Intelligence Automaton</div>
        </div>
    </body>
    </html>
    """
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(html_template)

if __name__ == "__main__":
    content = fetch_and_analyze()
    save_as_html(content)
