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
    # 日本時間 9:00 (UTC 0:00) 実行時に前日の記事を拾うよう設定
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    
    # クエリの定義（クレジット消費を考慮しつつソースを最大化）
    queries = [
        f'site:bleepingcomputer.com OR site:thehackernews.com "exploit" OR "PoC" after:{yesterday}',
        f'site:unit42.paloaltonetworks.com OR site:mandiant.com "campaign" OR "TTPs" after:{yesterday}',
        f'site:github.com "redteam" OR "exploit" OR "bypass" after:{yesterday}',
        f'site:crowdstrike.com/blog OR site:sentinelone.com/blog after:{yesterday}',
        f'latest "initial access" OR "EDR evasion" writeup 2026 after:{yesterday}'
    ]
    
    raw_results = []
    print(f"Gathering intelligence since {yesterday}...")
    
    for q in queries:
        try:
            res = tavily.search(query=q, search_depth="advanced", max_results=4)["results"]
            raw_results.extend(res)
        except Exception as e:
            print(f"Search Error: {e}")

    if not raw_results:
        return f"<p style='color: #888;'>{yesterday} 以降の新しい攻撃情報は確認されませんでした。</p>"

    unique_results = {res['url']: res for res in raw_results}.values()

    reports_html = ""
    for res in unique_results:
        # AIに対する「再現マニュアル ＋ 防御対策」の指示
        prompt = f"""
        あなたはシニア・レッドチーム・オペレーター兼セキュリティアーキテクトです。
        以下のソースを元に、攻撃の再現と防御対策を網羅した詳細なテクニカルレポートを作成してください。

        【ソース】
        URL: {res['url']}
        内容: {res['content'][:7000]}

        【レポート構成（必ず以下の項目名を使用すること）】
        1. **記事概要**: 内容の簡潔な要約。
        2. **攻撃グループ**: APT名、マルウェア名、または「不明」。
        3. **攻撃が刺さる条件**: 対象OS、パッチレベル、設定、必要権限。
        4. **攻撃概要**: 技術的な論理と既存手法との違い。
        5. **攻撃で得られる結果**: 最終的に攻撃者が達成するゴール。
        6. **攻撃再現手順**:
           - **環境準備**: OS、ネットワーク、必要な依存パッケージ。
           - **攻撃ツール準備**: git clone、コンパイル、ペイロード生成コマンド。
           - **攻撃実行**: 具体的なコマンド例（パラメータ付き）。
        7. **対策**: ブルーチーム向けの検知方法（Sigma/YARA等）、緩和策、設定による防御。

        【出力ルール】
        - 不明な点は「不明」と明記すること。
        - 全て日本語で記述し、コマンドや技術用語は英語を併記すること。
        - 出力はHTMLの <article> タグのみで構成すること。
        """

        try:
            response = groq.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a top-tier security researcher. You provide detailed attack reproduction steps and defensive mitigations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0
            )
            reports_html += f"<article style='background: #111; color: #cfd8dc; border: 1px solid #333; border-left: 6px solid #d32f2f; padding: 25px; margin-bottom: 50px; font-family: \"Consolas\", monospace;'>{response.choices[0].message.content}<br><p><small>Source: <a href='{res['url']}' target='_blank'>{res['url']}</a></small></p></article>"
        except Exception as e:
            print(f"AI Error: {e}")

    return reports_html

def save_as_html(content):
    date_str = datetime.now().strftime("%Y-%m-%d")
    html_template = f"""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="robots" content="noindex, nofollow">
        <title>RED TEAM OPS & DEFENSE: {date_str}</title>
        <style>
            body {{ background-color: #0c0c0c; color: #00e676; font-family: 'Consolas', 'Courier New', monospace; padding: 30px; line-height: 1.6; }}
            .container {{ max-width: 1050px; margin: 0 auto; }}
            header {{ border-bottom: 3px solid #d32f2f; margin-bottom: 30px; padding-bottom: 15px; }}
            h1 {{ font-size: 2.2em; color: #d32f2f; margin: 0; text-transform: uppercase; }}
            article h2, article h3 {{ color: #ff5252; margin-top: 1.8em; border-bottom: 1px solid #222; padding-bottom: 5px; }}
            pre {{ background: #000 !important; color: #00e676 !important; padding: 15px; border: 1px dashed #00e676; overflow-x: auto; margin: 15px 0; }}
            code {{ font-weight: bold; color: #fff; }}
            a {{ color: #03a9f4; text-decoration: none; }}
            .footer {{ text-align: center; margin-top: 60px; color: #333; font-size: 0.8em; padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>> RT-OPS DAILY INTELLIGENCE DISPATCH</h1>
                <p style="color: #666;">Targeting Latest Exploits & Countermeasures | {date_str}</p>
            </header>
            <main>{content}</main>
            <div class="footer">E.O.D. REPORT</div>
        </div>
    </body>
    </html>
    """
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(html_template)

if __name__ == "__main__":
    content = fetch_and_analyze()
    save_as_html(content)
