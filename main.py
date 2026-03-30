import os
import sys

# 取得したキーをチェック（デバッグ用）
TAVILY_KEY = os.getenv("TAVILY_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")

if not TAVILY_KEY or not GROQ_KEY:
    print("Error: APIキーが正しく読み込めていません。SettingsのSecretsを確認してください。")
    sys.exit(1)

import os
from tavily import TavilyClient
from groq import Groq
from datetime import datetime

# APIキーの設定
TAVILY_KEY = os.getenv("TAVILY_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")

tavily = TavilyClient(api_key=TAVILY_KEY)
groq = Groq(api_key=GROQ_KEY)

def fetch_and_analyze():
    # 1. 検索
    query = "latest exploit poc redteam writeup 2026 commands"
    results = tavily.search(query=query, search_depth="advanced", max_results=3)["results"]
    
    reports_html = ""
    for res in results:
        # 2. AIによる解析（HTMLタグを含めて出力させる）
        prompt = f"""
        あなたはRed Team技術者です。以下の情報を解析し、再現手順をHTMLの<div>タグ形式で出力してください。
        - <h3>にタイトル
        - <pre><code>に実行コマンド
        - <p>に解説と注意点
        ソース: {res['url']}
        内容: {res['content'][:5000]}
        """
        response = groq.chat.completions.create(
            model="llama-3.1-70b-versatile",
            messages=[{"role": "user", "content": prompt}]
        )
        reports_html += f"<article style='border-bottom:1px solid #ccc; padding:20px;'>{response.choices[0].message.content}</article>"
    
    return reports_html

def save_as_html(content):
    # 3. 最終的なHTMLファイルを構築
    date_str = datetime.now().strftime("%Y-%m-%d")
    html_template = f"""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="robots" content="noindex">
        <title>Daily Intel - {date_str}</title>
        <style>
            body {{ font-family: sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; background: #f4f4f4; }}
            article {{ background: white; margin-bottom: 20px; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            code {{ background: #eee; padding: 2px 5px; border-radius: 4px; }}
            pre {{ background: #222; color: #fff; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>Red Team Daily Intelligence ({date_str})</h1>
        <p>※本情報は教育および認可されたテスト目的のみに使用してください。</p>
        {content}
    </body>
    </html>
    """
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(html_template)

if __name__ == "__main__":
    report_data = fetch_and_analyze()
    save_as_html(report_data)
