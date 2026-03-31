import os
import json
import re
import time
import base64
from tavily import TavilyClient
from groq import Groq
from datetime import datetime, timedelta

# --- SETTINGS ---
TAVILY_KEY = os.getenv("TAVILY_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")
tavily = TavilyClient(api_key=TAVILY_KEY)
groq = Groq(api_key=GROQ_KEY)

MASTER_DATA = "all_articles.json"

def fetch_and_analyze():
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    categories = {
        "MALWARE": f'"{target_date}" malware technical analysis 2026',
        "INITIAL": f'"{target_date}" "initial access" exploit POC 2026',
        "POST_EXP": f'"{target_date}" "Active Directory" attack 2026',
        "AI_SEC": f'"{target_date}" LLM "Prompt Injection" technique 2026'
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=2)["results"]
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                # 構造化されたJSON出力を強制するプロンプト
                prompt = f"""
                あなたはレッドチームの専門家です。以下のソースを元に【日本語で】技術レポートを作成してください。
                
                【重要ルール】
                1. タイトルと内容を完全に一致させること。無関係な「印刷スプーラー」等の固定タイトルを使用することは厳禁。
                2. 記事を途中で終わらせず、最後まで完結させること。
                3. 出力は必ず以下のJSON形式で行うこと（他の説明文は一切不要）。
                
                {{
                  "title": "新聞の見出しのように、動詞を含み5W1Hが明確なタイトル",
                  "summary": "この記事の核心を3行でまとめた要約",
                  "report": "## 概要\\n(内容)... ## 攻撃手順\\n(1. 2. 3.)... ## 実行コマンド(OSCP形式)\\n(コード)... ## 検知・回避\\n(詳細)..."
                }}

                ソース内容: {item['content'][:6000]}
                """
                
                try:
                    # JSONモードを有効にしてリクエスト
                    response = groq.chat.completions.create(
                        model="llama-3.1-70b-versatile", # 精度向上のため上位モデルを使用
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.1, # 創造性を抑え、事実に忠実にする
                        response_format={"type": "json_object"}
                    )
                    res_json = json.loads(response.choices[0].message.content)
                    
                    # 必須項目の存在チェック
                    if not res_json.get("title") or not res_json.get("report"): continue

                    new_articles.append({
                        "date": target_date,
                        "category": cat_id,
                        "title": res_json["title"],
                        "summary": res_json["summary"],
                        "content": res_json["report"],
                        "url": item['url']
                    })
                    time.sleep(2)
                except Exception as e:
                    print(f"Error processing {cat_id}: {e}")
                    continue
        except Exception as e:
            print(f"Search Error: {e}")
    return new_articles

def update_db_and_ui(new_entries):
    db = []
    if os.path.exists(MASTER_DATA):
        try:
            with open(MASTER_DATA, "r", encoding="utf-8") as f: db = json.load(f)
        except: db = []
    
    # 重複排除
    existing_urls = {a['url'] for a in db}
    for entry in new_entries:
        if entry['url'] not in existing_urls: db.append(entry)
    
    # 常に最新20件程度に絞るか、全件保持（今回は全件保持）
    db = sorted(db, key=lambda x: x['date'], reverse=True)
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    # 安全なBase64化
    db_json = json.dumps(db, ensure_ascii=False)
    db_base64 = base64.b64encode(db_json.encode('utf-8')).decode('utf-8')

    html_template = r'''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>RED-TACTICAL INVENTORY</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --accent: #f85149; --text: #c9d1d9; --border: #30363d; --green: #7ee787; }
        body { margin:0; font-family: -apple-system, system-ui, sans-serif; background:var(--bg); color:var(--text); line-height: 1.6; }
        header { position:sticky; top:0; background:rgba(13,17,23,0.9); backdrop-filter:blur(10px); border-bottom:1px solid var(--border); padding:15px; z-index:100; }
        #search-box { width:100%; box-sizing:border-box; background:#000; border:1px solid var(--border); color:var(--green); padding:12px; border-radius:8px; font-size:16px; font-family:monospace; }
        main { padding:12px; max-width: 800px; margin: 0 auto; padding-bottom:80px; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; margin-bottom:15px; cursor:pointer; }
        .card-meta { font-size:0.75rem; color:var(--accent); font-weight:bold; margin-bottom:8px; display:flex; justify-content:space-between; }
        .card-title { font-weight:bold; font-size:1.15rem; line-height:1.4; color:#fff; margin-bottom:10px; border-left: 4px solid var(--accent); padding-left:12px; }
        .card-summary { font-size:0.85rem; color:#8b949e; }
        
        #detail-view { position:fixed; top:0; left:100%; width:100%; height:100%; background:var(--bg); transition: transform 0.3s ease; z-index:1000; overflow-y:auto; }
        #detail-view.open { transform: translateX(-100%); }
        .detail-header { position:sticky; top:0; background:var(--card); padding:10px; border-bottom:1px solid var(--border); display:flex; align-items:center; }
        .back-btn { font-size:1.8rem; background:none; border:none; color:var(--accent); cursor:pointer; padding:0 20px; }
        .detail-body { padding:20px; font-size: 1rem; max-width: 800px; margin: 0 auto; }
        .detail-body h1, .detail-body h2 { color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:5px; margin-top:30px; }
        .detail-body pre { background:#000; padding:15px; border-radius:10px; border:1px solid var(--border); overflow-x:auto; position:relative; margin: 20px 0; }
        .detail-body code { color:var(--green); font-family:monospace; }
        .copy-btn { position:absolute; top:8px; right:8px; background:#21262d; border:1px solid var(--border); color:#fff; border-radius:5px; font-size:0.6rem; padding:5px 10px; cursor:pointer; }
    </style>
</head>
<body>
    <header><input type="text" id="search-box" placeholder="grep assets..."></header>
    <main id="list"></main>
    <div id="detail-view">
        <div class="detail-header"><button class="back-btn" onclick="closeDetail()">←</button><div id="det-head" style="font-weight:bold; font-size:0.85rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"></div></div>
        <div class="detail-body" id="det-body"></div>
    </div>
    <script>
        function b64DecodeUnicode(str) {
            return decodeURIComponent(atob(str).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
        }
        try {
            const db = JSON.parse(b64DecodeUnicode("INSERT_BASE64_HERE"));
            function render() {
                const q = document.getElementById('search-box').value.toLowerCase();
                const list = document.getElementById('list');
                list.innerHTML = '';
                db.filter(a => (a.title + (a.summary || "") + (a.content || "")).toLowerCase().includes(q)).forEach(a => {
                    const el = document.createElement('div');
                    el.className = 'card';
                    el.innerHTML = `
                        <div class="card-meta"><span>${a.date}</span><span>${a.category}</span></div>
                        <div class="card-title">${a.title}</div>
                        <div class="card-summary">${a.summary}</div>`;
                    el.onclick = () => openDetail(a);
                    list.appendChild(el);
                });
            }
            function openDetail(a) {
                document.getElementById('det-head').innerText = a.title;
                document.getElementById('det-body').innerHTML = marked.parse(a.content || "") + `<hr style="border:0; border-top:1px solid var(--border); margin:40px 0;"><a href="${a.url}" target="_blank" style="color:var(--accent); font-size:0.8rem;">[Source]</a>`;
                document.querySelectorAll('pre').forEach(pre => {
                    const b = document.createElement('button');
                    b.className = 'copy-btn'; b.innerText = 'COPY';
                    b.onclick = (e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(pre.innerText.replace('COPY','')).then(() => {
                            b.innerText = 'DONE'; setTimeout(()=>b.innerText='COPY', 1000);
                        });
                    };
                    pre.appendChild(b);
                });
                document.getElementById('detail-view').classList.add('open');
                history.pushState({view:'detail'}, '');
            }
            function closeDetail() { document.getElementById('detail-view').classList.remove('open'); }
            window.onpopstate = closeDetail;
            document.getElementById('search-box').oninput = render;
            render();
        } catch(e) { console.error(e); }
    </script>
</body>
</html>
'''
    final_html = html_template.replace("INSERT_BASE64_HERE", db_base64)
    with open("index.html", "w", encoding="utf-8") as f: f.write(final_html)

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
