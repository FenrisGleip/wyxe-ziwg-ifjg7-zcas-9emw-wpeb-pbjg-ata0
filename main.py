import os
import json
import re
import time
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
    print("情報収集を開始します...")
    # 検索クエリをより確実にヒットするよう調整
    categories = {
        "MALWARE": "malware technical analysis persistence 2026",
        "INITIAL": "exploit POC initial access bypass vulnerability 2026",
        "POST_EXP": "Active Directory lateral movement attack tool 2026",
        "AI_SEC": "LLM prompt injection jailbreak exploit 2026"
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        print(f"Searching {cat_id}...")
        try:
            # 過去1日(day)の最新かつ高度な情報を取得
            search_res = tavily.search(query=q, search_depth="advanced", max_results=3, search_period="day")["results"]
            
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                print(f"Analyzing: {item['url'][:50]}...")
                prompt = f"""
                あなたはシニア・レッドチーム・アナリストです。以下の情報を分析し、実戦的な技術レポートを作成してください。

                【指示事項】
                1. タイトルは「～がどうなった」等の指示的な言い回しを避け、客観的な新聞の見出し（日本語）にすること。
                2. 攻撃手順は抽象化を排除し、攻撃者が行う具体的ステップを記述すること。
                3. 実行コマンドは、curl, impacket, msfvenom, powershell等の実際のツール名と具体的パラメータを含むこと。
                4. ソース内にGitHubのPoCやExploitコードのURLがある場合、必ず "poc_url" フィールドに抽出すること。
                5. 出力は必ず以下のJSON形式で行い、他の解説文は一切含めないこと。

                {{
                  "title": "具体的かつ自然な日本語ニュース見出し",
                  "summary": "技術的要点のみを絞った3行要約",
                  "poc_url": "抽出したPoCリンク（なければ空文字列）",
                  "report": "## 概要\\n... ## 具体的な再現手順\\n... ## 実行コマンド(OSCP準拠)\\n... ## 影響範囲・検知ルール"
                }}

                ソース: {item['content'][:8000]}
                """
                
                try:
                    response = groq.chat.completions.create(
                        model="llama-3.3-70b-versatile",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0,
                        response_format={"type": "json_object"}
                    )
                    res_json = json.loads(response.choices[0].message.content)
                    
                    if not res_json.get("title") or len(res_json.get("report", "")) < 200: continue

                    new_articles.append({
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "category": cat_id,
                        "title": res_json["title"],
                        "summary": res_json["summary"],
                        "poc_url": res_json.get("poc_url", ""),
                        "content": res_json["report"],
                        "url": item['url']
                    })
                except Exception as e:
                    print(f"Groq分析エラー: {e}")
                    continue
        except Exception as e:
            print(f"Tavily検索エラー: {e}")
            
    return new_articles

def update_db_and_ui(new_entries):
    db = []
    if os.path.exists(MASTER_DATA):
        try:
            with open(MASTER_DATA, "r", encoding="utf-8") as f: db = json.load(f)
        except: db = []
    
    existing_urls = {a['url'] for a in db}
    for entry in new_entries:
        if entry['url'] not in existing_urls: db.append(entry)
    
    db = sorted(db, key=lambda x: x['date'], reverse=True)[:100]
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    # データをJS変数として直接埋め込む（Base64のトラブルを回避）
    db_json_str = json.dumps(db, ensure_ascii=False)

    html_template = r'''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RED-TACTICAL INVENTORY</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root { 
            --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
            --MALWARE: #f85149; --INITIAL: #f0883e; --POST_EXP: #a371f7; --AI_SEC: #58a6ff; --green: #7ee787;
        }
        body { margin:0; display:flex; font-family:-apple-system, sans-serif; background:var(--bg); color:var(--text); height: 100vh; overflow: hidden; }
        
        /* Sidebar */
        nav { width: 280px; background: #010409; border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; }
        .sidebar-header { padding: 20px; border-bottom: 1px solid var(--border); }
        .sidebar-header h1 { font-size: 1.1rem; color: #fff; margin: 0 0 15px 0; letter-spacing: 1px; }
        #search-box { width:100%; padding:10px; background:#000; border:1px solid var(--border); color:var(--green); border-radius:6px; outline:none; box-sizing:border-box; }
        .date-links { flex: 1; overflow-y: auto; padding: 10px; }
        .date-item { padding: 10px 15px; cursor: pointer; border-radius: 6px; font-size: 0.9rem; color: #8b949e; margin-bottom: 5px; }
        .date-item:hover { background: var(--card); color: #fff; }
        .date-item.active { background: #21262d; color: var(--green); border-left: 3px solid var(--green); }

        /* Main Feed */
        main { flex: 1; overflow-y: auto; padding: 20px; position: relative; }
        .feed-container { max-width: 800px; margin: 0 auto; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; margin-bottom:15px; cursor:pointer; transition: 0.2s; }
        .card:hover { border-color: #8b949e; transform: translateY(-2px); }
        .cat-tag { font-size: 0.7rem; font-weight: bold; padding: 3px 10px; border-radius: 4px; margin-right: 10px; color: #fff; text-transform: uppercase; }
        .card-title { font-weight:bold; font-size:1.25rem; line-height:1.4; color:#fff; margin: 12px 0; }
        .card-summary { font-size: 0.9rem; color: #8b949e; line-height: 1.6; }

        /* Detail Layer */
        #detail-view { position:fixed; top:0; right:-100%; width:100%; height:100%; background:var(--bg); transition: right 0.35s cubic-bezier(0,0,0.2,1); z-index:1000; overflow-y:auto; }
        #detail-view.open { right: 0; }
        .detail-header { position:sticky; top:0; background:rgba(22,27,34,0.95); backdrop-filter:blur(10px); padding:15px; border-bottom:1px solid var(--border); display:flex; align-items:center; z-index:10; }
        .back-btn { background:none; border:none; color:var(--green); font-size:1.2rem; cursor:pointer; padding: 10px 20px; font-weight: bold; }
        .detail-content { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
        .poc-btn { display: inline-block; background: #238636; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; margin: 20px 0; font-size: 0.9rem; }
        .poc-btn:hover { background: #2ea043; }
        
        /* Markdown Style */
        .detail-content h2 { border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 40px; color: var(--accent); }
        .detail-content pre { background:#000; padding:20px; border-radius:8px; overflow-x:auto; border: 1px solid var(--border); position: relative; margin: 20px 0; }
        .detail-content code { color:var(--green); font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.9rem; }
        .copy-btn { position:absolute; top:10px; right:10px; background:#21262d; border:1px solid var(--border); color:#fff; font-size:0.7rem; padding:4px 8px; border-radius:4px; cursor:pointer; }

        .no-data { text-align: center; padding: 50px; color: #8b949e; }

        @media (max-width: 768px) {
            nav { width: 100%; height: auto; position: fixed; bottom: 0; border-right: none; border-top: 1px solid var(--border); z-index: 50; }
            .date-links { display: flex; overflow-x: auto; flex-direction: row; }
            .date-item { white-space: nowrap; margin-bottom: 0; margin-right: 10px; }
            main { padding-bottom: 100px; }
        }
    </style>
</head>
<body>
    <nav>
        <div class="sidebar-header">
            <h1>RT-INVENTORY</h1>
            <input type="text" id="search-box" placeholder="キーワード検索...">
        </div>
        <div class="date-links" id="date-list">
            <div class="date-item active" data-date="all">すべて</div>
        </div>
    </nav>
    <main>
        <div class="feed-container" id="feed"></div>
    </main>

    <div id="detail-view">
        <div class="detail-header">
            <button class="back-btn" onclick="closeDetail()">← 戻る</button>
            <div id="det-cat"></div>
        </div>
        <div class="detail-content" id="det-body"></div>
    </div>

    <script>
        // Pythonから直接データを注入
        const db = INSERT_DATA_HERE;
        let currentDate = 'all';

        function init() {
            const dates = [...new Set(db.map(a => a.date))];
            const list = document.getElementById('date-list');
            dates.forEach(d => {
                const el = document.createElement('div');
                el.className = 'date-item';
                el.innerText = d;
                el.onclick = () => {
                    currentDate = d;
                    document.querySelectorAll('.date-item').forEach(i => i.classList.remove('active'));
                    el.classList.add('active');
                    render();
                };
                list.appendChild(el);
            });
            render();
        }

        function render() {
            const q = document.getElementById('search-box').value.toLowerCase();
            const feed = document.getElementById('feed');
            feed.innerHTML = '';
            
            const filtered = db.filter(a => {
                const matchDate = currentDate === 'all' || a.date === currentDate;
                const matchSearch = (a.title + a.summary + a.content).toLowerCase().includes(q);
                return matchDate && matchSearch;
            });

            if (filtered.length === 0) {
                feed.innerHTML = '<div class="no-data">表示できるインテリジェンスがありません。</div>';
                return;
            }

            filtered.forEach(a => {
                const el = document.createElement('div');
                el.className = 'card';
                el.innerHTML = `
                    <div style="display:flex; align-items:center;">
                        <span class="cat-tag" style="background:var(--${a.category})">${a.category}</span>
                        <span style="font-size:0.8rem; color:#8b949e;">${a.date}</span>
                    </div>
                    <div class="card-title">${a.title}</div>
                    <div class="card-summary">${a.summary}</div>
                `;
                el.onclick = () => openDetail(a);
                feed.appendChild(el);
            });
        }

        function openDetail(a) {
            const body = document.getElementById('det-body');
            let html = `<h1>${a.title}</h1>`;
            if (a.poc_url) {
                html += `<a href="${a.poc_url}" target="_blank" class="poc-btn">🚀 PoCコード・リポジトリを閲覧</a>`;
            }
            html += marked.parse(a.content);
            html += `<hr style="border:0; border-top:1px solid var(--border); margin:40px 0;"><a href="${a.url}" target="_blank" style="color:var(--green); font-size:0.8rem;">[ ソース元記事を確認 ]</a>`;
            
            body.innerHTML = html;
            document.getElementById('det-cat').innerHTML = `<span class="cat-tag" style="background:var(--${a.category})">${a.category}</span>`;
            
            document.querySelectorAll('pre').forEach(pre => {
                const b = document.createElement('button');
                b.className = 'copy-btn'; b.innerText = 'COPY';
                b.onclick = () => {
                    navigator.clipboard.writeText(pre.innerText.replace('COPY','')).then(() => {
                        b.innerText = 'DONE'; setTimeout(()=>b.innerText='COPY', 1500);
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
        
        init();
    </script>
</body>
</html>
'''
    # 直接文字列置換でデータを流し込む
    final_html = html_template.replace("INSERT_DATA_HERE", db_json_str)
    with open("index.html", "w", encoding="utf-8") as f: f.write(final_html)
    print("更新が完了しました。 index.html を確認してください。")

if __name__ == "__main__":
    new_data = fetch_and_analyze()
    update_db_and_ui(new_data)
