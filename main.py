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
    target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    categories = {
        "MALWARE": f'"{target_date}" malware technical analysis (persistence OR evasion) 2026',
        "INITIAL": f'"{target_date}" (initial access OR "ClickFix") POC delivery 2026',
        "POST_EXP": f'"{target_date}" (Credential Access OR "Lateral Movement") attack PoC 2026',
        "AI_SEC": f'"{target_date}" (Prompt Injection OR "Model Inversion") attack vector 2026'
    }
    
    new_articles = []
    for cat_id, q in categories.items():
        try:
            search_res = tavily.search(query=q, search_depth="advanced", max_results=3)["results"]
            for item in search_res:
                if any(x['url'] == item['url'] for x in new_articles): continue
                
                prompt = f"""
                あなたはレッドチーム・リサーチャーです。情報を「武器化」してください。
                1. **Weapon_ID**: [CVE/Name] Target -> Method
                2. **Tactical_Flow**: 攻撃ステップのASCII ART
                3. **Target_Requirements**: 環境（OS、権限等）
                4. **Exploit_Payload**: `export TARGET=...` から始まる実戦コマンド
                5. **Detection_Evasion**: 回避ロジック
                6. **Detection_Rule**: 検知クエリ

                URL: {item['url']}
                Content: {item['content'][:8000]}
                """
                
                try:
                    response = groq.chat.completions.create(
                        model="llama-3.1-8b-instant",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0
                    )
                    res_text = response.choices[0].message.content
                    if "SKIP" in res_text[:10]: continue

                    attack_id = re.search(r'T\d{4}(?:\.\d{3})?', res_text)
                    title_match = re.search(r'Weapon_ID\*\*: (.*)', res_text)
                    
                    new_articles.append({
                        "date": target_date,
                        "category": cat_id,
                        "title": title_match.group(1).strip() if title_match else "RAW_INTEL",
                        "attack_id": attack_id.group(0) if attack_id else "N/A",
                        "content": res_text,
                        "url": item['url']
                    })
                    time.sleep(1)
                except Exception as e:
                    print(f"Groq API Error: {e}")
                    continue
        except Exception as e:
            print(f"Search Error: {e}")
    return new_articles

def update_db_and_ui(new_entries):
    db = []
    if os.path.exists(MASTER_DATA):
        try:
            with open(MASTER_DATA, "r", encoding="utf-8") as f:
                db = json.load(f)
        except: db = []
    
    existing_urls = {a['url'] for a in db}
    for entry in new_entries:
        if entry['url'] not in existing_urls:
            db.append(entry)
    
    with open(MASTER_DATA, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    
    json_payload = json.dumps(db)

    # HTML生成 (波括弧を二重にしてエスケープ)
    html_content = f"""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>RT-TACTICAL | DATABASE</title>
        <style>
            :root {{ --bg: #05070a; --card: #0d1117; --accent: #f85149; --text: #c9d1d9; --border: #30363d; --green: #7ee787; }}
            body {{ margin:0; font-family:'Consolas', monospace; background:var(--bg); color:var(--text); overflow-x:hidden; }}
            header {{ position:sticky; top:0; background:var(--bg); border-bottom:1px solid var(--border); padding:15px; z-index:100; }}
            #search-box {{ width:100%; box-sizing:border-box; background:#000; border:1px solid var(--border); color:var(--green); padding:12px; border-radius:8px; font-size:16px; }}
            main {{ padding:15px; padding-bottom:80px; }}
            .article-card {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; margin-bottom:15px; cursor:pointer; }}
            .meta {{ font-size:0.7rem; color:#8b949e; margin-bottom:8px; display:flex; justify-content:space-between; }}
            .attack-id {{ color:var(--accent); font-weight:bold; }}
            #detail-view {{ position:fixed; top:0; right:-100%; width:100%; height:100%; background:var(--bg); transition: 0.3s; z-index:1000; overflow-y:auto; }}
            #detail-view.open {{ right: 0; }}
            .detail-header {{ position:sticky; top:0; background:var(--card); padding:15px; border-bottom:1px solid var(--border); display:flex; align-items:center; }}
            .back-btn {{ font-size:1.5rem; background:none; border:none; color:var(--accent); cursor:pointer; margin-right:15px; }}
            .detail-content {{ padding:20px; white-space: pre-wrap; }}
            h3 {{ font-size:0.9rem; color:var(--
