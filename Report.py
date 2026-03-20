# --- 第一層：基礎標準庫 (永遠不會報編碼錯) ---
import sys
import os

# 強制設定系統環境變數為 UTF-8
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["LANG"] = "C.UTF-8"
os.environ["LC_ALL"] = "C.UTF-8"

import io

# --- 第二層：環境編碼補強 (優先執行！) ---
# 這段話會直接告訴 Python，不管系統預設是什麼，通通給我用 utf-8 輸出
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# --- 第三層：第三方大型套件 (放在補強之後) ---
import pandas as pd
import html
import time
import json
import re
from google import genai
from google.genai import types

import requests
from bs4 import BeautifulSoup

# --- [1. 設定區] ---
GOOGLE_API_KEY = "您的_API_KEY"
client = genai.Client(api_key=GOOGLE_API_KEY)
MODEL_ID = "gemini-2.5-flash"

CACHE_FILE = "translation_cache.json"
SAFE_INTERVAL = 12 # 批次處理時，每組請求之間的冷卻時間

# --- [2. 工具函式] ---

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            # 加上 errors='ignore' 或 'replace' 預防檔案內有毀損字元
            with open(CACHE_FILE, "r", encoding="utf-8", errors='replace') as f:
                return json.load(f, strict=False)
        except Exception as e:
            print(f"⚠️ 快取讀取失敗: {e}")
            return {}
    return {}

def save_cache(cache_data):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache_data, f, ensure_ascii=False, indent=4)

def format_html_text(text):
    if pd.isna(text) or str(text).lower() == 'nan' or str(text).strip() == '':
        return "N/A"
    # 同時處理實際換行與字串 \n
    return str(text).replace('\\n', '<br/>').replace('\n', '<br/>')

# 載入現有快取
translation_cache = load_cache()

def get_official_info(pid):
    """嘗試從 Tenable 官網抓取繁體中文資料"""
    url = f"https://zh-tw.tenable.com/plugins/nessus/{pid}"
    try:
        # 加上 User-Agent 模擬瀏覽器，避免被阻擋
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # 抓取網頁內容 (Tenable 官網結構)
            # 這裡我們先抓取整頁文字，交給 AI 萃取關鍵欄位
            return soup.get_text()
    except:
        pass
    return None

def batch_translate_weaknesses(items_to_translate):
    if not items_to_translate:
        return {}

    final_batch = {}
    
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL_ID}:generateContent?key={GOOGLE_API_KEY}"

    for item in items_to_translate:
        pid = str(item['pid'])
        print(f"--> [HTTP Mode] Processing ID: {pid} ...")
        
        # 組合 Prompt，並確保 100% 只有 ASCII
        prompt_text = (
            f"Act as a cybersecurity expert. Translate Nessus ID {pid} into Traditional Chinese (Taiwan). "
            f"Return ONLY JSON with keys: desc, sol, see_also.\n"
            f"Desc: {item.get('desc', '')[:500]}\nSol: {item.get('sol', '')[:500]}"
        ).encode("ascii", "ignore").decode("ascii")

        payload = {
            "contents": [{"parts": [{"text": prompt_text}]}],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.1
            }
        }

        try:
            # 增加冷卻時間
            time.sleep(12)
            
            # 使用 requests 發送，這會完全繞過 SDK 的環境檢查
            response = requests.post(
                api_url, 
                json=payload, 
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            # 檢查 HTTP 狀態碼
            if response.status_code != 200:
                print(f"   API Error {response.status_code}: {response.text}")
                continue

            result_json = response.json()
            answer_text = result_json['candidates'][0]['content']['parts'][0]['text']
            
            # 解析並存入結果
            res = json.loads(answer_text)
            final_batch[pid] = {
                "desc": res.get("desc") or "",
                "sol": res.get("sol") or "",
                "see_also": item.get('see_also', '')
            }
            print(f"   ✅ ID {pid} Finished.")

        except Exception as e:
            print(f"   ❌ ID {pid} Error: {str(e)}")
            
    return final_batch

def wrap_html(body):
    return f"<html><head><meta charset='utf-8'></head><body style='font-family:微軟正黑體, 標楷體, sans-serif; padding: 20px;'>{body}</body></html>"

# --- [3. 主程式] ---

def main():
    if len(sys.argv) < 2:
        print("Usage: python Report.py [Nessus.csv]")
        return

    input_file = sys.argv[1]
    base_name = os.path.splitext(input_file)[0]
    df = pd.read_csv(input_file)

    risk_map = {'Critical': '極高風險', 'High': '高風險', 'Medium': '中風險', 'Low': '低風險'}
    risk_order = {'極高風險': 0, '高風險': 1, '中風險': 2, '低風險': 3}
    color_map = {'極高風險': '#702082', '高風險': '#DD4B50', '中風險': '#F18C43', '低風險': '#107C10'}

    df_filtered = df[df['Risk'].isin(risk_map.keys())].copy()
    df_filtered['Risk_TW'] = df_filtered['Risk'].map(risk_map)
    df_filtered['Port_Disp'] = df_filtered['Protocol'].str.upper() + " " + df_filtered['Port'].astype(str)

    # --- 第一步：批次檢查並翻譯 ---
    summary_df = df_filtered.drop_duplicates(subset=['Plugin ID'])
    missing_items = []
    for _, row in summary_df.iterrows():
        pid = str(row['Plugin ID'])
        if pid not in translation_cache:
            missing_items.append({
                'pid': pid, 'name': row['Name'], 
                'desc': row['Description'], 'sol': row['Solution'], 
                'see_also': row['See Also']
            })

    if missing_items:
        print(f"-> 偵測到 {len(missing_items)} 項新弱點，開始批次翻譯...")
        chunk_size = 5 # 每次處理 5 個
        for i in range(0, len(missing_items), chunk_size):
            chunk = missing_items[i:i + chunk_size]
            new_translations = batch_translate_weaknesses(chunk)
            
            translation_cache.update(new_translations)
            save_cache(translation_cache)
            print(f"   進度：{min(i + chunk_size, len(missing_items))}/{len(missing_items)}")

    # --- 第二步：產製風險摘要.html ---
    print("-> 1/3 產製：風險摘要.html...")
    ip_map = df_filtered.groupby('Plugin ID')['Host'].apply(lambda x: '、'.join(sorted(set(x))))
    summary_df = summary_df.copy()
    summary_df['order'] = summary_df['Risk_TW'].map(risk_order)
    summary_df = summary_df.sort_values(['order', 'Plugin ID'])
    
    summary_html = ""
    for i, (_, row) in enumerate(summary_df.iterrows()):
        pid = str(row['Plugin ID'])
        ai = translation_cache.get(pid, {"desc": row['Description'], "sol": row['Solution'], "see_also": row['See Also']})
        color = color_map.get(row['Risk_TW'], '#DD4B50')
        idx = f"（{i+1}）" if i >= 10 else ["（一）","（二）","（三）","（四）","（五）","（六）","（七）","（八）","（九）","（十）"][i]
        
        summary_html += f"""
        <table border="1" style="border-collapse:collapse; width:100%; max-width:1080px; margin-bottom:30px; font-size:12pt;">
            <tr bgcolor="{color}" style="color:white; font-weight:bold;">
                <td colspan="2" style="padding:10px; font-size:14pt;">{idx} {row['Risk_TW']} - {html.escape(row['Name'])}</td>
            </tr>
            <tr>
                <td width="120" bgcolor="#f9f9f9" style="padding:8px; font-weight:bold;">風險代號</td>
                <td style="padding:8px;">{pid}</td>
            </tr>
            <tr>
                <td bgcolor="#f9f9f9" style="padding:8px; font-weight:bold;">目標 IP</td>
                <td style="padding:8px;">{ip_map[row['Plugin ID']]}</td>
            </tr>
            <tr>
                <td bgcolor="#f9f9f9" style="padding:8px; font-weight:bold;">弱點摘要</td>
                <td style="padding:8px; text-align:justify; word-break:break-all;">{format_html_text(ai['desc'])}</td>
            </tr>
            <tr>
                <td bgcolor="#f9f9f9" style="padding:8px; font-weight:bold;">修補建議</td>
                <td style="padding:8px; text-align:justify; word-break:break-all;">{format_html_text(ai['sol'])}</td>
            </tr>
            <tr>
                <td bgcolor="#f9f9f9" style="padding:8px; font-weight:bold;">參考資料</td>
                <td style="padding:8px; word-break:break-all;">{format_html_text(ai['see_also'])}</td>
            </tr>
        </table>
        """
    with open(f'{base_name}_風險摘要.html', 'w', encoding='utf-8') as f:
        f.write(wrap_html(summary_html))

    # --- 第三、四步：產製統計表 (邏輯維持原樣) ---
    print("-> 2/3 產製：弱點統計表.html...")
    v_res = df_filtered.groupby(['Risk_TW', 'Plugin ID'])['Port_Disp'].apply(lambda x: '、'.join(sorted(set(x)))).reset_index()
    v_res['order'] = v_res['Risk_TW'].map(risk_order)
    v_res = v_res.sort_values(['order', 'Plugin ID'])
    v_res['rowspan'] = v_res.groupby('Risk_TW')['Risk_TW'].transform('count')
    v_res['is_first'] = ~v_res.duplicated(subset=['Risk_TW'])

    v_table = "<h2>弱點統計表</h2><table border='1' style='border-collapse:collapse; width:100%; text-align:center;'>"
    v_table += "<tr bgcolor='#eeeeee'><th>風險等級</th><th>風險代號</th><th>連接埠 (Port)</th></tr>"
    for _, r in v_res.iterrows():
        v_table += "<tr>"
        if r['is_first']: v_table += f"<td rowspan='{int(r['rowspan'])}' bgcolor='#f2f2f2'><b>{r['Risk_TW']}</b></td>"
        v_table += f"<td>{r['Plugin ID']}</td><td>{r['Port_Disp']}</td></tr>"
    v_table += "</table>"
    with open(f'{base_name}_弱點統計表.html', 'w', encoding='utf-8') as f:
        f.write(wrap_html(v_table))

    print("-> 3/3 產製：IP統計表.html...")
    i_pivot = df_filtered.pivot_table(index=['Risk_TW', 'Plugin ID'], columns='Host', values='Port_Disp', aggfunc=lambda x: '<br/>'.join(sorted(set(x)))).fillna('')
    i_pivot = i_pivot.reset_index()
    i_pivot['order'] = i_pivot['Risk_TW'].map(risk_order)
    i_pivot = i_pivot.sort_values(['order', 'Plugin ID'])
    hosts = [c for c in i_pivot.columns if c not in ['Risk_TW', 'Plugin ID', 'order']]
    i_pivot['rowspan'] = i_pivot.groupby('Risk_TW')['Risk_TW'].transform('count')
    i_pivot['is_first'] = ~i_pivot.duplicated(subset=['Risk_TW'])

    i_table = "<h2>IP 統計表</h2><table border='1' style='border-collapse:collapse; font-size:10pt; width:100%; text-align:center;'>"
    i_table += "<tr bgcolor='#eeeeee'><th>風險等級</th><th>風險代號</th>" + "".join([f"<th>{h}</th>" for h in hosts]) + "</tr>"
    for _, r in i_pivot.iterrows():
        i_table += "<tr>"
        if r['is_first']: i_table += f"<td rowspan='{int(r['rowspan'])}' bgcolor='#f2f2f2'><b>{r['Risk_TW']}</b></td>"
        i_table += f"<td>{r['Plugin ID']}</td>"
        for h in hosts: i_table += f"<td>{r[h]}</td>"
        i_table += "</tr>"
    i_table += "</table>"
    with open(f'{base_name}_IP統計表.html', 'w', encoding='utf-8') as f:
        f.write(wrap_html(i_table))

    print(f"\n✅ 全部完成！產出檔案：風險摘要、弱點統計、IP統計。")

if __name__ == "__main__":
    main()
