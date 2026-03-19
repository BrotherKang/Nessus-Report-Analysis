import pandas as pd
import html
import sys
import os

def main():
    # --- 0. 處理命令列參數 ---
    if len(sys.argv) < 2:
        print("使用說明: python Report.py [Nessus報告路徑.csv]")
        print("範例: python Report.py MyScan.csv")
        return

    input_file = sys.argv[1]
    
    if not os.path.exists(input_file):
        print(f"錯誤：找不到檔案 '{input_file}'")
        return

    # --- 1. 資料讀取與預處理 ---
    try:
        df = pd.read_csv(input_file)
    except Exception as e:
        print(f"讀取 CSV 失敗: {e}")
        return

    risk_map = {'Critical': '極高風險', 'High': '高風險', 'Medium': '中風險', 'Low': '低風險'}
    risk_order = {'極高風險': 0, '高風險': 1, '中風險': 2, '低風險': 3}
    # 顏色定義：高風險(紅)、中風險(橘)
    color_map = {'高風險': '#DD4B50', '中風險': '#F18C43', '極高風險': '#702082', '低風險': '#107C10'}

    df_filtered = df[df['Risk'].isin(risk_map.keys())].copy()
    df_filtered['Risk_TW'] = df_filtered['Risk'].map(risk_map)
    df_filtered['Port_Display'] = df_filtered['Protocol'].str.upper() + " " + df_filtered['Port'].astype(str)

    # --- 2. 產製「弱點統計表」 ---
    def generate_vuln_stat(df):
        summary = df.groupby(['Risk_TW', 'Plugin ID'])['Port_Display'].apply(
            lambda x: '、'.join(sorted(set(x)))
        ).reset_index()
        summary['order'] = summary['Risk_TW'].map(risk_order)
        summary = summary.sort_values(['order', 'Plugin ID'])
        summary['rowspan'] = summary.groupby('Risk_TW')['Risk_TW'].transform('count')
        summary['is_first'] = ~summary.duplicated(subset=['Risk_TW'])
        
        rows_html = ""
        for _, row in summary.iterrows():
            rows_html += "<tr>"
            if row['is_first']:
                rows_html += f'<td rowspan="{int(row["rowspan"])}">{row["Risk_TW"]}</td>'
            rows_html += f"<td>{row['Plugin ID']}</td><td>{row['Port_Display']}</td></tr>"
        
        header = '<tr><td style="background-color:#eeeeee">風險等級</td><td style="background-color:#eeeeee">風險代號</td><td style="background-color:#eeeeee">Plugin Output</td></tr>'
        return wrap_table(header + rows_html)

    # --- 3. 產製「IP 統計表」 ---
    def generate_ip_stat(df):
        pivot = df.pivot_table(
            index=['Risk_TW', 'Plugin ID'], 
            columns='Host', 
            values='Port_Display', 
            aggfunc=lambda x: '<br/>'.join(sorted(set(x)))
        ).fillna('')
        pivot = pivot.reset_index()
        pivot['order'] = pivot['Risk_TW'].map(risk_order)
        pivot = pivot.sort_values(['order', 'Plugin ID']).drop(columns=['order'])
        
        hosts = [col for col in pivot.columns if col not in ['Risk_TW', 'Plugin ID']]
        header = f'<tr><td style="background-color:#eeeeee">風險等級</td><td style="background-color:#eeeeee">風險代號</td>' + ''.join([f'<td style="background-color:#eeeeee">{h}</td>' for h in hosts]) + '</tr>'
        
        pivot['rowspan'] = pivot.groupby('Risk_TW')['Risk_TW'].transform('count')
        pivot['is_first'] = ~pivot.duplicated(subset=['Risk_TW'])
        
        rows_html = ""
        for _, row in pivot.iterrows():
            rows_html += "<tr>"
            if row['is_first']:
                rows_html += f'<td rowspan="{int(row["rowspan"])}">{row["Risk_TW"]}</td>'
            rows_html += f"<td>{row['Plugin ID']}</td>"
            for h in hosts:
                rows_html += f"<td>{row[h]}</td>"
            rows_html += "</tr>"
        return wrap_table(header + rows_html)

    # --- 4. 產製「風險摘要」 (含顏色區分、目標 IP、範例格式) ---
    def generate_risk_summary(df):
        ip_list_series = df.groupby('Plugin ID')['Host'].apply(lambda x: '、'.join(sorted(set(x))))
        summary_df = df.drop_duplicates(subset=['Plugin ID']).copy()
        summary_df['order'] = summary_df['Risk_TW'].map(risk_order)
        summary_df = summary_df.sort_values(['order', 'Plugin ID'])
        
        content = ""
        # 標題序號
        idx_chars = ["（一）", "（二）", "（三）", "（四）", "（五）", "（六）", "（七）", "（八）", "（九）", "（十）"]
        
        for i, (_, row) in enumerate(summary_df.iterrows()):
            idx_str = idx_chars[i] if i < len(idx_chars) else f"（{i+1}）"
            bg_color = color_map.get(row['Risk_TW'], '#DD4B50')
            affected_ips = ip_list_series[row['Plugin ID']]
            
            # 清理 HTML 語法並轉換換行
            desc = html.escape(str(row['Description'])).replace('\n', '<br/>')
            sol = html.escape(str(row['Solution'])).replace('\n', '<br/>')
            see_also = html.escape(str(row['See Also'])).replace('\n', '<br/>')
            
            content += f"""
            <p style='margin-left:69.25pt;text-indent:-42.75pt;margin-bottom:5pt;'>
                <span style="font-size:14pt;font-family:標楷體">{idx_str}</span>
                <span style="font-size:14pt;font-family:Calibri">{html.escape(row['Name'])}</span>
            </p>
            <table border="1" style="margin-left:9.35pt;border-collapse:collapse;font-size:12pt;font-family:標楷體;width:635pt;border:solid windowtext 1.0pt;">
                <tr><td bgcolor="{bg_color}" colspan="2" style="color:white;padding:5pt;border:solid windowtext 1.0pt;">{row['Risk_TW']}</td></tr>
                <tr><td bgcolor="{bg_color}" style="color:white;width:100pt;padding:5pt;border:solid windowtext 1.0pt;">風險代號：</td><td style="padding:5pt;border:solid windowtext 1.0pt;">{row['Plugin ID']}</td></tr>
                <tr><td style="padding:5pt;border:solid windowtext 1.0pt;">目標 IP：</td><td style="padding:5pt;border:solid windowtext 1.0pt;">{affected_ips}</td></tr>
                <tr><td style="padding:5pt;border:solid windowtext 1.0pt;">風險說明：</td><td style="padding:5pt;border:solid windowtext 1.0pt;text-align:justify;">{desc}</td></tr>
                <tr><td style="padding:5pt;border:solid windowtext 1.0pt;">解決方案：</td><td style="padding:5pt;border:solid windowtext 1.0pt;text-align:justify;">{sol}</td></tr>
                <tr><td style="padding:5pt;border:solid windowtext 1.0pt;">參考資料：</td><td style="padding:5pt;border:solid windowtext 1.0pt;text-align:justify;">{see_also}</td></tr>
            </table><br/>
            """
        return f"<html><head><meta charset='utf-8'></head><body style='font-family:標楷體;'>{content}</body></html>"

    def wrap_table(inner_html):
        return f"""<html><head><meta charset='utf-8'></head><body>
        <table border="1" style="border-collapse:collapse;text-align:left;font-size:12pt;font-family:Calibri, 標楷體;">
        {inner_html}
        </table></body></html>"""

    # --- 5. 執行產出 ---
    base_name = os.path.splitext(input_file)[0]
    
    with open(f'{base_name}_IP統計表.html', 'w', encoding='utf-8') as f: f.write(generate_ip_stat(df_filtered))
    with open(f'{base_name}_弱點統計表.html', 'w', encoding='utf-8') as f: f.write(generate_vuln_stat(df_filtered))
    with open(f'{base_name}_風險摘要.html', 'w', encoding='utf-8') as f: f.write(generate_risk_summary(df_filtered))

    print(f"解析完成！已針對 '{input_file}' 產製三份 HTML 報表。")

if __name__ == "__main__":
    main()
