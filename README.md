## Nessus 報告分析統計小工具
這是將 nessus 產生的 CSV 報告檔案，分析統計並產製「弱點統計表」、「IP 統計表」及「風險摘要」，三個 HTML 檔案<br>
方便用來做報告撰寫或後續分析用

### 更新說明
20260320：這次是將內容給中文化，搭配 Gemini API KEY，使風險摘要更有可讀性。

### 使用方式
1. `pip install -r requirements.txt`
2. 修改 Report.py 中 GOOGLE_API_KEY 的值。
3. 執行`python Report.py YourReportFile.csv`

輸出的 HTML 檔名會根據輸入的 CSV 檔名自動命名。例如您輸入 Temp.csv，產出的檔案就會是 Temp_IP統計表.html 等，不會覆蓋到舊的檔案。
第一次執行會產生 translation_cache.json 檔案，這是用來存放風險說明的，當日後有重複的風險項目就會從這邊讀取，也能減少 token 的消耗。

### 改版方向
預計將加入下面兩個功能：
1. 除三個統計檔案外，能產生綜合評估的 word 檔案。
2. 因為 nessus 有時候會更新風險資訊，思考怎麼確保資訊會是最新的
