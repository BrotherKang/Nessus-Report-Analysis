## Nessus 報告分析統計小工具
這是將 nessus 產生的 CSV 報告檔案，分析統計並產製「弱點統計表」、「IP 統計表」及「風險摘要」，三個 HTML 檔案<br>
方便用來做報告撰寫或後續分析用

### 使用方式
1. 要先安裝 pandas
 ```shell
pip install pandas
```
2. 執行`python Report.py YourReportFile.csv`
輸出的 HTML 檔名會根據輸入的 CSV 檔名自動命名。例如您輸入 Temp.csv，產出的檔案就會是 Temp_IP統計表.html 等，不會覆蓋到舊的檔案。
