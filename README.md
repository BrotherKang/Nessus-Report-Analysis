## Nessus 報告分析統計小工具
這是將 nessus 產生的 CSV 報告檔案，分析統計並產製「弱點統計表」、「IP 統計表」及「風險摘要」，三個 HTML 檔案<br>
方便用來做報告撰寫或後續分析用

### 更新說明
20260320：這次是將內容給中文化，搭配 Gemini API KEY，使風險摘要更有可讀性。<BR>
20260427：整個利用 nessus 官方 API 來達到中文化。

### 安裝
直接執行 `pip install -r requirements.txt`

# Report.py 完整使用說明

> Nessus 弱點報告產生器 — 讀取 Nessus CSV 匯出檔，產生繁體中文 HTML 報告，並以本地快取保存 Tenable 官方翻譯。

---

## 一、兩種執行模式

`Report.py` 依是否提供 CSV 檔，分成兩種模式：

- **報告模式**：提供 CSV → 產生 3 份 HTML 報告 + 順帶維護快取
- **維護模式**：不提供 CSV → 只做快取維護（刷新 / 檢查 Tenable 更新）

---

## 二、所有參數

| 參數 | 類型 | 說明 |
|---|---|---|
| `csv` | 位置參數 (可省) | Nessus 匯出的 CSV 檔路徑;省略即進入維護模式 |
| `--cache-dir DIR` | 選項 | 指定 `translation_cache.json` 與 `keyword_refs.json` 所在目錄(預設:目前工作目錄 cwd) |
| `--lang {zh-tw,zh-cn,ja,en}` | 選項 | 從 Tenable 抓取的語系,預設 `zh-tw`(繁中缺時自動用 zh_CN + zhconv 轉繁) |
| `--refresh [PID ...]` | 選項 | 強制重抓:不帶參數=快取內全部;帶 PID=只抓指定 ID(允許加入新 ID) |
| `--refresh-older DAYS` | 選項 | 只重抓快取時間超過 N 天的 ID |
| `--check-updates` | 旗標 | 向 Tenable 查最後修改日期,只更新有變動的 ID |
| `-h`, `--help` | 旗標 | 顯示內建 help |

---

## 三、常用指令組合

### 1. 產報告(最基本)

```bash
python3 Report.py Nessus.csv
```

產出(放在 CSV 同資料夾):

- `Nessus_風險摘要.html`
- `Nessus_弱點統計表.html`
- `Nessus_統計表.html`

第一次跑會呼叫 Tenable API 建立 `translation_cache.json`;之後再跑就直接讀快取,速度很快。

### 2. 指定快取位置

```bash
python3 Report.py Nessus.csv --cache-dir ~/nessus-cache
```

適合 CSV 放在各處、快取集中管理的情境。

### 3. 切換語系

```bash
python3 Report.py Nessus.csv --lang ja          # 日文
python3 Report.py Nessus.csv --lang zh-cn       # 簡中
python3 Report.py Nessus.csv --lang en          # 英文
```

### 4. 強制重抓全部快取

```bash
python3 Report.py Nessus.csv --refresh
```

不理快取,一律重向 Tenable 抓。

### 5. 只重抓指定 Plugin ID

```bash
python3 Report.py Nessus.csv --refresh 51192 57608
```

PID 不必先在快取裡,會順便補進去。

### 6. 重抓「超過 N 天沒更新」的快取

```bash
python3 Report.py Nessus.csv --refresh-older 30
```

只重抓 `fetched_at` 超過 30 天的 ID。

### 7. 檢查 Tenable 是否有更新(不用 CSV)

```bash
python3 Report.py --check-updates
```

比對快取裡每個 PID 的 `plugin_modified` 與 Tenable 目前最新日期:

- 有變動才呼叫完整 API 更新
- 沒變動只更新 `fetched_at` 時間戳

這個指令適合排程每週跑一次,抓官方修訂。

### 8. 維護模式(不用 CSV)

```bash
# 只重抓快取內全部
python3 Report.py --refresh

# 只重抓指定 ID
python3 Report.py --refresh 15901 50686

# 只重抓超過 14 天沒更新的
python3 Report.py --refresh-older 14

# 檢查更新
python3 Report.py --check-updates
```

維護模式需要已存在的 `translation_cache.json`,若沒有會提示先跑一次報告模式建立。

---

## 四、典型工作流程建議

### 初次使用

```bash
# 1. 遮罩 IP(如需外傳)
python3 mask_ip.py mask Nessus.csv
#    → 產出 Nessus.masked.csv + ip_map.json

# 2. 產報告(第一次會花時間建快取)
python3 Report.py Nessus.masked.csv

# 3. 回傳報告前,把遮罩的 IP 還原
python3 mask_ip.py unmask Nessus.masked_風險摘要.html \
                           Nessus.masked_弱點統計表.html \
                           Nessus.masked_統計表.html
```

### 日常更新(已有快取)

```bash
# 週一早上跑一次,抓 Tenable 最新修訂
python3 Report.py --check-updates

# 需要針對某次掃描產報告時,直接跑即可(快取命中,秒出)
python3 Report.py /path/to/new-scan.csv --cache-dir ~/nessus-cache
```

### 排程更新(cron)

```cron
# 每週一 07:00 自動檢查更新
0 7 * * 1  cd ~/nessus-cache && /usr/bin/python3 /path/to/Report.py --check-updates >> ~/nessus-cache/update.log 2>&1
```

---

## 五、輸出檔案說明

| 檔名 | 內容 |
|---|---|
| `{name}_風險摘要.html` | 每個弱點的描述、解決方案、參考連結(繁中) |
| `{name}_弱點統計表.html` | 各 Plugin ID 的風險等級、受影響主機數量 |
| `{name}_統計表.html` | 每個主機 × 每個弱點的交叉表 |
| `translation_cache.json` | 翻譯快取(desc / sol / see_also / plugin_modified / fetched_at) |
| `keyword_refs.json` | 自訂關鍵字 → 額外參考連結的對照表 |

---

## 六、需要輔助工具時

- `mask_ip.py mask <csv>` — CSV 裡的 IP 遮罩成 `198.18.x.x`
- `mask_ip.py unmask <html ...>` — 用 `ip_map.json` 把 HTML 裡的假 IP 還原
- `probe_tenable.py [PID]` — 診斷 Tenable API 端點是否可達、結構是否變動

---

## 七、為什麼需要快取檔

`translation_cache.json` 不只是效能優化,還扮演三個關鍵角色:

### 1. 效能加速器

| 情境 | 有快取 | 沒快取 |
|---|---|---|
| 100 個 Plugin 的報告 | 幾秒 | 2–5 分鐘(每個 API 要 1–3 秒) |
| 同一 CSV 跑第二次 | 瞬間 | 又一輪 2–5 分鐘 |
| 10 份 CSV 批次處理 | 只抓沒見過的 PID | 每份都全抓 |

### 2. 離線備援

可能遇到的狀況:

- 客戶機房沒開外網(只有內網 + 跳板機)
- 公司 proxy 擋 tenable.com
- Tenable 那邊 CDN 暫時性出包
- 半夜臨時要出報告,但 Tenable 剛好在維護

只要把 `translation_cache.json` 帶著,腳本照常運作。

### 3. 客製化存放處

每個客戶要求不太一樣:

- A 客戶要用「漏洞」,B 客戶要用「弱點」
- 某個 Plugin 官方翻譯太隨便,改得專業一點
- 補公司內部的修補 SOP 連結(搭配 `keyword_refs.json`)
- 特定產業客戶要求統一用語(金融業 vs 製造業)

這些客製化成果住在快取裡,不會因 Tenable 改版而消失。

### 建議

把快取檔納入備份範圍,跟掃描報告一起備份。通常 `~/nessus-cache/translation_cache.json` 放進雲端同步或 git 都很輕量(幾百 KB 到幾 MB)。

---

## 八、常見問題

**Q:看到 `未取得中文資料` 怎麼辦?**

A:通常是 Tenable API 沒拿到繁中;裝 `zhconv` 可讓腳本把簡中自動轉繁:

```bash
pip3 install zhconv --break-system-packages
```

**Q:`--check-updates` 回報「無變動」但我知道有改?**

A:確認快取裡 `plugin_modified` 是 `YYYY-MM-DD` 格式(空字串會視為首次寫入)。

**Q:想改從其他語系版本抓?**

A:`--lang zh-cn` 或 `--lang ja`;英文直接用 `--lang en`(略過翻譯邏輯)。

**Q:可以離線使用嗎?**

A:可以。只要 `translation_cache.json` 裡已經有需要的 Plugin ID,就能在沒網路的環境產報告。

**Q:快取會自動過期嗎?**

A:不會自動過期。請主動用 `--check-updates`(只更新有變動的)或 `--refresh-older 30`(超過 30 天就更新)維護。

輸出的 HTML 檔名會根據輸入的 CSV 檔名自動命名。例如您輸入 Temp.csv，產出的檔案就會是 Temp_IP統計表.html 等，不會覆蓋到舊的檔案。
第一次執行會產生 translation_cache.json 檔案，這是用來存放風險說明的，當日後有重複的風險項目就會從這邊讀取，也能減少 token 的消耗。

### 改版方向
預計將加入下面兩個功能：
1. 除三個統計檔案外，能產生綜合評估的 word 檔案。
2. 因為 nessus 有時候會更新風險資訊，思考怎麼確保資訊會是最新的
