# -*- coding: utf-8 -*-
"""
Nessus 弱點報告產生器
---------------------
讀取 Nessus 匯出的 CSV，產出三個繁體中文 HTML：
  1. <檔名>_風險摘要.html     每個弱點一張說明表 (含中文描述/建議/參考資料)
  2. <檔名>_弱點統計表.html   所有弱點一覽 (風險等級/代號/Plugin Output)
  3. <檔名>_統計表.html       依 IP 橫向展開，含小計與合計

資料來源：
  - 繁體中文內容：Tenable 官方 (https://zh-tw.tenable.com/plugins/nessus/<PID>)
  - 參考資料 fallback：CVE→NVD 連結、關鍵字對照 (keyword_refs.json)

兩個外部檔 (會自動在 CSV 同目錄建立)：
  - translation_cache.json   Tenable 抓下來的中文內容快取
  - keyword_refs.json        當 Tenable 無「另請參閱」時使用的關鍵字對照表

用法：
  # 一、報告模式 (有 CSV) ─────────────────────────
  python Report.py Nessus.csv                          # 正常執行，有快取就用快取
  python Report.py Nessus.csv --refresh                # 強制重抓 CSV 中所有 ID
  python Report.py Nessus.csv --refresh 15901 45411    # 只重抓指定 ID
  python Report.py Nessus.csv --refresh-older 30       # 重抓 30 天以前抓的
  python Report.py Nessus.csv --check-updates          # 比對 Tenable 最後修改日期

  # 二、維護模式 (不需要 CSV，只操作快取) ────────
  python Report.py --check-updates                     # 檢查所有快取 ID 是否有更新
  python Report.py --refresh-older 30                  # 重抓快取中 30 天前的項目
  python Report.py --refresh 15901 45411               # 重抓指定 ID (不用管 CSV)
  python Report.py --refresh                           # 重抓所有快取項目
  python Report.py --cache-dir /path/to/reports ...    # 指定快取檔位置
"""

# --- 第一層：基礎標準庫 ---
import sys
import os

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ.setdefault("LANG", "C.UTF-8")
os.environ.setdefault("LC_ALL", "C.UTF-8")

import io
if getattr(sys.stdout, "encoding", "").lower() != "utf-8":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    except Exception:
        pass
if getattr(sys.stderr, "encoding", "").lower() != "utf-8":
    try:
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    except Exception:
        pass

# --- 第二層：第三方套件 ---
import argparse
import html
import json
import re
import time
from datetime import datetime, timedelta, timezone

import pandas as pd
import requests
from bs4 import BeautifulSoup

# --- [1. 設定區] ---
CACHE_FILENAME = "translation_cache.json"
KEYWORD_REFS_FILENAME = "keyword_refs.json"

FETCH_INTERVAL = 2
REQUEST_TIMEOUT = 15
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Tenable 多語系 host 對照 (僅 HTML 頁面墊底用；API 一律走 www.tenable.com)
LANG_HOSTS = {
    "zh-tw": "zh-tw.tenable.com",   # 繁體中文
    "zh-cn": "zh-cn.tenable.com",   # 簡體中文
    "ja":    "ja.tenable.com",       # 日文
    "en":    "www.tenable.com",      # 英文
}
# API 固定端點 (與語系無關)
TENABLE_API_HOST = "www.tenable.com"

# --lang 對應到 API 回傳的 i18n 欄位 key
# Tenable API 的 description_i18n / solution_i18n 依 Plugin 不同，可能有
# zh_TW / zh_CN / ja_JP 等語系；部分老舊 Plugin 只有 zh_CN，這時會退而用
# zhconv (若安裝) 做簡→繁轉換。
LANG_I18N_KEY = {
    "zh-tw": "zh_TW",    # 若 API 有提供就直接用；沒有則 fallback zh_CN (需轉繁)
    "zh-cn": "zh_CN",
    "ja":    "ja_JP",
    "en":    None,        # 用頂層英文欄位
}
DEFAULT_LANG = "zh-tw"

RISK_MAP = {
    "Critical": "嚴重風險",
    "High": "高風險",
    "Medium": "中風險",
    "Low": "低風險",
}
RISK_ORDER = {"嚴重風險": 0, "高風險": 1, "中風險": 2, "低風險": 3}
COLOR_MAP = {
    "嚴重風險": "#702082",
    "高風險": "#DD4B50",
    "中風險": "#F18C43",
    "低風險": "#107C10",
}

# 預設關鍵字對照表 (首次執行時會寫成 keyword_refs.json，之後請改 JSON 檔，不要改這裡)
DEFAULT_KEYWORD_REFS = [
    {"keywords": ["Certificate Expiry", "Certificate Expired", "Expired Certificate"],
     "urls": [
         "https://www.ssl.com/article/the-complete-guide-to-ssl-certificate-expiration/",
         "https://www.digicert.com/kb/ssl-support/why-ssl-expires.htm",
     ]},
    {"keywords": ["Wrong Hostname", "Hostname Mismatch", "Common Name Mismatch"],
     "urls": [
         "https://www.ssl.com/article/why-common-name-mismatches-happen-how-to-fix-them/",
         "https://datatracker.ietf.org/doc/html/rfc6125",
     ]},
    {"keywords": ["Self-Signed", "Self Signed"],
     "urls": [
         "https://en.wikipedia.org/wiki/Self-signed_certificate",
         "https://www.itu.int/rec/T-REC-X.509/en",
     ]},
    {"keywords": ["Cannot Be Trusted", "Untrusted Certificate"],
     "urls": [
         "https://en.wikipedia.org/wiki/X.509",
         "https://www.itu.int/rec/T-REC-X.509/en",
     ]},
    {"keywords": ["Weak Cipher", "Weak Encryption"],
     "urls": [
         "https://ssl-config.mozilla.org/",
         "https://wiki.mozilla.org/Security/Server_Side_TLS",
     ]},
    {"keywords": ["SWEET32", "Medium Strength Cipher", "3DES"],
     "urls": [
         "https://sweet32.info/",
         "https://www.openssl.org/blog/blog/2016/08/24/sweet32/",
     ]},
    {"keywords": ["POODLE"],
     "urls": [
         "https://www.openssl.org/~bodo/ssl-poodle.pdf",
         "https://en.wikipedia.org/wiki/POODLE",
     ]},
    {"keywords": ["BEAST"],
     "urls": ["https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack"]},
    {"keywords": ["TLS Version 1.0", "TLSv1.0"],
     "urls": [
         "https://datatracker.ietf.org/doc/html/rfc8996",
         "https://tools.ietf.org/html/draft-ietf-tls-oldversions-deprecate-00",
     ]},
    {"keywords": ["TLS Version 1.1", "TLSv1.1"],
     "urls": ["https://datatracker.ietf.org/doc/html/rfc8996"]},
    {"keywords": ["SSL Version 2", "SSLv2", "SSL Version 3", "SSLv3"],
     "urls": [
         "https://datatracker.ietf.org/doc/html/rfc7568",
         "https://datatracker.ietf.org/doc/html/rfc6176",
     ]},
    {"keywords": ["SMB Signing"],
     "urls": [
         "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing",
         "https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html",
     ]},
    {"keywords": ["SMBv1", "SMB Version 1"],
     "urls": ["https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"]},
    {"keywords": ["NetBIOS"],
     "urls": ["https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/what-is-windows-time-service"]},
    {"keywords": ["IP Forwarding"],
     "urls": [
         "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ip-forwarding",
         "https://access.redhat.com/solutions/6196",
         "https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt",
     ]},
    {"keywords": ["ICMP Timestamp"],
     "urls": [
         "https://datatracker.ietf.org/doc/html/rfc792",
         "https://cwe.mitre.org/data/definitions/200.html",
     ]},
    {"keywords": ["SNMP"],
     "urls": [
         "https://datatracker.ietf.org/doc/html/rfc3414",
         "https://learn.microsoft.com/en-us/windows/win32/snmp/snmp-start-page",
     ]},
    {"keywords": ["HTTP", "Apache", "IIS", "Nginx"],
     "urls": [
         "https://owasp.org/www-project-secure-headers/",
         "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
     ]},
    {"keywords": ["Cross-Site Scripting", "XSS"],
     "urls": [
         "https://owasp.org/www-community/attacks/xss/",
         "https://cwe.mitre.org/data/definitions/79.html",
     ]},
    {"keywords": ["SQL Injection"],
     "urls": [
         "https://owasp.org/www-community/attacks/SQL_Injection",
         "https://cwe.mitre.org/data/definitions/89.html",
     ]},
    {"keywords": ["Anonymous", "Null Session", "Guest Account"],
     "urls": ["https://cwe.mitre.org/data/definitions/287.html"]},
    {"keywords": ["Default Credential", "Default Password"],
     "urls": [
         "https://cwe.mitre.org/data/definitions/521.html",
         "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
     ]},
]


# --- [2. 外部檔 I/O] ---

def load_cache(path):
    """
    載入 translation_cache.json。若檔案不存在，先建立一個空的 {}，
    避免使用者誤以為「沒寫出檔」，也方便後續手動 merge/編輯。
    """
    if not os.path.exists(path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({}, f, ensure_ascii=False, indent=2)
            print(f"📝 已建立空白快取檔：{path}")
        except Exception as e:
            print(f"⚠️ 無法建立 {path}：{e}")
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f, strict=False)
    except Exception as e:
        print(f"⚠️ 快取讀取失敗：{e}")
        return {}


def save_cache(path, cache_data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f, ensure_ascii=False, indent=2)


def load_keyword_refs(path):
    """
    載入 keyword_refs.json。若檔案不存在，寫出預設內容後回傳預設資料。
    回傳格式：[(['keyword1','keyword2'], ['url1','url2']), ...]
    """
    if not os.path.exists(path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_KEYWORD_REFS, f, ensure_ascii=False, indent=2)
            print(f"📝 已建立預設關鍵字對照表：{path}")
        except Exception as e:
            print(f"⚠️ 無法建立 {path}：{e}")
        data = DEFAULT_KEYWORD_REFS
    else:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("keyword_refs.json 必須是 list")
        except Exception as e:
            print(f"⚠️ {path} 讀取失敗 ({e})，改用預設關鍵字表")
            data = DEFAULT_KEYWORD_REFS

    result = []
    for item in data:
        if not isinstance(item, dict):
            continue
        kws = item.get("keywords") or []
        urls = item.get("urls") or []
        if kws and urls:
            result.append((kws, urls))
    return result


# --- [3. 工具函式] ---

def format_html_text(text):
    if text is None:
        return "N/A"
    if isinstance(text, float) and pd.isna(text):
        return "N/A"
    s = str(text).strip()
    if s == "" or s.lower() == "nan":
        return "N/A"
    return s.replace("\\n", "<br/>").replace("\n", "<br/>")


def chinese_numeral(n):
    units = ["", "一", "二", "三", "四", "五", "六", "七", "八", "九"]
    if n < 1 or n > 99:
        return str(n)
    if n < 10:
        return units[n]
    if n == 10:
        return "十"
    if n < 20:
        return "十" + units[n - 10]
    tens, ones = divmod(n, 10)
    return units[tens] + "十" + (units[ones] if ones else "")


def now_iso():
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def parse_iso(s):
    if not s:
        return None
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


# --- [4. Tenable 抓取 ---

def _extract_modified_date(soup, raw_text):
    """
    從頁面中找「Plugin 最後修改日期 / Plugin Last Modification Date」。
    找不到回傳空字串。
    """
    # 以文字比對為主 (Tenable 頁面用法多變，純文字比較保險)
    patterns = [
        r"(?:Plugin\s*最後修改(?:日期)?|最後修改日期|Last\s*Modif(?:ication|ied)(?:\s*Date)?)\s*[:：]?\s*([0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2})",
        r"(?:Modification\s*Date)\s*[:：]?\s*([0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2})",
        r"(?:Updated|Modified|更新日期)\s*[:：]?\s*([0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2})",
        # 月份英文形式，例如 "Last Modified: January 15, 2024"
        r"(?:Last\s*Modif(?:ication|ied)|Modification\s*Date)\s*[:：]?\s*"
        r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+"
        r"([0-9]{1,2}),?\s+([0-9]{4})",
    ]
    month_map = {"January":1,"February":2,"March":3,"April":4,"May":5,"June":6,
                 "July":7,"August":8,"September":9,"October":10,"November":11,"December":12}
    for i, p in enumerate(patterns):
        m = re.search(p, raw_text)
        if m:
            if i == 3:  # 英文月份格式
                mon = month_map[m.group(1)]
                return f"{m.group(3)}-{mon:02d}-{int(m.group(2)):02d}"
            return m.group(1).replace("/", "-").replace(".", "-")

    # 再試 meta/time 標籤
    for tag in soup.find_all(["time", "meta"]):
        dt = tag.get("datetime") or tag.get("content") or ""
        if re.match(r"^\d{4}-\d{2}-\d{2}", dt):
            return dt[:10]

    # 最後嘗試：從 JSON-LD 或 inline JSON 裡找 dateModified / plugin_modification_date
    for script in soup.find_all("script"):
        s = script.string or script.get_text() or ""
        m = re.search(
            r'"(?:dateModified|plugin_modification_date|modificationDate|modified)"\s*:\s*"([0-9]{4}-[0-9]{2}-[0-9]{2})',
            s,
        )
        if m:
            return m.group(1)
    return ""


def _normalize_date(s):
    """把各種 date 字串標準化成 YYYY-MM-DD，抓不到回傳空字串。"""
    if not s:
        return ""
    m = re.search(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", str(s))
    if m:
        return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    return ""


def _api_first_value(data, keys):
    """從 dict 裡依序找第一個有值的欄位。"""
    for k in keys:
        v = data.get(k)
        if v not in (None, "", [], {}):
            return v
    return ""


def _zhcn_to_zhtw(text):
    """
    把簡體中文轉繁體。若有安裝 zhconv 套件就用；沒有就原樣回傳。
    安裝：pip install zhconv
    """
    if not text:
        return text
    try:
        import zhconv
        return zhconv.convert(text, "zh-tw")
    except ImportError:
        return text


def _source_get_i18n(source, base_field, primary_key, allow_zhcn_fallback):
    """
    依序找：
      1) source[base_field + '_i18n'][primary_key]
      2) (僅當 allow_zhcn_fallback) source[base_field + '_i18n']['zh_CN'] → 簡轉繁
      3) source[base_field]  (通常是英文)
    回傳 (value, lang_used)，lang_used 供上層判斷是否成功拿到目標語系。
    """
    i18n = source.get(f"{base_field}_i18n") or {}
    if primary_key and isinstance(i18n, dict):
        v = i18n.get(primary_key)
        if v:
            return v, primary_key
        if allow_zhcn_fallback:
            v = i18n.get("zh_CN")
            if v:
                return _zhcn_to_zhtw(v), "zh_CN→zh_TW"
    return source.get(base_field, ""), "en"


def _extract_modified_from_source(source):
    """從 _source 裡找 plugin 最後修改日期；也會掃 attributes 陣列。"""
    direct = _api_first_value(source, [
        "plugin_modification_date",
        "plugin_last_modification_date",
        "modification_date",
        "script_set_attribute_modification_date",
        "dateModified",
        "modified",
    ])
    d = _normalize_date(direct)
    if d:
        return d
    for attr in source.get("attributes", []) or []:
        if not isinstance(attr, dict):
            continue
        if attr.get("attribute_name") in (
            "plugin_modification_date",
            "plugin_last_modification_date",
            "modification_date",
            "script_set_attribute_modification_date",
        ):
            d = _normalize_date(attr.get("attribute_value"))
            if d:
                return d
    return ""


def fetch_tenable_api(pid, lang=DEFAULT_LANG):
    """
    透過 Tenable JSON API 抓取外掛內容。
    端點 (固定)：https://www.tenable.com/plugins/api/v1/nessus/<pid>
    JSON 結構：{ success, data: { _source: { description, description_i18n: {zh_CN, ja_JP}, ... } } }

    多語策略：
      --lang zh-tw → 先抓 zh_TW，沒有就抓 zh_CN 用 zhconv 轉繁，都沒有就回英文
      --lang zh-cn → 抓 zh_CN，沒有就回英文
      --lang ja    → 抓 ja_JP，沒有就回英文
      --lang en    → 直接回英文

    回傳：dict(desc, sol, see_also, plugin_modified, fetched_at)；失敗回 None。
    """
    url = f"https://{TENABLE_API_HOST}/plugins/api/v1/nessus/{pid}"
    try:
        resp = requests.get(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Accept-Language": f"{lang},zh;q=0.9,en;q=0.5",
                "Referer": f"https://{LANG_HOSTS.get(lang, TENABLE_API_HOST)}/",
            },
            timeout=REQUEST_TIMEOUT,
        )
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    try:
        payload = resp.json()
    except Exception:
        return None

    # 結構：{success: true, data: {_source: {...}}}
    if not (isinstance(payload, dict) and payload.get("success")):
        return None
    data = payload.get("data") or {}
    source = data.get("_source") or {}
    if not isinstance(source, dict) or not source:
        return None

    primary_key = LANG_I18N_KEY.get(lang)
    allow_zhcn_fallback = (lang == "zh-tw")   # 繁中缺時允許取簡中轉繁

    desc, _     = _source_get_i18n(source, "description", primary_key, allow_zhcn_fallback)
    sol, _      = _source_get_i18n(source, "solution",    primary_key, allow_zhcn_fallback)
    # synopsis 備用 (desc 若太短可以補)
    synopsis, _ = _source_get_i18n(source, "synopsis",    primary_key, allow_zhcn_fallback)

    if isinstance(desc, list):
        desc = "\n\n".join(str(x) for x in desc)
    if isinstance(sol, list):
        sol = "\n\n".join(str(x) for x in sol)

    # URL 來源：先看老欄位 see_also，再看 references
    # references 在新版 API 是 list of dict： [{"type":"...", "url":"https://...", ...}, ...]
    # 舊版或某些 Plugin 直接給 list of str 或字串也相容
    see_also_raw = source.get("see_also")
    if not see_also_raw:
        see_also_raw = source.get("references") or ""
    if isinstance(see_also_raw, list):
        urls = []
        for item in see_also_raw:
            if isinstance(item, dict):
                u = item.get("url")
                if u:
                    urls.append(str(u))
            elif item:
                urls.append(str(item))
        see_also = "\n".join(urls)
    else:
        see_also = str(see_also_raw or "")

    plugin_modified = _extract_modified_from_source(source)

    if not any([desc, sol, see_also]):
        return None

    return {
        "desc": str(desc).strip(),
        "sol": str(sol).strip(),
        "see_also": str(see_also).strip(),
        "plugin_modified": plugin_modified,
        "fetched_at": now_iso(),
    }


def fetch_tenable_zh(pid, lang=DEFAULT_LANG):
    """
    抓取 Tenable 官方繁中內容 (優先 API，失敗時 fallback HTML)。
    回傳：{'desc', 'sol', 'see_also', 'plugin_modified', 'fetched_at'}
    失敗回 None。
    """
    # (1) 優先用 JSON API
    info = fetch_tenable_api(pid, lang=lang)
    if info:
        return info

    # (2) Fallback：回去爬 HTML (舊版行為，供 API 失效時墊底)
    host = LANG_HOSTS.get(lang, LANG_HOSTS[DEFAULT_LANG])
    url = f"https://{host}/plugins/nessus/{pid}"
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT,
                     "Accept-Language": f"{lang},zh;q=0.9,en;q=0.5"},
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as e:
        print(f"   ⚠️ ID {pid} 連線失敗：{e}")
        return None

    if resp.status_code != 200:
        print(f"   ⚠️ ID {pid} HTTP {resp.status_code}")
        return None

    soup = BeautifulSoup(resp.text, "html.parser")
    page_text = soup.get_text("\n", strip=True)

    def collect(keywords):
        for lbl in soup.find_all(class_=lambda c: c and "field__label" in c):
            if any(k in lbl.get_text(strip=True) for k in keywords):
                parent = lbl.parent or lbl
                item = parent.find(class_=lambda c: c and "field__item" in c)
                if item:
                    return item.get_text("\n", strip=True)
        for h in soup.find_all(["h2", "h3"]):
            if any(k in h.get_text(strip=True) for k in keywords):
                parts = []
                for sib in h.find_next_siblings():
                    if sib.name in ("h1", "h2", "h3"):
                        break
                    t = sib.get_text("\n", strip=True)
                    if t:
                        parts.append(t)
                if parts:
                    return "\n".join(parts)
        for dt in soup.find_all("dt"):
            if any(k in dt.get_text(strip=True) for k in keywords):
                dd = dt.find_next_sibling("dd")
                if dd:
                    return dd.get_text("\n", strip=True)
        return ""

    result = {
        "desc":     collect(["描述", "說明", "Description"]),
        "sol":      collect(["解決方案", "Solution"]),
        "see_also": collect(["另請參閱", "參閱", "See Also"]),
        "plugin_modified": _extract_modified_date(soup, page_text),
        "fetched_at": now_iso(),
    }
    # 至少要抓到 desc/sol/see_also 其中一個才算成功
    if not any([result["desc"], result["sol"], result["see_also"]]):
        return None
    return result


def fetch_tenable_modified_only(pid, lang=DEFAULT_LANG):
    """
    輕量檢查：只回傳 plugin_modified，用於 --check-updates。
    優先走 JSON API (直接回傳欄位)，失敗時才爬 HTML。
    回傳值：
      - "YYYY-MM-DD" 字串  → 成功抓到日期
      - None              → 連線 / HTTP / 解析都失敗
    """
    # (1) 先試 API (固定 www.tenable.com)
    try:
        resp = requests.get(
            f"https://{TENABLE_API_HOST}/plugins/api/v1/nessus/{pid}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            payload = resp.json()
            if isinstance(payload, dict) and payload.get("success"):
                source = (payload.get("data") or {}).get("_source") or {}
                d = _extract_modified_from_source(source)
                if d:
                    return d
    except Exception:
        pass

    # (2) Fallback：爬 HTML
    host = LANG_HOSTS.get(lang, LANG_HOSTS[DEFAULT_LANG])
    try:
        resp = requests.get(
            f"https://{host}/plugins/nessus/{pid}",
            headers={"User-Agent": USER_AGENT,
                     "Accept-Language": f"{lang},zh;q=0.9,en;q=0.5"},
            timeout=REQUEST_TIMEOUT,
        )
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    soup = BeautifulSoup(resp.text, "html.parser")
    date = _extract_modified_date(soup, soup.get_text("\n", strip=True))
    return date if date else None


# --- [5. 參考資料組合 ---

def build_references(pid, name, cve_field, tenable_see_also, keyword_refs):
    s = str(tenable_see_also or "").strip()
    if s and s.lower() not in ("nan", "n/a"):
        return s

    parts = []
    if cve_field is not None:
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(cve_field))))
        for c in cves:
            parts.append(f"https://nvd.nist.gov/vuln/detail/{c}")

    name_lower = str(name or "").lower()
    for keywords, urls in keyword_refs:
        if any(k.lower() in name_lower for k in keywords):
            parts.extend(urls)
            break

    parts.append(f"https://zh-tw.tenable.com/plugins/nessus/{pid}")
    return "\n".join(parts)


# --- [6. HTML 產生器] ---

def wrap_html(body):
    return (
        '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" />'
        '</head><body style="font-family:\'標楷體\', Calibri, sans-serif; padding:20px;">'
        f"{body}"
        "</body></html>"
    )


def build_port_disp(df, compact=False):
    proto = df["Protocol"].fillna("").astype(str).str.upper()
    port = df["Port"].fillna("").astype(str)
    sep = "" if compact else " "
    return proto + sep + port


def build_target_string(df_plugin):
    host_ports = (
        df_plugin.groupby("Host")["Port_Disp"]
        .apply(lambda x: "、".join(sorted(set(x))))
    )
    parts = [f"{host}({ports})" for host, ports in host_ports.sort_index().items()]
    return "、".join(parts)


def build_summary_line(df):
    unique = df.drop_duplicates(subset=["Plugin ID"])
    counts = {r: 0 for r in RISK_ORDER}
    for r in unique["Risk_TW"]:
        counts[r] = counts.get(r, 0) + 1
    total = sum(counts.values())
    return (
        f"合計：嚴重風險{counts['嚴重風險']}項、高風險{counts['高風險']}項、"
        f"中風險{counts['中風險']}項、低風險{counts['低風險']}項，共{total}項"
    )


def render_summary(df, cache, keyword_refs):
    uniq = df.drop_duplicates(subset=["Plugin ID"]).copy()
    uniq["order"] = uniq["Risk_TW"].map(RISK_ORDER)
    uniq = uniq.sort_values(["order", "Plugin ID"]).reset_index(drop=True)

    pieces = []
    for i, row in uniq.iterrows():
        pid = str(row["Plugin ID"])
        name = str(row["Name"])
        risk = row["Risk_TW"]
        color = COLOR_MAP.get(risk, "#DD4B50")
        idx_zh = chinese_numeral(i + 1)

        sub = df[df["Plugin ID"] == row["Plugin ID"]]
        plugin_output = "、".join(sorted(set(sub["Port_Disp"])))
        targets = build_target_string(sub)

        info = cache.get(pid, {})
        desc     = info.get("desc")     or row.get("Description", "")
        sol      = info.get("sol")      or row.get("Solution", "")
        see_also_raw = info.get("see_also") or row.get("See Also", "")

        cve_field = ""
        for col in ("CVE", "cve"):
            if col in row.index and pd.notna(row[col]):
                cve_field = str(row[col])
                break
        see_also = build_references(pid, name, cve_field, see_also_raw, keyword_refs)

        pieces.append(
            f'<p style="margin:18pt 0 4pt 0;">'
            f'<span style="font-size:14pt; font-family:\'標楷體\';">（{idx_zh}）</span>'
            f'<span style="font-size:14pt;">{html.escape(name)}</span>'
            f'</p>'
        )
        pieces.append(f"""
<table border="1" cellpadding="4" cellspacing="0" style="border-collapse:collapse; width:100%; max-width:1080px; font-size:12pt; font-family:'標楷體', Calibri; margin-bottom:18pt;">
  <tr>
    <td colspan="2" bgcolor="{color}" style="color:white; font-weight:bold; padding:8px; font-size:13pt;">{risk}</td>
  </tr>
  <tr>
    <td bgcolor="{color}" width="130" style="color:white; font-weight:bold; padding:6px 8px;">風險代號：</td>
    <td bgcolor="{color}" style="color:white; padding:6px 8px;">{pid}</td>
  </tr>
  <tr>
    <td bgcolor="#f9f9f9" style="font-weight:bold; padding:6px 8px;">Plugin Output</td>
    <td style="padding:6px 8px;">{plugin_output}</td>
  </tr>
  <tr>
    <td bgcolor="#f9f9f9" style="font-weight:bold; padding:6px 8px;">目標：</td>
    <td style="padding:6px 8px; word-break:break-all;">{targets}</td>
  </tr>
  <tr>
    <td bgcolor="#f9f9f9" style="font-weight:bold; padding:6px 8px;">弱點摘要、分析說明：</td>
    <td style="padding:6px 8px; text-align:justify; word-break:break-all;">{format_html_text(desc)}</td>
  </tr>
  <tr>
    <td bgcolor="#f9f9f9" style="font-weight:bold; padding:6px 8px;">安全強化建議：</td>
    <td style="padding:6px 8px; text-align:justify; word-break:break-all;">{format_html_text(sol)}</td>
  </tr>
  <tr>
    <td bgcolor="#f9f9f9" style="font-weight:bold; padding:6px 8px;">參考資料：</td>
    <td style="padding:6px 8px; word-break:break-all;">{format_html_text(see_also)}</td>
  </tr>
</table>
""")
    return "\n".join(pieces)


def render_vuln_table(df):
    grouped = (
        df.groupby(["Risk_TW", "Plugin ID"])["Port_Disp"]
        .apply(lambda x: "、".join(sorted(set(x))))
        .reset_index()
    )
    grouped["order"] = grouped["Risk_TW"].map(RISK_ORDER)
    grouped = grouped.sort_values(["order", "Plugin ID"]).reset_index(drop=True)
    grouped["rowspan"] = grouped.groupby("Risk_TW")["Risk_TW"].transform("count")
    grouped["is_first"] = ~grouped.duplicated(subset=["Risk_TW"])

    rows = [
        '<tr bgcolor="#eeeeee">'
        '<td><b>風險等級</b></td>'
        '<td><b>風險代號</b></td>'
        '<td><b>Plugin Output</b></td>'
        '</tr>'
    ]
    for _, r in grouped.iterrows():
        color = COLOR_MAP.get(r["Risk_TW"], "#ffffff")
        tr = ["<tr>"]
        if r["is_first"]:
            tr.append(
                f'<td rowspan="{int(r["rowspan"])}" bgcolor="{color}" '
                f'style="color:white; font-weight:bold; text-align:center;">{r["Risk_TW"]}</td>'
            )
        tr.append(f'<td style="text-align:center;">{r["Plugin ID"]}</td>')
        tr.append(f'<td>{r["Port_Disp"]}</td>')
        tr.append("</tr>")
        rows.append("".join(tr))

    rows.append(
        f'<tr><td colspan="3" style="text-align:center; font-weight:bold;">'
        f'{build_summary_line(df)}</td></tr>'
    )
    return (
        '<table border="1" cellpadding="4" cellspacing="0" '
        'style="border-collapse:collapse; font-size:12pt; font-family:\'標楷體\', Calibri; text-align:left;">'
        + "".join(rows)
        + "</table>"
    )


def render_ip_table(df):
    df = df.copy()
    df["Port_Compact"] = build_port_disp(df, compact=True)

    pivot = df.pivot_table(
        index=["Risk_TW", "Plugin ID"],
        columns="Host",
        values="Port_Compact",
        aggfunc=lambda x: "<br/>".join(sorted(set(x))),
    ).fillna("")
    pivot = pivot.reset_index()
    pivot["order"] = pivot["Risk_TW"].map(RISK_ORDER)
    pivot = pivot.sort_values(["order", "Plugin ID"]).reset_index(drop=True)

    hosts = sorted([c for c in pivot.columns if c not in ("Risk_TW", "Plugin ID", "order")])
    pivot["rowspan"] = pivot.groupby("Risk_TW")["Risk_TW"].transform("count")
    pivot["is_first"] = ~pivot.duplicated(subset=["Risk_TW"])
    risk_totals = pivot.groupby("Risk_TW").size().to_dict()

    header = ['<tr bgcolor="#eeeeee"><td><b>風險等級</b></td><td><b>風險代號</b></td>']
    header += [f"<td><b>{h}</b></td>" for h in hosts]
    header.append("<td><b>小計</b></td></tr>")

    body = []
    for _, r in pivot.iterrows():
        color = COLOR_MAP.get(r["Risk_TW"], "#ffffff")
        tr = ["<tr>"]
        if r["is_first"]:
            tr.append(
                f'<td rowspan="{int(r["rowspan"])}" bgcolor="{color}" '
                f'style="color:white; font-weight:bold; text-align:center;">{r["Risk_TW"]}</td>'
            )
        tr.append(f'<td style="text-align:center;">{r["Plugin ID"]}</td>')
        for h in hosts:
            tr.append(f'<td style="text-align:center;">{r[h]}</td>')
        if r["is_first"]:
            tr.append(
                f'<td rowspan="{int(r["rowspan"])}" style="text-align:center; font-weight:bold;">'
                f'{risk_totals[r["Risk_TW"]]}</td>'
            )
        tr.append("</tr>")
        body.append("".join(tr))

    total_cols = len(hosts) + 3
    body.append(
        f'<tr><td colspan="{total_cols}" style="text-align:center; font-weight:bold;">'
        f'{build_summary_line(df)}</td></tr>'
    )
    return (
        '<table border="1" cellpadding="4" cellspacing="0" '
        'style="border-collapse:collapse; font-size:10pt; font-family:\'標楷體\', Calibri; text-align:center;">'
        + "".join(header)
        + "".join(body)
        + "</table>"
    )


# --- [7. 更新邏輯 ---

def pids_to_refresh(all_pids, cache, mode, target_pids=None, older_days=None):
    """
    決定這次要重抓哪些 PID。
    mode:
      'normal'        : 只抓還沒在快取裡的
      'refresh-all'   : 全部重抓
      'refresh-some'  : 只抓 target_pids
      'refresh-older' : 抓快取時間超過 older_days 的
    """
    all_pids = [str(p) for p in all_pids]
    if mode == "refresh-all":
        return list(all_pids)
    if mode == "refresh-some":
        return [p for p in all_pids if p in set(str(x) for x in (target_pids or []))]
    if mode == "refresh-older":
        threshold = datetime.now() - timedelta(days=older_days or 0)
        result = []
        for p in all_pids:
            entry = cache.get(p)
            if not entry:
                result.append(p)
                continue
            fetched = parse_iso(entry.get("fetched_at", ""))
            if fetched is None or fetched < threshold:
                result.append(p)
        return result
    # normal
    return [p for p in all_pids if p not in cache]


def fetch_and_cache(pids, cache, cache_path, verb="抓取", lang=DEFAULT_LANG):
    if not pids:
        return 0
    print(f"-> 開始{verb} {len(pids)} 項弱點資訊 (Tenable {lang} API)…")
    ok = 0
    for i, pid in enumerate(pids, 1):
        print(f"   [{i}/{len(pids)}] {verb} ID {pid} …", end=" ", flush=True)
        info = fetch_tenable_zh(pid, lang=lang)
        if info:
            cache[pid] = info
            save_cache(cache_path, cache)
            ok += 1
            print("✅")
        else:
            print("⚠️ 未取得中文資料，保留原本快取/CSV 原文")
        time.sleep(FETCH_INTERVAL)
    return ok


def check_updates(pids, cache, cache_path, lang=DEFAULT_LANG):
    """逐一比對 Tenable 頁面「最後修改日期」，有變動的才重抓。"""
    changed = []
    print(f"-> 檢查 {len(pids)} 項弱點是否有更新 (Tenable {lang} API 比對最後修改日期)…")
    failed = 0
    for i, pid in enumerate(pids, 1):
        pid = str(pid)
        print(f"   [{i}/{len(pids)}] 檢查 ID {pid} …", end=" ", flush=True)
        live = fetch_tenable_modified_only(pid, lang=lang)
        cached = (cache.get(pid) or {}).get("plugin_modified", "")
        if live is None:
            print("⚠️ 檢查失敗 (找不到最後修改日期，可能是頁面結構改版)")
            failed += 1
        elif not cached:
            # 快取裡沒日期但這次抓到了 → 當作「有更新」強制重抓，順便把 plugin_modified 寫回快取
            print(f"🔄 首次寫入日期 (— → {live})")
            changed.append(pid)
        elif live != cached:
            print(f"🔄 有更新 ({cached} → {live})")
            changed.append(pid)
        else:
            print(f"✔ 無變動 ({cached})")
        time.sleep(FETCH_INTERVAL)
    if failed:
        print(f"   (其中 {failed} 項檢查失敗；可改用 `--refresh` 強制重抓完整內容)")

    if changed:
        print(f"-> 有 {len(changed)} 項弱點內容已更新，開始重抓")
        fetch_and_cache(changed, cache, cache_path, verb="更新", lang=lang)
    else:
        print("-> 所有弱點都是最新版本")
    return changed


# --- [8. 主程式] ---

def parse_args():
    ap = argparse.ArgumentParser(
        description="Nessus 弱點報告產生器 (支援報告模式與純快取維護模式)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("csv", nargs="?",
                    help="Nessus 匯出的 CSV 檔 (省略時進入純快取維護模式)")
    ap.add_argument("--cache-dir", default=None, metavar="DIR",
                    help="指定快取檔 (translation_cache.json) 與關鍵字表 (keyword_refs.json) 的目錄 "
                         "(預設：目前工作目錄)")
    ap.add_argument("--lang", default=DEFAULT_LANG,
                    choices=list(LANG_HOSTS.keys()),
                    help=f"Tenable 語系 (預設 {DEFAULT_LANG})：zh-tw 繁中、zh-cn 簡中、ja 日文、en 英文")
    ap.add_argument("--refresh", nargs="*", metavar="PID",
                    help="強制重抓：不帶參數=全部；帶 PID=只抓指定的 ID")
    ap.add_argument("--refresh-older", type=int, metavar="DAYS",
                    help="重抓快取時間超過 N 天的 ID")
    ap.add_argument("--check-updates", action="store_true",
                    help="比對 Tenable 最後修改日期，只更新有變動的 ID")
    return ap.parse_args()


def run_maintenance_mode(args):
    """不需要 CSV 的純快取維護模式"""
    cache_dir = os.path.abspath(args.cache_dir or ".")
    cache_path = os.path.join(cache_dir, CACHE_FILENAME)

    has_action = (args.refresh is not None
                  or args.refresh_older is not None
                  or args.check_updates)
    if not has_action:
        print("❌ 沒提供 CSV 時，必須搭配 --refresh / --refresh-older / --check-updates")
        print("   範例：python Report.py --check-updates")
        print("   (使用 -h 查看完整說明)")
        return 1

    if not os.path.exists(cache_path):
        print(f"❌ 找不到快取檔：{cache_path}")
        print("   請先在該目錄執行一次「報告模式」(帶 CSV) 建立快取，或用 --cache-dir 指定正確路徑")
        return 1

    cache = load_cache(cache_path)
    if not cache:
        print(f"❌ 快取是空的：{cache_path}")
        return 1

    cached_pids = list(cache.keys())
    print(f"📂 載入快取：{cache_path} ({len(cached_pids)} 項)")

    if args.check_updates:
        check_updates(cached_pids, cache, cache_path, lang=args.lang)
    elif args.refresh is not None:
        if len(args.refresh) == 0:
            targets = cached_pids          # 全部快取項
            verb = "重抓"
        else:
            targets = [str(p) for p in args.refresh]  # 允許抓還不在快取裡的新 ID
            verb = "重抓"
        fetch_and_cache(targets, cache, cache_path, verb=verb, lang=args.lang)
    elif args.refresh_older is not None:
        pids = pids_to_refresh(cached_pids, cache, "refresh-older",
                               older_days=args.refresh_older)
        if not pids:
            print(f"-> 沒有快取時間超過 {args.refresh_older} 天的項目")
        else:
            fetch_and_cache(pids, cache, cache_path, verb="更新", lang=args.lang)

    print("\n✅ 維護完成")
    return 0


def main():
    args = parse_args()

    # 沒提供 CSV → 進入維護模式
    if not args.csv:
        sys.exit(run_maintenance_mode(args))

    input_file = args.csv
    if not os.path.exists(input_file):
        print(f"❌ 找不到檔案：{input_file}")
        return

    base_name = os.path.splitext(os.path.basename(input_file))[0]
    out_dir = os.path.dirname(os.path.abspath(input_file))
    # 快取檔與關鍵字表：預設放在「目前工作目錄 (cwd)」，與舊版一致。
    # 這樣既有的 translation_cache.json 不會因為 CSV 放在其他資料夾而被「找不到」。
    # 若要指定其他位置，用 --cache-dir。
    cache_base = os.path.abspath(args.cache_dir) if args.cache_dir else os.getcwd()
    cache_path = os.path.join(cache_base, CACHE_FILENAME)
    kw_path = os.path.join(cache_base, KEYWORD_REFS_FILENAME)
    if os.path.exists(cache_path):
        print(f"📂 使用快取：{cache_path}")
    else:
        print(f"ℹ️  快取檔尚不存在，將建立於：{cache_path}")

    # 讀 CSV
    try:
        df = pd.read_csv(input_file)
    except UnicodeDecodeError:
        df = pd.read_csv(input_file, encoding="utf-8-sig")

    required = ["Risk", "Plugin ID", "Host", "Protocol", "Port", "Name"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"❌ CSV 缺少必要欄位：{missing}")
        return

    df = df[df["Risk"].isin(RISK_MAP.keys())].copy()
    if df.empty:
        print("⚠️ CSV 沒有符合風險等級 (Critical/High/Medium/Low) 的資料")
        return

    df["Risk_TW"] = df["Risk"].map(RISK_MAP)
    df["Port_Disp"] = build_port_disp(df, compact=False)
    for col in ("Description", "Solution", "See Also"):
        if col not in df.columns:
            df[col] = ""

    # 載入外部檔
    cache = load_cache(cache_path)
    keyword_refs = load_keyword_refs(kw_path)

    all_pids = [str(p) for p in df.drop_duplicates(subset=["Plugin ID"])["Plugin ID"]]

    # 決定重抓策略
    if args.check_updates:
        # 只檢查已在快取的項目；順便把沒抓過的新項目也抓一下
        check_updates([p for p in all_pids if p in cache], cache, cache_path, lang=args.lang)
        new_pids = [p for p in all_pids if p not in cache]
        fetch_and_cache(new_pids, cache, cache_path, verb="抓取", lang=args.lang)
    else:
        if args.refresh is not None:
            if len(args.refresh) == 0:
                mode = "refresh-all"
                target = None
            else:
                mode = "refresh-some"
                target = args.refresh
        elif args.refresh_older is not None:
            mode = "refresh-older"
            target = None
        else:
            mode = "normal"
            target = None

        pids = pids_to_refresh(all_pids, cache, mode,
                               target_pids=target,
                               older_days=args.refresh_older)
        verb = {"refresh-all": "重抓", "refresh-some": "重抓",
                "refresh-older": "更新", "normal": "抓取"}[mode]
        fetch_and_cache(pids, cache, cache_path, verb=verb, lang=args.lang)

    # 產出 HTML
    print("-> 1/3 產製：風險摘要.html")
    out1 = os.path.join(out_dir, f"{base_name}_風險摘要.html")
    with open(out1, "w", encoding="utf-8") as f:
        f.write(wrap_html(render_summary(df, cache, keyword_refs)))

    print("-> 2/3 產製：弱點統計表.html")
    out2 = os.path.join(out_dir, f"{base_name}_弱點統計表.html")
    with open(out2, "w", encoding="utf-8") as f:
        f.write(wrap_html(render_vuln_table(df)))

    print("-> 3/3 產製：統計表.html")
    out3 = os.path.join(out_dir, f"{base_name}_統計表.html")
    with open(out3, "w", encoding="utf-8") as f:
        f.write(wrap_html(render_ip_table(df)))

    print("\n✅ 全部完成！")
    print(f"   {out1}")
    print(f"   {out2}")
    print(f"   {out3}")


if __name__ == "__main__":
    main()
