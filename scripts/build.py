#!/usr/bin/env python3
"""
Pulls the full malicious-address list from siberguvenlik.gov.tr and writes
two plain-text feeds suitable for Fortinet External Block List / Palo Alto
External Dynamic List consumers:

    out/domains.txt   one domain per line, sorted, deduped
    out/ips.txt       one IPv4 per line, sorted, deduped

Full re-fetch every run. Incremental would miss removals from the upstream list.
"""
from __future__ import annotations

import datetime as dt
import html
import ipaddress
import os
import pathlib
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode

import requests

API = "https://siberguvenlik.gov.tr/api/address/index"
PER_PAGE = 1000
PARALLELISM = 6
TIMEOUT = 30
MAX_RETRIES = 5
OUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "out"

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "usomfeed-builder/1.0 (+https://github.com/yunuskargi/usomfeed)"


def fetch_page(addr_type: str, page: int) -> dict:
    qs = urlencode({"type": addr_type, "per-page": PER_PAGE, "page": page})
    url = f"{API}?{qs}"
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = SESSION.get(url, timeout=TIMEOUT)
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            if attempt == MAX_RETRIES:
                raise RuntimeError(f"giving up on {addr_type} page {page}: {e}") from e
            backoff = min(2 ** attempt, 30)
            print(f"[warn] {addr_type} page {page} attempt {attempt} failed: {e}; retrying in {backoff}s", file=sys.stderr)
            time.sleep(backoff)
    raise AssertionError("unreachable")


def fetch_all(addr_type: str) -> dict[str, int]:
    """Address → criticality_level (eğer aynı adres birden fazla sayfada gelirse en yükseğini tut)."""
    first = fetch_page(addr_type, 1)
    total = int(first.get("totalCount", 0))
    page_count = int(first.get("pageCount", 1))
    entries: dict[str, int] = {}
    _merge(entries, first)
    print(f"[info] {addr_type}: totalCount={total} pageCount={page_count}", file=sys.stderr)

    if page_count <= 1:
        return entries

    pages = list(range(2, page_count + 1))
    with ThreadPoolExecutor(max_workers=PARALLELISM) as pool:
        futures = {pool.submit(fetch_page, addr_type, p): p for p in pages}
        for fut in as_completed(futures):
            page = futures[fut]
            data = fut.result()
            _merge(entries, data)
            if page % 25 == 0:
                print(f"[info] {addr_type}: fetched page {page}/{page_count} (running unique={len(entries)})", file=sys.stderr)

    return entries


def _merge(dest: dict[str, int], payload: dict) -> None:
    for m in payload.get("models", []) or []:
        v = (m.get("url") or "").strip().lower()
        if not v:
            continue
        crit = int(m.get("criticality_level") or 0)
        if crit > dest.get(v, 0):
            dest[v] = crit


def _clean_host(d: str) -> str | None:
    # upstream sometimes ships "www.foo.com/path" or "foo.com:8080"; trim to bare host
    host = d.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if host and "." in host and " " not in host:
        return host
    return None


def write_domains(entries: dict[str, int], path: pathlib.Path,
                  min_criticality: int = 0) -> int:
    cleaned: set[str] = set()
    for d, crit in entries.items():
        if crit < min_criticality:
            continue
        host = _clean_host(d)
        if host:
            cleaned.add(host)
    return _write_sorted(cleaned, path)


def write_ips(entries: dict[str, int], path: pathlib.Path) -> int:
    cleaned: set[str] = set()
    for v in entries.keys():
        try:
            cleaned.add(str(ipaddress.IPv4Address(v)))
        except ValueError:
            continue  # skip malformed entries
    # sort numerically, not lexicographically
    sorted_ips = sorted(cleaned, key=lambda x: int(ipaddress.IPv4Address(x)))
    _write_lf(sorted_ips, path)
    return len(sorted_ips)


def _write_sorted(items: set[str], path: pathlib.Path) -> int:
    items_sorted = sorted(items)
    _write_lf(items_sorted, path)
    return len(items_sorted)


def _write_lf(lines: list[str], path: pathlib.Path) -> None:
    # binary write → guaranteed LF on any platform, no BOM, no CRLF
    path.parent.mkdir(parents=True, exist_ok=True)
    body = ("\n".join(lines) + "\n") if lines else ""
    path.write_bytes(body.encode("utf-8"))


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("[info] fetching domains...", file=sys.stderr)
    domains = fetch_all("domain")
    n_dom = write_domains(domains, OUT_DIR / "domains.txt")
    print(f"[ok] wrote {n_dom} domains", file=sys.stderr)

    n_crit = write_domains(domains, OUT_DIR / "domains_critical.txt",
                           min_criticality=7)
    print(f"[ok] wrote {n_crit} critical domains (level >= 7)", file=sys.stderr)

    print("[info] fetching ips...", file=sys.stderr)
    ips = fetch_all("ip")
    n_ip = write_ips(ips, OUT_DIR / "ips.txt")
    print(f"[ok] wrote {n_ip} ips", file=sys.stderr)

    # sanity: refuse to publish a feed that suddenly collapsed (likely upstream outage)
    if n_dom < 1000:
        print(f"[fatal] domain count {n_dom} suspiciously low; aborting", file=sys.stderr)
        return 2
    if n_ip < 100:
        print(f"[fatal] ip count {n_ip} suspiciously low; aborting", file=sys.stderr)
        return 2
    if n_crit < 100:
        print(f"[fatal] critical domain count {n_crit} suspiciously low; aborting", file=sys.stderr)
        return 2

    write_index(OUT_DIR / "index.html", n_dom, n_ip, n_crit,
                (OUT_DIR / "domains.txt").stat().st_size,
                (OUT_DIR / "ips.txt").stat().st_size,
                (OUT_DIR / "domains_critical.txt").stat().st_size)
    print("[ok] wrote index.html", file=sys.stderr)

    return 0


INDEX_TEMPLATE = r"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>USOM Feeds</title>
<meta name="description" content="T.C. Siber Güvenlik Başkanlığı zararlı domain ve IP listesinin FortiGate / Palo Alto uyumlu txt formatı. Saatte bir güncellenir.">
<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>
<style>
  :root {
    --bg: #f4fbfa;            /* daha nötr soft mint */
    --bg-elev: #ffffff;
    --surface: rgba(15, 118, 110, 0.06);
    --surface-hover: rgba(15, 118, 110, 0.12);
    --border: rgba(15, 118, 110, 0.20);
    --border-strong: rgba(15, 118, 110, 0.45);
    --fg: #0f172a;            /* near-black, ~14:1 contrast on bg */
    --fg-dim: #334155;        /* secondary text */
    --muted: #475569;         /* tertiary text, hâlâ WCAG AA */
    --accent: #0f766e;        /* readable teal — link/url için */
    --accent-bright: #14b8a6; /* sadece large UI öğeleri (logo, tab bg) için */
    --accent-deep: #115e59;
    --glow: rgba(20, 184, 166, 0.28);
    --ok: #059669;
    --warn: #d97706;
    --err: #dc2626;
  }
  /* force light scheme — dark sistem ayarı bile olsa light gösterir */
  html { color-scheme: light; }

  *{box-sizing:border-box}
  html,body{margin:0;padding:0;overflow-x:hidden}
  body{
    font:15px/1.65 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Inter","SF Pro Text",system-ui,sans-serif;
    color:var(--fg);
    background:var(--bg);
    -webkit-font-smoothing:antialiased;
    min-height:100vh;
    position:relative;
  }
  /* subtle background accents */
  body::before, body::after {
    content:"";
    position:fixed;
    width:550px; height:550px;
    border-radius:50%;
    filter:blur(130px);
    z-index:0;
    pointer-events:none;
    opacity:.32;
  }
  body::before {
    background:radial-gradient(circle, var(--accent) 0%, transparent 70%);
    top:-150px; left:-150px;
  }
  body::after {
    background:radial-gradient(circle, var(--accent-deep) 0%, transparent 70%);
    bottom:-150px; right:-150px;
  }

  .wrap{
    max-width:960px;
    margin:0 auto;
    padding:48px 24px 96px;
    position:relative;
    z-index:1;
  }

  /* hero */
  .hero{
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:24px;
    flex-wrap:wrap;
    margin-bottom:48px;
  }
  .brand{display:flex;align-items:center;gap:14px}
  .logo{
    width:44px;height:44px;
    border-radius:12px;
    background:linear-gradient(135deg, var(--accent) 0%, var(--accent-deep) 100%);
    display:flex;align-items:center;justify-content:center;
    box-shadow:0 8px 32px var(--glow), inset 0 1px 0 rgba(255,255,255,.2);
    flex-shrink:0;
  }
  .logo svg{width:24px;height:24px;color:#fff}
  h1{
    margin:0;
    font-size:24px;
    font-weight:700;
    letter-spacing:-.02em;
    color:var(--fg);
  }
  .tagline{color:var(--muted);font-size:13px;margin-top:2px}

  .pill{
    display:inline-flex;align-items:center;gap:8px;
    padding:6px 14px;
    border-radius:999px;
    font-size:12px;font-weight:600;
    background:var(--surface);
    border:1px solid var(--border);
    backdrop-filter:blur(8px);
    -webkit-backdrop-filter:blur(8px);
  }
  .pill .dot{
    width:8px;height:8px;
    border-radius:50%;
    background:var(--muted);
    position:relative;
  }
  .pill.ok .dot{background:var(--ok)}
  .pill.ok .dot::after{
    content:"";
    position:absolute;
    inset:-2px;
    border-radius:50%;
    background:var(--ok);
    opacity:.4;
    animation:pulse 2s ease-in-out infinite;
  }
  .pill.warn .dot{background:var(--warn)}
  .pill.err .dot{background:var(--err)}
  @keyframes pulse{
    0%,100%{transform:scale(1);opacity:.4}
    50%{transform:scale(1.8);opacity:0}
  }

  /* stats */
  .stats{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
    gap:16px;
    margin-bottom:32px;
  }
  .stat{
    background:var(--bg-elev);
    border:1px solid var(--border);
    border-radius:14px;
    padding:20px 22px;
    transition:transform .2s ease, border-color .2s ease;
    backdrop-filter:blur(12px);
    -webkit-backdrop-filter:blur(12px);
  }
  .stat:hover{border-color:var(--border-strong);transform:translateY(-2px)}
  .stat .v{
    font-size:28px;font-weight:700;
    letter-spacing:-.03em;
    color:var(--fg);
    line-height:1.1;
  }
  .stat .l{
    color:var(--muted);
    font-size:11px;
    text-transform:uppercase;
    letter-spacing:.08em;
    margin-top:8px;
    font-weight:500;
  }

  /* cards */
  .card{
    background:var(--bg-elev);
    border:1px solid var(--border);
    border-radius:16px;
    padding:28px;
    margin-bottom:20px;
    backdrop-filter:blur(12px);
    -webkit-backdrop-filter:blur(12px);
  }
  .card-title{
    font-size:11px;
    font-weight:700;
    text-transform:uppercase;
    letter-spacing:.1em;
    color:var(--accent-deep);
    margin:0 0 18px;
  }

  .feed-item{
    display:flex;align-items:center;gap:12px;
    padding:14px 16px;
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:10px;
    transition:all .2s ease;
  }
  .feed-item:hover{background:var(--surface-hover);border-color:var(--border-strong)}
  .feed-item + .feed-item{margin-top:10px}
  .feed-url{
    flex:1;
    font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
    font-size:13px;
    font-weight:500;
    color:var(--accent-deep);
    text-decoration:none;
    word-break:break-all;
    min-width:0;
  }
  .feed-url:hover{color:var(--accent)}
  .feed-meta{
    color:var(--muted);
    font-size:12px;
    margin-top:6px;
    padding-left:16px;
  }

  /* tabs */
  .tabs{
    display:flex;
    gap:4px;
    margin:-4px -4px 24px;
    padding:6px;
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:12px;
    overflow-x:auto;
  }
  .tab{
    background:none;border:none;
    color:var(--muted);
    padding:10px 18px;
    cursor:pointer;
    font-size:13px;
    font-weight:600;
    border-radius:8px;
    white-space:nowrap;
    font-family:inherit;
    transition:all .2s ease;
  }
  .tab:hover{color:var(--fg-dim)}
  .tab.active{
    color:#fff;
    background:var(--accent-deep);
    box-shadow:0 4px 12px var(--glow);
  }
  .panel{display:none}
  .panel.active{display:block;animation:fadeIn .25s ease}
  @keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
  .panel p{margin:0 0 14px}
  .panel ol{margin:0 0 14px;padding-left:22px}
  .panel li{margin:8px 0}
  .panel li::marker{color:var(--accent)}

  /* code blocks */
  .code{position:relative;margin:14px 0}
  .code pre{
    margin:0;
    background:#f4fbfa;
    border:1px solid var(--border);
    border-radius:10px;
    padding:18px 18px;
    overflow-x:auto;
    font-size:13px;
    font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
    color:var(--fg);
    line-height:1.7;
  }
  .copy{
    position:absolute;
    top:10px;right:10px;
    background:#ffffff;
    border:1px solid var(--border-strong);
    color:var(--accent-deep);
    font-size:11px;font-weight:700;
    padding:6px 12px;
    border-radius:6px;
    cursor:pointer;
    font-family:inherit;
    transition:all .15s ease;
    text-transform:uppercase;
    letter-spacing:.05em;
  }
  .copy:hover{background:var(--surface);border-color:var(--accent)}
  .copy.copied{background:var(--accent);color:#fff;border-color:var(--accent)}

  /* inline copy on feed-item */
  .feed-item .copy{position:static;flex-shrink:0}

  code{
    background:var(--surface);
    border:1px solid var(--border);
    padding:2px 7px;
    border-radius:5px;
    font-size:.9em;
    font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
    color:var(--accent-deep);
  }

  a{color:var(--accent);text-decoration:none}
  a:hover{color:var(--accent-deep);text-decoration:underline}

  footer{
    margin-top:48px;
    padding-top:24px;
    border-top:1px solid var(--border);
    color:var(--muted);
    font-size:12px;
    line-height:1.8;
  }
  footer code{color:var(--muted);background:transparent;border:none;padding:0}
</style>
</head>
<body>
<div class="wrap">

  <div class="hero">
    <div class="brand">
      <div class="logo">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="9"/>
          <circle cx="12" cy="12" r="5" opacity="0.5"/>
          <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none"/>
          <line x1="12" y1="12" x2="18.3" y2="5.7"/>
          <circle cx="16.5" cy="8" r="1.1" fill="currentColor" stroke="none"/>
        </svg>
      </div>
      <div>
        <h1>USOM Feeds</h1>
        <div class="tagline">Zararlı domain ve IP listesi · txt format</div>
      </div>
    </div>
    <span id="status" class="pill"><span class="dot"></span><span id="status-text">kontrol ediliyor</span></span>
  </div>

  <div class="stats">
    <div class="stat"><div class="v">__N_DOM__</div><div class="l">Domain</div></div>
    <div class="stat"><div class="v">__N_CRIT__</div><div class="l">Kritik Domain (≥7)</div></div>
    <div class="stat"><div class="v">__N_IP__</div><div class="l">IPv4 Adresi</div></div>
    <div class="stat"><div class="v" id="age">—</div><div class="l">Son Güncelleme</div></div>
  </div>

  <div class="card">
    <p class="card-title">Feed URL'leri</p>
    <div class="feed-item">
      <a class="feed-url" href="/domains.txt">https://usomfeeds.dalnet.tr/domains.txt</a>
      <button class="copy" data-copy="https://usomfeeds.dalnet.tr/domains.txt">kopyala</button>
    </div>
    <div class="feed-meta">Tam liste · __N_DOM__ kayıt · __SZ_DOM__</div>
    <div class="feed-item" style="margin-top:14px">
      <a class="feed-url" href="/domains_critical.txt">https://usomfeeds.dalnet.tr/domains_critical.txt</a>
      <button class="copy" data-copy="https://usomfeeds.dalnet.tr/domains_critical.txt">kopyala</button>
    </div>
    <div class="feed-meta">Kritiklik ≥ 7 · __N_CRIT__ kayıt · __SZ_CRIT__ · cihaz limiti dar olanlar için</div>
    <div class="feed-item" style="margin-top:14px">
      <a class="feed-url" href="/ips.txt">https://usomfeeds.dalnet.tr/ips.txt</a>
      <button class="copy" data-copy="https://usomfeeds.dalnet.tr/ips.txt">kopyala</button>
    </div>
    <div class="feed-meta">__N_IP__ kayıt · __SZ_IP__ · IPv4, numeric sıralı</div>
  </div>

  <div class="card">
    <p class="card-title">Entegrasyon</p>
    <div class="tabs" role="tablist">
      <button class="tab active" data-tab="forti">FortiGate</button>
      <button class="tab" data-tab="palo">Palo Alto</button>
      <button class="tab" data-tab="generic">Generic (curl)</button>
    </div>

    <div class="panel active" id="panel-forti">
      <p>FortiGate CLI'dan <strong>External Block List</strong> tanımla (GUI'de <em>System → Settings → CLI Console</em>):</p>
      <div class="code">
        <button class="copy" data-copy-pre>kopyala</button>
<pre>config system external-resource
    edit "usom-domains"
        set type domain
        set resource "https://usomfeeds.dalnet.tr/domains.txt"
        set refresh-rate 60
    next
    edit "usom-ips"
        set type address
        set resource "https://usomfeeds.dalnet.tr/ips.txt"
        set refresh-rate 60
    next
end</pre>
      </div>
      <p>Sonra bu resource'u <strong>DNS Filter profili</strong> veya <strong>Firewall Policy</strong>'sine ekle. GUI üzerinden: <em>Security Fabric → External Connectors → Create New → Threat Feeds</em>.</p>
    </div>

    <div class="panel" id="panel-palo">
      <p>GUI üzerinden:</p>
      <ol>
        <li><strong>Objects → External Dynamic Lists → Add</strong></li>
        <li><strong>Type:</strong> <code>Domain List</code> (domains.txt için) veya <code>IP List</code> (ips.txt için)</li>
        <li>
          <strong>Source:</strong>
          <div class="code" style="margin:10px 0">
            <button class="copy" data-copy="https://usomfeeds.dalnet.tr/domains.txt">kopyala</button>
<pre>https://usomfeeds.dalnet.tr/domains.txt</pre>
          </div>
        </li>
        <li><strong>Check for updates:</strong> <code>Hourly</code></li>
        <li><strong>Commit</strong>, sonra Security Policy veya DNS Security profilinde kullan</li>
      </ol>
    </div>

    <div class="panel" id="panel-generic">
      <p>Cron veya systemd timer ile saatlik indirme:</p>
      <div class="code">
        <button class="copy" data-copy-pre>kopyala</button>
<pre>curl -fsSL -o /etc/blocklists/usom-domains.txt \
  https://usomfeeds.dalnet.tr/domains.txt
curl -fsSL -o /etc/blocklists/usom-ips.txt \
  https://usomfeeds.dalnet.tr/ips.txt</pre>
      </div>
      <p>İndiren taraf <code>Last-Modified</code> / <code>ETag</code> destekliyorsa koşullu indirir; değişiklik yoksa bandwidth harcamaz.</p>
    </div>
  </div>

  <footer>
    Kaynak: <a href="https://siberguvenlik.gov.tr/zararli-baglantilar">siberguvenlik.gov.tr</a> ·
    Repo: <a href="https://github.com/yunuskargi/usomfeed">github.com/yunuskargi/usomfeed</a> ·
    Son build: <code>__UPDATED__</code><br>
    Resmi olmayan bir aynadır. Veri olduğu gibi sunulur, doğruluk veya erişilebilirlik garantisi verilmez.
  </footer>

</div>

<script>
(function(){
  const tabs = document.querySelectorAll('.tab');
  const panels = document.querySelectorAll('.panel');
  tabs.forEach(t => t.addEventListener('click', () => {
    tabs.forEach(x => x.classList.remove('active'));
    panels.forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('panel-' + t.dataset.tab).classList.add('active');
  }));

  document.querySelectorAll('.copy').forEach(btn => {
    btn.addEventListener('click', async () => {
      let text = btn.dataset.copy;
      if (btn.hasAttribute('data-copy-pre')) {
        text = btn.parentElement.querySelector('pre').innerText;
      }
      try {
        await navigator.clipboard.writeText(text);
        const original = btn.textContent;
        btn.textContent = 'kopyalandı';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1500);
      } catch (e) {}
    });
  });

  function formatAge(ms) {
    const m = Math.round(ms / 60000);
    if (m < 1) return 'az önce';
    if (m < 60) return m + ' dk önce';
    const h = Math.round(m / 60);
    if (h < 24) return h + ' sa önce';
    const d = Math.round(h / 24);
    return d + ' gün önce';
  }
  function updateStatus(lastMod) {
    const ageMs = Date.now() - lastMod.getTime();
    const ageH = ageMs / 3600000;
    const pill = document.getElementById('status');
    const txt  = document.getElementById('status-text');
    const ageEl = document.getElementById('age');
    pill.classList.remove('ok', 'warn', 'err');
    if (ageH < 24)       { pill.classList.add('ok');   txt.textContent = 'Güncel'; }
    else if (ageH < 72)  { pill.classList.add('warn'); txt.textContent = 'Gecikme'; }
    else                 { pill.classList.add('err');  txt.textContent = 'Eski'; }
    ageEl.textContent = formatAge(ageMs);
  }
  async function checkFreshness() {
    try {
      const r = await fetch('/domains.txt', { method: 'HEAD', cache: 'no-store' });
      const lm = r.headers.get('Last-Modified');
      if (lm) updateStatus(new Date(lm));
    } catch (e) {}
  }
  checkFreshness();
  setInterval(checkFreshness, 60000);
})();
</script>
</body>
</html>
"""


def write_index(path: pathlib.Path, n_dom: int, n_ip: int, n_crit: int,
                sz_dom: int, sz_ip: int, sz_crit: int) -> None:
    tr_tz = dt.timezone(dt.timedelta(hours=3))  # Türkiye sabit UTC+3 (2016'dan beri DST yok)
    updated = dt.datetime.now(tr_tz).strftime("%d.%m.%Y %H:%M TSİ")

    def fmt_size(n: int) -> str:
        if n >= 1024 * 1024:
            return f"{n/1024/1024:.2f} MB"
        if n >= 1024:
            return f"{n/1024:.1f} KB"
        return f"{n} B"

    html_str = (INDEX_TEMPLATE
        .replace("__N_DOM__",   f"{n_dom:,}")
        .replace("__N_CRIT__",  f"{n_crit:,}")
        .replace("__N_IP__",    f"{n_ip:,}")
        .replace("__SZ_DOM__",  fmt_size(sz_dom))
        .replace("__SZ_CRIT__", fmt_size(sz_crit))
        .replace("__SZ_IP__",   fmt_size(sz_ip))
        .replace("__UPDATED__", html.escape(updated)))
    path.write_bytes(html_str.encode("utf-8"))


if __name__ == "__main__":
    sys.exit(main())
