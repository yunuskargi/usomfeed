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


def fetch_all(addr_type: str) -> set[str]:
    first = fetch_page(addr_type, 1)
    total = int(first.get("totalCount", 0))
    page_count = int(first.get("pageCount", 1))
    entries: set[str] = set()
    entries.update(_extract(first))
    print(f"[info] {addr_type}: totalCount={total} pageCount={page_count}", file=sys.stderr)

    if page_count <= 1:
        return entries

    pages = list(range(2, page_count + 1))
    with ThreadPoolExecutor(max_workers=PARALLELISM) as pool:
        futures = {pool.submit(fetch_page, addr_type, p): p for p in pages}
        for fut in as_completed(futures):
            page = futures[fut]
            data = fut.result()
            entries.update(_extract(data))
            if page % 25 == 0:
                print(f"[info] {addr_type}: fetched page {page}/{page_count} (running unique={len(entries)})", file=sys.stderr)

    return entries


def _extract(payload: dict) -> list[str]:
    out = []
    for m in payload.get("models", []) or []:
        v = (m.get("url") or "").strip().lower()
        if v:
            out.append(v)
    return out


def write_domains(entries: set[str], path: pathlib.Path) -> int:
    cleaned: set[str] = set()
    for d in entries:
        # upstream sometimes ships "www.foo.com/path" or "foo.com:8080"; trim to bare host
        host = d.split("/", 1)[0].split(":", 1)[0].rstrip(".")
        if host and "." in host and " " not in host:
            cleaned.add(host)
    return _write_sorted(cleaned, path)


def write_ips(entries: set[str], path: pathlib.Path) -> int:
    cleaned: set[str] = set()
    for v in entries:
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

    write_index(OUT_DIR / "index.html", n_dom, n_ip,
                (OUT_DIR / "domains.txt").stat().st_size,
                (OUT_DIR / "ips.txt").stat().st_size)
    print("[ok] wrote index.html", file=sys.stderr)

    return 0


INDEX_TEMPLATE = r"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>USOM Zararlı Bağlantı Feed'i</title>
<meta name="description" content="T.C. Siber Güvenlik Başkanlığı zararlı domain ve IP listesinin FortiGate / Palo Alto uyumlu txt formatı. Saatte bir güncellenir.">
<style>
  :root {
    --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --accent:#58a6ff;
    --card:#161b22; --border:#30363d; --code:#0d1117; --code-border:#21262d;
    --ok:#3fb950; --warn:#d29922; --err:#f85149;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#ffffff; --fg:#1f2328; --muted:#59636e; --accent:#0969da;
            --card:#f6f8fa; --border:#d1d9e0; --code:#f6f8fa; --code-border:#d1d9e0;
            --ok:#1a7f37; --warn:#9a6700; --err:#cf222e; }
  }
  *{box-sizing:border-box}
  html,body{margin:0;padding:0}
  body{font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,sans-serif;background:var(--bg);color:var(--fg)}
  .wrap{max-width:880px;margin:0 auto;padding:40px 20px 80px}
  header{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:8px}
  h1{margin:0;font-size:26px;letter-spacing:-.01em}
  .sub{color:var(--muted);margin:0 0 28px}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;background:var(--card);border:1px solid var(--border)}
  .pill .dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
  .pill.ok .dot{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 25%,transparent)}
  .pill.warn .dot{background:var(--warn)}
  .pill.err .dot{background:var(--err)}

  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:24px 0}
  .stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}
  .stat .v{font-size:24px;font-weight:700;letter-spacing:-.02em}
  .stat .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}

  .card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px;margin:16px 0}
  .card h2{margin:0 0 12px;font-size:16px}
  .urlrow{display:flex;align-items:center;gap:8px;margin:8px 0}
  .url{flex:1;background:var(--code);border:1px solid var(--code-border);padding:10px 12px;border-radius:6px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;word-break:break-all;color:var(--accent);text-decoration:none;display:block}
  .url:hover{text-decoration:underline}
  .meta{color:var(--muted);font-size:12px;margin-top:6px}

  .tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);margin:-4px -4px 16px;padding:0 4px;overflow-x:auto}
  .tab{background:none;border:none;color:var(--muted);padding:10px 14px;cursor:pointer;font-size:14px;font-weight:500;border-bottom:2px solid transparent;margin-bottom:-1px;white-space:nowrap;font-family:inherit}
  .tab:hover{color:var(--fg)}
  .tab.active{color:var(--accent);border-bottom-color:var(--accent)}
  .panel{display:none}
  .panel.active{display:block}
  .panel p{margin:0 0 12px}
  .panel ol{margin:0 0 12px;padding-left:20px}
  .panel li{margin:6px 0}

  .code{position:relative}
  .code pre{margin:0;background:var(--code);border:1px solid var(--code-border);border-radius:6px;padding:14px 14px;overflow-x:auto;font-size:13px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .copy{position:absolute;top:8px;right:8px;background:var(--card);border:1px solid var(--border);color:var(--muted);font-size:11px;padding:4px 8px;border-radius:5px;cursor:pointer;font-family:inherit;transition:all .15s}
  .copy:hover{color:var(--fg);border-color:var(--accent)}
  .copy.copied{color:var(--ok);border-color:var(--ok)}

  code{background:var(--code);padding:2px 6px;border-radius:4px;font-size:.92em;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  a{color:var(--accent)}
  hr{border:none;border-top:1px solid var(--border);margin:32px 0}
  footer{color:var(--muted);font-size:12px;line-height:1.7}
</style>
</head>
<body>
<div class="wrap">

<header>
  <h1>USOM Zararlı Bağlantı Feed'i</h1>
  <span id="status" class="pill"><span class="dot"></span><span id="status-text">kontrol ediliyor…</span></span>
</header>
<p class="sub">T.C. Siber Güvenlik Başkanlığı'nın yayınladığı zararlı domain ve IP listesinin FortiGate / Palo Alto / Squid / Pi-hole gibi sistemlere doğrudan beslenebilecek <code>.txt</code> sürümü. Saatte bir güncellenir.</p>

<div class="stats">
  <div class="stat"><div class="v">__N_DOM__</div><div class="l">domain</div></div>
  <div class="stat"><div class="v">__N_IP__</div><div class="l">IPv4</div></div>
  <div class="stat"><div class="v">__SZ_TOTAL__</div><div class="l">toplam boyut</div></div>
  <div class="stat"><div class="v" id="age">—</div><div class="l">son güncelleme</div></div>
</div>

<div class="card">
  <h2>Feed URL'leri</h2>
  <div class="urlrow">
    <a class="url" href="/domains.txt">https://usomfeeds.yunuskargi.com/domains.txt</a>
    <button class="copy" data-copy="https://usomfeeds.yunuskargi.com/domains.txt">kopyala</button>
  </div>
  <div class="meta">__N_DOM__ kayıt · __SZ_DOM__ · alfabetik sıralı</div>
  <div class="urlrow" style="margin-top:16px">
    <a class="url" href="/ips.txt">https://usomfeeds.yunuskargi.com/ips.txt</a>
    <button class="copy" data-copy="https://usomfeeds.yunuskargi.com/ips.txt">kopyala</button>
  </div>
  <div class="meta">__N_IP__ kayıt · __SZ_IP__ · numeric sıralı (IPv4)</div>
</div>

<div class="card">
  <h2>Entegrasyon</h2>
  <div class="tabs" role="tablist">
    <button class="tab active" data-tab="forti">FortiGate</button>
    <button class="tab" data-tab="palo">Palo Alto</button>
    <button class="tab" data-tab="generic">Generic (curl)</button>
  </div>

  <div class="panel active" id="panel-forti">
    <p>SSH ile <code>External Block List</code> tanımla:</p>
    <div class="code">
      <button class="copy" data-copy-pre>kopyala</button>
<pre>config system external-resource
    edit "usom-domains"
        set type domain
        set resource "https://usomfeeds.yunuskargi.com/domains.txt"
        set refresh-rate 60
    next
    edit "usom-ips"
        set type address
        set resource "https://usomfeeds.yunuskargi.com/ips.txt"
        set refresh-rate 60
    next
end</pre>
    </div>
    <p>Sonra bu resource'u <strong>DNS Filter profili</strong> veya <strong>Firewall Policy</strong>'sine ekle. GUI üzerinden: Security Fabric → External Connectors → Create New → Threat Feeds.</p>
  </div>

  <div class="panel" id="panel-palo">
    <p>GUI üzerinden:</p>
    <ol>
      <li><strong>Objects → External Dynamic Lists → Add</strong></li>
      <li><strong>Type:</strong> <code>Domain List</code> (domains.txt için) veya <code>IP List</code> (ips.txt için)</li>
      <li><strong>Source:</strong>
        <div class="code" style="margin:8px 0">
          <button class="copy" data-copy="https://usomfeeds.yunuskargi.com/domains.txt">kopyala</button>
          <pre>https://usomfeeds.yunuskargi.com/domains.txt</pre>
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
  https://usomfeeds.yunuskargi.com/domains.txt
curl -fsSL -o /etc/blocklists/usom-ips.txt \
  https://usomfeeds.yunuskargi.com/ips.txt</pre>
    </div>
    <p>İndiren taraf <code>Last-Modified</code> / <code>ETag</code> destekliyorsa koşullu indirir; değişiklik yoksa bandwidth harcamaz.</p>
  </div>
</div>

<hr>

<footer>
  Kaynak: <a href="https://siberguvenlik.gov.tr/zararli-baglantilar">siberguvenlik.gov.tr</a> ·
  Repo: <a href="https://github.com/yunuskargi/usomfeed">github.com/yunuskargi/usomfeed</a> ·
  Son build: <code>__UPDATED__</code><br>
  Resmi olmayan bir aynadır. Veri olduğu gibi sunulur, doğruluk veya erişilebilirlik garantisi verilmez.
</footer>

</div>

<script>
(function(){
  // Tabs
  const tabs = document.querySelectorAll('.tab');
  const panels = document.querySelectorAll('.panel');
  tabs.forEach(t => t.addEventListener('click', () => {
    tabs.forEach(x => x.classList.remove('active'));
    panels.forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('panel-' + t.dataset.tab).classList.add('active');
  }));

  // Copy buttons
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

  // Live freshness from Last-Modified header on domains.txt
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
    if (ageH < 2)        { pill.classList.add('ok');   txt.textContent = 'çalışıyor'; }
    else if (ageH < 24)  { pill.classList.add('warn'); txt.textContent = 'gecikme'; }
    else                 { pill.classList.add('err');  txt.textContent = 'eski feed'; }
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


def write_index(path: pathlib.Path, n_dom: int, n_ip: int, sz_dom: int, sz_ip: int) -> None:
    updated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_mb = (sz_dom + sz_ip) / 1024 / 1024

    def fmt_size(n: int) -> str:
        if n >= 1024 * 1024:
            return f"{n/1024/1024:.2f} MB"
        if n >= 1024:
            return f"{n/1024:.1f} KB"
        return f"{n} B"

    html_str = (INDEX_TEMPLATE
        .replace("__N_DOM__",   f"{n_dom:,}")
        .replace("__N_IP__",    f"{n_ip:,}")
        .replace("__SZ_DOM__",  fmt_size(sz_dom))
        .replace("__SZ_IP__",   fmt_size(sz_ip))
        .replace("__SZ_TOTAL__", f"{total_mb:.1f} MB")
        .replace("__UPDATED__", html.escape(updated)))
    path.write_bytes(html_str.encode("utf-8"))


if __name__ == "__main__":
    sys.exit(main())
