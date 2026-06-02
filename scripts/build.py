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


def write_index(path: pathlib.Path, n_dom: int, n_ip: int, sz_dom: int, sz_ip: int) -> None:
    updated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    h = html.escape
    body = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>USOM Zararlı Bağlantı Feed'i</title>
<meta name="description" content="T.C. Siber Güvenlik Başkanlığı zararlı domain ve IP listesinin FortiGate / Palo Alto uyumlu txt formatı.">
<style>
  :root {{
    --bg: #0e1116; --fg: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --card: #161b22; --border: #30363d; --code: #1f242c;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg:#ffffff; --fg:#1f2328; --muted:#656d76; --accent:#0969da; --card:#f6f8fa; --border:#d0d7de; --code:#eff2f5; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:var(--bg); color:var(--fg); }}
  .wrap {{ max-width: 760px; margin: 0 auto; padding: 48px 24px; }}
  h1 {{ margin: 0 0 8px; font-size: 28px; }}
  .sub {{ color: var(--muted); margin: 0 0 32px; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:20px; margin:16px 0; }}
  .card h2 {{ margin:0 0 8px; font-size:18px; }}
  .url {{ display:block; background:var(--code); padding:10px 12px; border-radius:6px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:14px; word-break:break-all; color:var(--accent); text-decoration:none; }}
  .url:hover {{ text-decoration:underline; }}
  .meta {{ color:var(--muted); font-size:13px; margin-top:10px; }}
  pre {{ background:var(--code); padding:14px; border-radius:6px; overflow-x:auto; font-size:13px; }}
  a {{ color:var(--accent); }}
  hr {{ border:none; border-top:1px solid var(--border); margin:32px 0; }}
  footer {{ color:var(--muted); font-size:13px; }}
</style>
</head>
<body>
<div class="wrap">

<h1>USOM Zararlı Bağlantı Feed'i</h1>
<p class="sub">T.C. Siber Güvenlik Başkanlığı zararlı domain ve IP listesinin FortiGate / Palo Alto uyumlu txt sürümü. Saatte bir güncellenir.</p>

<div class="card">
  <h2>domains.txt</h2>
  <a class="url" href="/domains.txt">https://usomfeeds.yunuskargi.com/domains.txt</a>
  <div class="meta">{n_dom:,} kayıt · {sz_dom/1024/1024:.2f} MB · alfabetik sıralı</div>
</div>

<div class="card">
  <h2>ips.txt</h2>
  <a class="url" href="/ips.txt">https://usomfeeds.yunuskargi.com/ips.txt</a>
  <div class="meta">{n_ip:,} kayıt · {sz_ip/1024:.1f} KB · numeric sıralı (IPv4)</div>
</div>

<p class="sub" style="margin-top:24px">Son güncelleme: <strong>{h(updated)}</strong></p>

<hr>

<h2 style="font-size:18px">FortiGate</h2>
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

<h2 style="font-size:18px">Palo Alto</h2>
<p>Objects → External Dynamic Lists → Add → Type: <code>Domain List</code> / <code>IP List</code>, Source: yukarıdaki URL, Check for updates: <code>Hourly</code>.</p>

<hr>

<footer>
  Kaynak: <a href="https://siberguvenlik.gov.tr/zararli-baglantilar">siberguvenlik.gov.tr</a> ·
  Repo: <a href="https://github.com/yunuskargi/usomfeed">github.com/yunuskargi/usomfeed</a> ·
  Resmi olmayan aynadır
</footer>

</div>
</body>
</html>
"""
    path.write_bytes(body.encode("utf-8"))


if __name__ == "__main__":
    sys.exit(main())
