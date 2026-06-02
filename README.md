# usomfeed

T.C. Siber Güvenlik Başkanlığı'nın (eski USOM) yeni API'sinden zararlı domain ve IP listesini çekip Fortinet **External Block List** / Palo Alto **External Dynamic List** uyumlu düz metin (txt) feed'leri olarak üreten ve Cloudflare R2 üzerinden yayınlayan otomasyon.

> **Resmi olmayan bir aynadır.** Otoritatif kaynak: <https://siberguvenlik.gov.tr/zararli-baglantilar>

## Ne yapıyor

Saatte bir GitHub Actions koşusu:

1. `https://siberguvenlik.gov.tr/api/address/index` API'sini `type=domain` ve `type=ip` için baştan sona çeker (`per-page=1000`, paralel sayfalama, retry/backoff).
2. Çıktıları temizler/dedupe eder, sıralar:
   - `out/domains.txt` — satır başına bir domain
   - `out/ips.txt` — satır başına bir IPv4
3. Cloudflare R2 bucket'ına `aws s3 sync --delete` ile yükler.
4. Cloudflare custom domain üzerinden public olarak servis edilir.

Tam yenileme yapılır (incremental değil) — upstream'den kaldırılan kayıtların feed'den de düşmesi için bu şart.

## Kurulum

### 1. Cloudflare R2

1. Cloudflare hesabında **R2** → bucket oluştur (örn. `usom-feeds`).
2. **R2 → Settings → Custom Domains** → kendi domain'inin alt domain'ini bağla (örn. `feeds.example.com`). DNS, SSL, CDN otomatik kurulur. `pub-xxx.r2.dev` public URL'ini production'da kullanma.
3. **R2 → Manage API Tokens** → "Object Read & Write" izniyle, sadece bu bucket'a scope'lu yeni token oluştur. Açılan ekrandaki `Access Key ID`, `Secret Access Key` ve hesap sayfasındaki `Account ID` değerlerini sakla.

### 2. GitHub Secrets

Repo → Settings → Secrets and variables → Actions:

| Secret | Değer |
|---|---|
| `R2_ACCOUNT_ID` | Cloudflare Account ID |
| `R2_ACCESS_KEY_ID` | R2 API token Access Key |
| `R2_SECRET_ACCESS_KEY` | R2 API token Secret |
| `R2_BUCKET` | Bucket adı (örn. `usom-feeds`) |

### 3. Workflow'u tetikle

İlk koşuyu **Actions → update-feeds → Run workflow** ile manuel başlat. Sonrasında saatte bir otomatik çalışır.

## Lokal test

```bash
pip install requests
python scripts/build.py
# out/domains.txt ve out/ips.txt üretilir
wc -l out/*.txt
```

## Feed URL'leri (örnek)

```
https://feeds.example.com/domains.txt
https://feeds.example.com/ips.txt
```

### Fortinet (FortiGate External Block List)

```
config system external-resource
    edit "usom-domains"
        set type domain
        set resource "https://feeds.example.com/domains.txt"
        set refresh-rate 60
    next
    edit "usom-ips"
        set type address
        set resource "https://feeds.example.com/ips.txt"
        set refresh-rate 60
    next
end
```

### Palo Alto (External Dynamic List)

- **Objects → External Dynamic Lists → Add**
- Type: `Domain List` (domains.txt) veya `IP List` (ips.txt)
- Source: yukarıdaki URL'ler
- Check for updates: `Hourly`

## Performans / maliyet

- Feed boyutu: toplam ~10 MB. R2 free tier'ı (10 GB storage, sınırsız egress) ile yıllarca ücretsiz çalışır.
- Edge cache TTL 5 dk (workflow `cache-control: public, max-age=300` set ediyor). Cihazlar genelde saatte bir poll'lar, conditional GET (`If-Modified-Since`) destekler — değişiklik yoksa indirme yapılmaz.

## Güvenlik

Pipeline bir sanity check uygular: domain sayısı 1000'in, IP sayısı 100'ün altına düşerse build patlar ve R2'ye boş/yanlış dosya push'lanmaz. Upstream çöktüğünde firewall'larınızdaki son sağlam feed kalır.

## Yasal

- Kaynak: T.C. Siber Güvenlik Başkanlığı, <https://siberguvenlik.gov.tr>
- API kullanım şartları: <https://siberguvenlik.gov.tr/yasal-uyarilar>
- Bu repo resmi değildir, herhangi bir kuruma bağlı değildir. Veri olduğu gibi sunulur, doğruluk/erişilebilirlik garantisi verilmez.
