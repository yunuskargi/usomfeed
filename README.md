# usomfeed

T.C. Siber Güvenlik Başkanlığı'nın (eski USOM) zararlı domain ve IP listesinin **FortiGate / Palo Alto / Squid / Pi-hole** gibi sistemlere doğrudan beslenebilecek düz metin (`.txt`) sürümü.

USOM 1 Haziran 2026 itibarıyla eski [`url-list.txt`](https://www.usom.gov.tr/duyurular/zararli-baglantilar-listesinde-yapilacak-degisiklik-hakkinda) yayınını durdurdu, yerine paginated JSON API getirdi. Bu repo o API'yi her saat çekip eski txt formatını üreten bir köprü.

> **Resmi olmayan bir aynadır.** Otoritatif kaynak: <https://siberguvenlik.gov.tr/zararli-baglantilar>

## Feed URL'leri

```
https://usomfeeds.yunuskargi.com/domains.txt
https://usomfeeds.yunuskargi.com/ips.txt
```

- **domains.txt** — satır başına bir domain, alfabetik sıralı (~450.000 kayıt, ~10 MB)
- **ips.txt** — satır başına bir IPv4, numeric sıralı (~14.000 kayıt, ~200 KB)
- UTF-8, LF satır sonu, BOM yok
- Saatte bir güncellenir, Cloudflare CDN üzerinden servis edilir

## Kullanım

### FortiGate

```
config system external-resource
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
end
```

Sonra DNS Filter profiline veya firewall policy'sine `external-resource` olarak ekle.

### Palo Alto Networks

**Objects → External Dynamic Lists → Add**

| Alan | Değer |
|---|---|
| Type | `Domain List` veya `IP List` |
| Source | yukarıdaki ilgili URL |
| Check for updates | `Hourly` |

Security Policy veya DNS Security'de kullan.

### Pi-hole

```
Settings → Adlists → Add a new adlist
URL: https://usomfeeds.yunuskargi.com/domains.txt
```

### curl / wget (genel)

```bash
curl -o /etc/blocklists/usom-domains.txt https://usomfeeds.yunuskargi.com/domains.txt
curl -o /etc/blocklists/usom-ips.txt     https://usomfeeds.yunuskargi.com/ips.txt
```

İndiren taraf `Last-Modified` / `ETag` header'larını destekliyorsa `If-Modified-Since` ile koşullu indirir; değişiklik yoksa bandwidth harcamaz.

## Güncelleme döngüsü

```
USOM API güncellemesi
       │ (en geç 1 saat — sunucu kendi yanıtını cache'liyor)
       ▼
Saatlik cron → API'den tam liste çekilir → R2'ye yazılır
       │
       ▼
Cloudflare edge cache (1 saat)
       │
       ▼
Sizin sisteminiz (refresh-rate 60 dk)
```

USOM bir kayıt eklediğinde / kaldırdığında feed'inize en geç **~2-3 saat** içinde yansır.

## Güvenlik

Pipeline her koşuda sanity check yapar: çekilen domain sayısı 1000'in, IP sayısı 100'ün altına düşerse build durdurulur ve R2'deki son sağlam dosyalar dokunulmaz. Upstream çökse veya API şeması değişse de mevcut feed servisi kesintisiz devam eder.

## Yasal

- Kaynak: T.C. Siber Güvenlik Başkanlığı — <https://siberguvenlik.gov.tr>
- Resmi kullanım şartları: <https://siberguvenlik.gov.tr/yasal-uyarilar>
- Bu repo bağımsız bir aynadır, herhangi bir kuruma bağlı değildir
- Veri olduğu gibi sunulur, doğruluk veya erişilebilirlik garantisi verilmez

Sorun bildirimi: <https://github.com/yunuskargi/usomfeed/issues>
