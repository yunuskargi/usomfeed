# USOM Zararlı Bağlantı Feed'i

T.C. Siber Güvenlik Başkanlığı'nın (eski USOM) zararlı domain ve IP listesinin **FortiGate / Palo Alto** gibi sistemlere doğrudan beslenebilecek düz metin (`.txt`) sürümü.

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

## Yasal

- Kaynak: T.C. Siber Güvenlik Başkanlığı — <https://siberguvenlik.gov.tr>
- Resmi kullanım şartları: <https://siberguvenlik.gov.tr/yasal-uyarilar>
- Bu repo bağımsız bir aynadır, herhangi bir kuruma bağlı değildir
- Veri olduğu gibi sunulur, doğruluk veya erişilebilirlik garantisi verilmez

Sorun bildirimi: <https://github.com/yunuskargi/usomfeed/issues>
