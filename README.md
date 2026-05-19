# 🚀 USOM List Service (API -> Düz Metin Köprüsü)

USOM (Ulusal Siber Olaylara Müdahale Merkezi), zararlı bağlantılar listesini (IP ve Domain) 1 Haziran 2026 itibarıyla statik `.txt` dosyası yerine sadece **API** üzerinden sunmaya başlayacaktır.

**USOM List Service**, doğrudan karmaşık API entegrasyonu (özellikle sayfalama, rate-limit vb. özellikleri) desteklemeyen, **External Dynamic List (EDL)** olarak sadece düz metin (plain text) formatındaki IP ve Domain listelerini tüketebilen Güvenlik Duvarı (Palo Alto, Fortinet vb.), WAF ve Mail Gateway'ler için geliştirilmiş **açık kaynaklı, yüksek performanslı bir ara katmandır (middleware)**.

## ✨ Öne Çıkan Özellikler

- **Kesintisiz Cihaz Entegrasyonu:** Güvenlik cihazlarınız, konfigürasyon değişikliğine gerek duymadan `http://sunucu_ip:8000/usom-ips` üzerinden geleneksel formattaki (CR-LF satır sonu) listeyi çekebilir.
- **Akıllı Senkronizasyon (Delta & Full):** APScheduler kullanılarak oluşturulan arka plan görevleri ile veri çekim işlemleri tam otomatik hale getirilmiştir.
  - *IP Saatlik Delta Sync:* Yalnızca yeni eklenen IP adreslerini çekerek API limitlerini yormaz. (Her saatin 5. dakikasında çalışır).
  - *Domain Saatlik Delta Sync:* Yalnızca yeni eklenen Domain adreslerini çeker. (Her saatin 10. dakikasında çalışır).
  - *IP Haftalık Full Sync:* Veritabanı tutarlılığını sağlamak için baştan sona tüm IP listesini kontrol eder. (Her Pazar gecesi 03:00'te çalışır).
  - *Domain Haftalık Full Sync:* Baştan sona tüm Domain listesini senkronize eder. (Her Pazar gecesi 04:00'te çalışır).
  - *Veri Çekim Düzeni (Rate Limit Koruması):* USOM API'sinin kısıtlamalarına takılmamak adına eşzamanlı HTTP istek sayısı (Semaphore) limitlenmiş ve başarısız isteklere karşı üstel bekleme (exponential backoff retry) mekanizması eklenmiştir. Delta (saatlik) senkronizasyonlarda, sayfalar taranırken daha önceden veritabanında olan bir kayda rastlandığında gereksiz API çağrısı yapmamak için işlem erken sonlandırılır (early stop).
- **CrowdStrike Falcon Entegrasyonu (Opsiyonel):** USOM'dan çekilen zararlı IP ve Domain'leri asenkron olarak CrowdStrike IOC veritabanına otomatik basar. (Whitelist özelliği ile false-positive'leri engeller).
- **Yüksek Performans:** Python FastAPI, `aiosqlite` (Async SQLite) ve `httpx` kullanılarak asenkron mimaride geliştirilmiştir.

## 🛠️ Kurulum

Projeyi **Docker** veya doğrudan **Systemd** servisi (Host üzerinde) olarak çalıştırabilirsiniz.

### 1. Docker ile Kurulum (Önerilen)

```bash
git clone https://github.com/KULLANICI_ADINIZ/USOMListService.git
cd USOMListService

# Ortam değişkenlerini kopyalayın
cp .env.example .env

# Docker-compose ile arka planda başlatın
docker-compose up -d --build
```
Servis, 8000 portunda dinlemeye başlayacaktır. Veritabanı `usom_ips.db` olarak dışarıya (volume) map edilir.

### 2. Systemd ile Host Üzerinde Kurulum

Debian/Ubuntu tabanlı bir sunucuda projeyi direkt servis olarak ayağa kaldırmak için:

```bash
git clone https://github.com/KULLANICI_ADINIZ/USOMListService.git
cd USOMListService
sudo ./deploy.sh
```
Bu script gerekli paketleri kuracak, `venv` oluşturacak, `.env` dosyasını ayarlayacak ve `usom-list-service` adlı systemd servisini başlatacaktır.

## ⚙️ Konfigürasyon (`.env`)

Eğer CrowdStrike entegrasyonunu kullanmak **istemiyorsanız**, `.env` dosyasını boş bırakabilir veya içerisindeki `FALCON_CLIENT_ID` satırlarını silebilirsiniz. Sistem CrowdStrike olmadan sadece web sunucusu olarak çalışmaya devam edecektir.

```ini
# .env dosyası
FALCON_CLIENT_ID="YOUR_CLIENT_ID_HERE"
FALCON_CLIENT_SECRET="YOUR_CLIENT_SECRET_HERE"
FALCON_IOC_ACTION="prevent" # prevent (engelle) veya detect (sadece alarm)
```

## 📡 API Uç Noktaları (Endpoints)

Servis ayağa kalktığında aşağıdaki uç noktalara hizmet verir:

| Endpoint | Metot | Açıklama |
|---|---|---|
| `/usom-ips` | GET | Zararlı IP adreslerini düz metin (plain-text, satır başı bir IP) formatında döner. Firewall'lar (EDL) için kullanılır. |
| `/usom-domains` | GET | Zararlı Domain adreslerini düz metin formatında döner. |
| `/health` | GET | Servis sağlığı, uptime, veritabanındaki toplam kayıt sayısı, CrowdStrike bağlantı durumu ve son sync zamanları gibi detaylı metrikleri (JSON) döner. |
| `/sync/delta` | POST | Manuel olarak saatlik "Delta Sync" (sadece yeniler) görevini tetikler. |
| `/sync/full` | POST | Manuel olarak tam senkronizasyon görevini tetikler. |
| `/sync/crowdstrike` | POST | Gönderilmemiş IP ve Domain'leri manuel olarak CrowdStrike'a basar. |

## 🛡️ Güvenlik Cihazı (Firewall) Entegrasyon Örneği

Örneğin **Palo Alto Networks** üzerinde bir EDL (External Dynamic List) tanımlamak için:
1. Objects > External Dynamic Lists menüsüne gidin.
2. Type olarak **IP List** veya **Domain List** seçin.
3. Source (URL) kısmına: `http://<sunucu_ip>:8000/usom-ips` (veya `usom-domains`) yazın.
4. Check for updates (Senkronizasyon) periyodunu **Hourly** (Saatlik) olarak ayarlayın.

## 📝 Lisans

Bu proje MIT Lisansı ile lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakabilirsiniz.
