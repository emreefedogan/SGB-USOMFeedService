"""
USOM Tehdit İstihbaratı Servisi (USOMListService)
=================================================

USOM (Ulusal Siber Olaylara Müdahale Merkezi) API'sinden zararlı IP adreslerini
asenkron olarak çekip, güvenlik cihazlarının (Firewall, WAF, Mail Gateway)
doğrudan tüketebileceği plain-text formatında sunan FastAPI mikroservisi.

Mimari Katmanlar:
    1. Veri Erişim Katmanı  → aiosqlite ile SQLite (kalıcılık)
    2. Veri Çekme Katmanı   → httpx + tenacity (async HTTP, retry)
    3. Zamanlayıcı Katmanı  → APScheduler AsyncIOScheduler (cron)
    4. Sunum Katmanı        → FastAPI endpoint (/usom-ips, text/plain)

Yazar : USOMListService
Tarih : 2026-05-13
"""

import asyncio
import json
import logging
import logging.handlers
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from html import escape
import os
from pathlib import Path
import time
from typing import Optional

from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

import aiosqlite
import httpx
from apscheduler.events import (
    EVENT_JOB_ERROR,
    EVENT_JOB_MAX_INSTANCES,
    EVENT_JOB_MISSED,
)
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

# ─────────────────────────────────────────────
# Yapılandırma Sabitleri
# ─────────────────────────────────────────────
USOM_BASE_URL = "https://siberguvenlik.gov.tr/api/address/index"
DATABASE_PATH = "usom_ips.db"

# Gösterge panosu şablonu — main.py'ın yanındaki templates/ dizininde.
# Mutlak yol kullanılır; servis farklı bir çalışma dizininden başlatılsa da bulunur.
DASHBOARD_PATH = Path(__file__).resolve().parent / "templates" / "dashboard.html"

# ── Zararlı yazılım hash kaynağı: abuse.ch MalwareBazaar ──
# USOM hash yayınlamıyor (API'de type=hash/md5/sha256 boş döner), bu yüzden
# hash istihbaratı ayrı bir kaynaktan alınır. "recent" dökümü son ~48 saati
# kapsar ve API anahtarı gerektirmez; kalıcı arşiv yerel veritabanında birikir.
MALWAREBAZAAR_CSV_URL = "https://bazaar.abuse.ch/export/csv/recent/"
MALWAREBAZAAR_TIMEOUT = 120.0     # Döküm ~600 KB, normal HTTP_TIMEOUT yetmeyebilir
# CSV kolon sırası (abuse.ch, başlıksız): doğrulanmış 2026-08-20
MB_COL_FIRST_SEEN = 0
MB_COL_SHA256 = 1
MB_COL_MD5 = 2
MB_COL_SHA1 = 3
MB_COL_REPORTER = 4
MB_COL_FILE_NAME = 5
MB_COL_FILE_TYPE = 6
MB_COL_MIME = 7
MB_COL_SIGNATURE = 8

# ── Hash gönderim politikası ──
#
# MalwareBazaar dökümü tek tip değil: 2026-08-20 ölçümünde 1.406 kaydın
# 298'i (%21,2) "signature = n/a", yani hiçbir zararlı yazılım ailesine
# eşleşmiyor. Bu "temiz" demek değil — MalwareBazaar yalnızca zararlı
# olduğu düşünülen örnekleri kabul ediyor, n/a "henüz sınıflandırılmadı"
# anlamına geliyor.
#
# Ancak hash aksiyonu "prevent": gönderilen bir hash'in çalıştırılması
# kurum genelinde engellenir. Sınıflandırılmamış bir örneğin meşru bir
# dosyayla çakışması hâlinde sonuç, tüm uç noktalarda o dosyanın
# çalışmaması olur. Gözlemlenen vaka: anonim olarak, imzasız gönderilmiş
# "cmd.exe" adlı bir dosyanın hash'i (8dd1ebb0...). CrowdStrike uyarı
# döndürüp isteği reddettiği için kaza yaşanmadı.
#
# Bu yüzden yalnızca ailesi bilinen örnekler gönderilir. Kalanlar
# veritabanında arşivlenir (arama ve /lookup çalışmaya devam eder) ama
# gönderim kuyruğuna hiç girmezler.
MB_UNSIGNED_VALUES = {"", "n/a", "na", "none", "null", "unknown"}

# Dosya adı bu listedeyse imzası ne olursa olsun gönderilmez.
# İkinci savunma hattı: CrowdStrike'ın "yaygın uygulama olabilir" uyarısına
# güvenmek yerine kendi tarafımızda da eleriz. Yanlış pozitifin maliyeti
# (kurum genelinde bir sistem ikilisinin çalışmaması) kaçırılan bir
# göstergenin maliyetinden kat kat yüksek.
MB_SYSTEM_BINARIES = {
    # Windows kabuk / betik çalıştırıcıları
    "cmd.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "hh.exe",
    # LOLBins — saldırganlar kötüye kullanır ama dosyanın kendisi meşrudur
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe",
    "bitsadmin.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "msbuild.exe", "mavinject.exe", "forfiles.exe", "wmic.exe",
    "schtasks.exe", "at.exe", "sc.exe", "net.exe", "net1.exe",
    "reg.exe", "tasklist.exe", "taskkill.exe", "whoami.exe",
    # Çekirdek Windows süreçleri
    "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "services.exe", "smss.exe", "wininit.exe", "dwm.exe", "conhost.exe",
    "spoolsv.exe", "taskhostw.exe", "runtimebroker.exe", "dllhost.exe",
    "werfault.exe", "searchindexer.exe", "ctfmon.exe", "notepad.exe",
    # Yaygın uygulamalar ve çalışma zamanları
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "outlook.exe", "excel.exe", "winword.exe", "powerpnt.exe",
    "java.exe", "javaw.exe", "python.exe", "pythonw.exe", "node.exe",
    "curl.exe", "wget.exe", "7z.exe", "winrar.exe", "putty.exe",
    "teams.exe", "onedrive.exe", "acrobat.exe", "acrord32.exe",
    # Unix tarafı
    "bash", "sh", "dash", "zsh", "python3", "perl", "curl", "wget",
    "busybox", "systemd", "init", "sshd", "cron",
}
# ── Brandefense Threat Intelligence ──
# Kimlik doğrulama: authorization: Bearer <key>
# Doğrulanmış 2026-08-20: ioc_type ∈ {ip_address, domain, url, hash},
# size ≤ 1000, sayfalama cursor tabanlı (yanıttaki "next" URL'i).
#
# hash ve url bilinçli olarak ÇEKİLMİYOR:
#   • hash → örneklemin %99'u abusech_bazaar, yani zaten doğrudan
#     çektiğimiz MalwareBazaar. Üstelik %99'u yalnızca MD5 ve kayıtta
#     zararlı yazılım ailesi alanı yok; bu yüzden imzasız hash'leri
#     göndermeme politikası (hash_push_block_reason) uygulanamaz.
#     Beslemeyi almak, kapatılan yanlış pozitif kapısını geri açardı.
#   • url → CrowdStrike'ın IOC tipleri arasında URL yok
#     (domain/ipv4/ipv6/md5/sha256).
BRANDEFENSE_BASE_URL = "https://api.brandefense.io/api/v1/threat-intelligence/iocs"
BRANDEFENSE_PAGE_SIZE = 500        # size=1000 kabul ediliyor ama API yavaşlıyor
BRANDEFENSE_TIMEOUT = 60.0
BRANDEFENSE_PERIOD = "24h"         # saatlik görev için pencere: 24h | 7d
# Sayfa üst sınırı: bir arıza ya da beklenmedik hacim yüzünden tek turda
# on binlerce IOC çekilip CrowdStrike kotasının tükenmesini engeller.
# Sınıra ulaşılırsa log'a yazılır — sessizce kırpılmaz.
BRANDEFENSE_MAX_PAGES = 40
# API yük altında 503 döndürüyor; deneme aralarında bekleme gerekiyor.
BRANDEFENSE_RETRIES = 4
BRANDEFENSE_PAGE_DELAY = 0.8       # saniye, sayfalar arası nezaket beklemesi
# Kaç ardışık sayfa YENİ kayıt getirmezse çekim durdurulsun.
# Kayıtlar yeniden eskiye sıralı, dolayısıyla bilinen bölgeye girildiğinde
# devam etmenin faydası yok. 1 değil 2: iki beslemenin çakıştığı bir
# sayfa tesadüfen tamamen bilinen kayıtlardan oluşabilir, hemen durmak
# arkasındaki yeni kayıtları kaçırırdı.
BRANDEFENSE_STALE_PAGES = 2

# Gösterge kaynakları (veritabanındaki source kolonu)
SOURCE_USOM = "usom"
SOURCE_BRANDEFENSE = "brandefense"
SOURCE_MALWAREBAZAAR = "malwarebazaar"
# Yalnızca eski 'malicious_urls' tablosundan gelen kayıtlar için. Bu kaynak
# hiçbir zaman YAZILMAZ; 14 Mayıs 2026'da kaldırılan URL ayrıştırma yolunun
# geride bıraktığı satırları panoda ayırt edebilmek için var.
SOURCE_LEGACY_URL = "legacy-url"

# ── Saklama (retention) politikası ──
#
# CrowdStrike tenant başına 1 milyon gösterge kabul ediyor. Sınır dolduğunda
# YENİ gösterge yazılamaz: her gönderim "Limit of 1 million indicators
# reached" ile reddedilir ve en güncel tehditler EDR'a hiç ulaşmaz. Yani
# eski göstergeleri tutmanın bedeli, yenilerinin engellenmemesidir.
#
# TTL kaynağın NE OLDUĞUNA göre belirlenir, hepsine aynı sayı verilemez:
#
#   • Brandefense saatlik olarak 24 saatlik kayan pencere yayınlıyor, yani
#     "son gözlemler" beslemesi. Bir kez görülüp bir daha raporlanmayan
#     IOC doğal olarak bayatlar. Üstelik en hızlı büyüyen kaynak bu
#     (~10K/gün); sınırlanmazsa tek başına tenant'ı doldurur.
#
#   • MalwareBazaar "recent" dökümü de kayan pencere; aynı mantık geçerli.
#
#   • USOM ise kayan pencere DEĞİL, güncel durum listesi: API'nin döndüğü
#     totalCount o an yayınlanan tüm göstergeleri kapsıyor. Mayıs'ta
#     eklenmiş bir domain bugün hâlâ listede olabilir ve çoğu öyle.
#     Yaşa göre silmek, hâlâ yayınlanan bir tehdidin korumasını
#     kaldırmak olurdu. Bu yüzden USOM varsayılanı 0 = ASLA SİLME.
#
# 0 verilen kaynak saklama işleminde hiç işlenmez.
#
# Bu blok logger kurulmadan önce çalışıyor (logger satır ~540'ta tanımlanıyor),
# bu yüzden yapılandırma hataları doğrudan log'a yazılamaz; toplanıp açılışta
# lifespan içinde basılır. Sessizce yutmak kabul edilemez — yanlış yazılmış
# bir TTL fark edilmeden varsayılana düşerse, operatör beklediğinden farklı
# bir politikayla çalıştığını hiç öğrenemez.
_CONFIG_WARNINGS: list[str] = []


def _retention_days(source: str, default: int) -> int:
    raw = os.getenv(f"RETENTION_DAYS_{source.upper()}", str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        _CONFIG_WARNINGS.append(
            f"RETENTION_DAYS_{source.upper()}='{raw}' sayı değil, "
            f"varsayılan {default} gün kullanılacak."
        )
        return default
    if value < 0:
        _CONFIG_WARNINGS.append(
            f"RETENTION_DAYS_{source.upper()}={value} negatif, 0 (asla silme) "
            f"olarak yorumlandı."
        )
        return 0
    return value


RETENTION_DAYS = {
    SOURCE_BRANDEFENSE: _retention_days(SOURCE_BRANDEFENSE, 30),
    SOURCE_MALWAREBAZAAR: _retention_days(SOURCE_MALWAREBAZAAR, 30),
    SOURCE_USOM: _retention_days(SOURCE_USOM, 0),
}

# Bir kaynağın last_seen_at'i EN SIK ne kadar sürede tazelenebilir (gün).
#
# TTL bu süreden kısa olursa hâlâ yayınlanan göstergeler silinir: kayıt
# tazelenmeye fırsat bulamadan süresi dolar, silinir, bir sonraki sync
# geri ekler — sonsuz bir sil/ekle döngüsü ve arada koruma boşluğu.
#
# USOM 7 gün: saatlik delta_sync BİLİNEN bir göstergeye rastlayınca erken
# duruyor (rate-limit koruması), dolayısıyla mevcut kayıtlara hiç
# dokunmuyor. Tazeleme yalnızca haftalık full_sync'te oluyor — o da tüm
# sayfaları upsert ettiği için her yayındaki göstergeyi tazeliyor.
#
# Brandefense ve MalwareBazaar 1 gün: saatlik turlar çektikleri sayfadaki
# TÜM değerleri (bilinenler dâhil) upsert ediyor.
RETENTION_REFRESH_INTERVAL_DAYS = {
    SOURCE_USOM: 7,
    SOURCE_BRANDEFENSE: 1,
    SOURCE_MALWAREBAZAAR: 1,
}

for _src, _ttl in RETENTION_DAYS.items():
    _refresh = RETENTION_REFRESH_INTERVAL_DAYS.get(_src, 1)
    if 0 < _ttl < _refresh * 2:
        _CONFIG_WARNINGS.append(
            f"RETENTION_DAYS_{_src.upper()}={_ttl} gün, bu kaynağın "
            f"tazelenme aralığına ({_refresh} gün) göre ÇOK KISA. Hâlâ "
            f"yayında olan göstergeler silinip yeniden eklenebilir. "
            f"En az {_refresh * 2} gün önerilir."
        )

# Tek bir saklama turunda silinebilecek azami gösterge. Yanlış yapılandırılmış
# bir TTL'in (ya da bozuk bir last_seen_at'in) tenant'ı tek gecede boşaltmasını
# engelleyen emniyet freni. Sınıra ulaşılırsa log'a yazılır, sessizce kırpılmaz.
def _retention_cap() -> int:
    raw = (os.getenv("RETENTION_MAX_PER_RUN", "") or "").strip()
    if not raw:
        return 50000
    try:
        return max(1, int(raw))
    except ValueError:
        _CONFIG_WARNINGS.append(
            f"RETENTION_MAX_PER_RUN='{raw}' sayı değil, varsayılan 50000 kullanılacak."
        )
        return 50000


RETENTION_MAX_PER_RUN = _retention_cap()

# CrowdStrike toplu silme ayarları.
# Arama filtresi URL'de taşınıyor: ~18 bayt/değer × 150 ≈ 2,7 KB, yaygın
# 8 KB sınırının güvenli tarafında. Silme ise id listesiyle gövdeden gider.
CS_BULK_SEARCH_CHUNK = 150
CS_BULK_DELETE_CHUNK = 500
SOURCE_LABELS = {
    SOURCE_USOM: ("USOM", "Siber Güvenlik Başkanlığı"),
    SOURCE_BRANDEFENSE: ("Brandefense", "Threat Intelligence"),
    SOURCE_MALWAREBAZAAR: ("MalwareBazaar", "abuse.ch"),
    SOURCE_LEGACY_URL: ("USOM (eski URL kaydı)", "14 Mayıs 2026 öncesi"),
}


def looks_like_ipv4(value: str) -> bool:
    """
    Değer bir IPv4 adresi biçiminde mi?

    Eski URL tablosundaki ana makine adlarının bir kısmı alan adı değil
    doğrudan IP. Tipi yanlış tahmin etmek, silme çağrısını CrowdStrike'ta
    yanlış IOC tipinde aratır ve gösterge bulunamaz.
    """
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts)


def cs_probe_targets(raw: str) -> list[tuple[str, str]]:
    """
    Bir sorgu için CrowdStrike'ta hangi (tip, değer) çiftlerinin aranacağı.

    Alan adında iki biçim de denenir. CrowdStrike değeri basıldığı gibi
    saklıyor: eski URL yolundan gelen kayıtlar 'www.' ÖNEKİYLE yazılmış,
    bugünkü domain akışı ise öneki kırpıyor. Tek biçim sorgulamak,
    aranan göstergenin orada olduğu hâlde bulunamaması demek.
    """
    value = (raw or "").strip().lower().rstrip(".")
    if not value:
        return []

    if looks_like_ipv4(value):
        return [("ip", value)]

    # 32 hane md5, 64 hane sha256 — ikisi de 'hash' tipiyle aranıyor.
    if len(value) in (32, 64) and all(c in "0123456789abcdef" for c in value):
        return [("hash", value)]

    if "." not in value:
        return []

    bare = value[4:] if value.startswith("www.") else value
    return [("domain", bare), ("domain", f"www.{bare}")]

PAGE_SIZE = 20                    # USOM API sayfada dönen kayıt sayısı
MAX_CONCURRENT_REQUESTS = 3       # API'ye eşzamanlı istek limiti (rate-limit koruması)
HTTP_TIMEOUT = 30.0               # Her bir HTTP isteği için zaman aşımı (saniye)
MAX_RETRY_ATTEMPTS = 5            # Başarısız istekler için yeniden deneme sayısı
DELTA_SYNC_MAX_PAGES = 10         # Saatlik delta sync'te taranacak maks. sayfa sayısı
APP_START_TIME = time.time()      # Uptime hesabı için başlangıç zamanı

# CrowdStrike zaman aşımları
# falconpy varsayılan olarak timeout uygulamaz; ölü bir TCP bağlantısında
# recv() sonsuza kadar bloklanır ve zamanlanmış görev bir daha hiç bitmez.
CS_CONNECT_TIMEOUT = 10.0         # CrowdStrike'a bağlanma zaman aşımı (saniye)
CS_READ_TIMEOUT = 60.0            # CrowdStrike yanıt bekleme zaman aşımı (saniye)
CS_BATCH_TIMEOUT = 120.0          # Tek bir batch push'u için üst sınır (saniye)
# Silinecek göstergenin id'sini ararken dönecek azami kayıt. Tek bir değer
# normalde tek id üretir; sınır, beklenmedik bir FQL eşleşmesinde binlerce
# kaydın silinmesini engelleyen emniyet freni.
CS_DELETE_SEARCH_LIMIT = 100

# CrowdStrike, batch içindeki TEK bir gösterge "duplicate" uyarısı üretse bile
# isteğin tamamını 400 ile reddeder — geçerli yeni göstergeler de yazılmaz.
# Bu yüzden 400 yanıtında sorunlu satırlar ayıklanıp kalan yeniden gönderilir.
CS_MAX_BATCH_RETRIES = 4          # Bir batch'i temizlemek için maks. deneme

# CrowdStrike domain göstergesi için değer uzunluk sınırı.
# Aşan kayıtlar "value is too long for domain type: max_length=200" ile
# reddedilir. Bunlar tipik olarak DNS tünelleme beacon'larıdır (base32
# kodlu, 200+ karakter alt alan adları). Gönderilmeleri mümkün olmadığı
# için kuyrukta sonsuza kadar dönmemeleri adına baştan ayıklanırlar —
# ilgili tünelleme altyapısı zaten ana alan adı üzerinden engellenir.
CS_MAX_DOMAIN_LENGTH = 200

# Uzun push'larda ilerlemenin veritabanına yazılma sıklığı.
# Tüm kuyruk bitene kadar beklenirse süreç ortada ölünce bütün ilerleme
# kaydı kaybolur ve gönderilmiş göstergeler bir daha duplicate olarak döner.
CS_CHECKPOINT_SIZE = 2000         # Kaç göstergede bir DB'ye işaretlensin

# Reddedilen gösterge kaydı.
# Redleri log'a yazmak arızayı sonradan incelemeye yetiyor ama panoda
# "bu gösterge neden gönderilmedi" sorusunu cevaplamıyor: log dosyası
# panonun erişemediği bir yerde duruyor. Bu yüzden redler tabloya da
# yazılır. Tablo sınırsız büyümesin diye her yazımdan sonra en yeni
# REJECTION_RETENTION kayıt bırakılıp gerisi silinir.
REJECTION_RETENTION = 5000        # Tabloda tutulacak en yeni red kaydı sayısı
REJECTION_REASON_MAX = 300        # Saklanacak red mesajının maks. uzunluğu

# Ağır dağılım sorguları (TLD, /16 yoğunluğu, saat histogramı) tam tablo
# tarar. Pano bunları dakikada bir isterse yüz binlik tabloda boşa yük
# olur — dağılımlar saat başı bir iki puan oynar. Sonuç bu süre boyunca
# bellekte tutulur.
DISTRIBUTION_CACHE_TTL = 300      # saniye

# SSE canlı akışında iki gönderim arası bekleme.
SSE_INTERVAL = 10                 # saniye
# Bir akışın ömrü sınırlı tutulur. Sonsuz akış, açık kalan her sekme için
# süresiz bir bağlantı ve görev bırakır; ayrıca uvicorn'un düzgün kapanışı
# uçuştaki isteği beklediği için servis yeniden başlatması takılır.
# Süre dolunca akış kapatılır, tarayıcının EventSource'u kendiliğinden
# yeniden bağlanır — kullanıcı açısından kesinti görünmez.
SSE_MAX_TICKS = 30                # 30 × 10 sn = 5 dakika

# /lookup için üst sınırlar — uzun bir girdiyle tam tablo taraması
# tetiklenmesin.
LOOKUP_MAX_LENGTH = 260
RECENT_MAX_LIMIT = 200

# service_meta anahtarları
META_LAST_SYNC_OK = "last_sync_ok"   # En son BAŞARIYLA tamamlanan sync (UTC ISO)

# CrowdStrike, "prevent"/"prevent_no_ui" (engelle) aksiyonunu YALNIZCA hash
# (sha256/md5) tipleri için kabul eder. domain ve ipv4 tiplerinde bu aksiyon
# HTTP 400 ile reddedilir — bu tipler için tavan "detect"tir.
# USOM feed'i yalnızca domain ve ip sağladığı için pratikte tek geçerli
# değer "detect"tir; yanlış yapılandırma tüm push'ları sessizce bozmasın diye
# aşağıda kelepçeleniyor.
CS_NETWORK_ALLOWED_ACTIONS = {"detect", "no_action", "allow"}
CS_NETWORK_FALLBACK_ACTION = "detect"

# Hash (sha256) tipinde ise CrowdStrike beş aksiyonun tamamını kabul eder —
# "prevent" dahil, yani dosyanın çalıştırılması gerçekten engellenir.
# Doğrulandı 2026-08-20: prevent / prevent_no_ui / detect / no_action / allow → 201
CS_HASH_ALLOWED_ACTIONS = {"prevent", "prevent_no_ui", "detect", "no_action", "allow"}
CS_HASH_FALLBACK_ACTION = "detect"   # Geçersiz yapılandırmada güvenli tarafta kal

# /health tazelik eşiği: son senkronizasyon bundan eskiyse "degraded" döner
SYNC_STALENESS_THRESHOLD = 7200   # 2 saat (saniye)

# Panoda ve OpenAPI dokümantasyonunda görünen servis adı. Kurumunuzun adını
# yansıtmak için .env içinde SERVICE_TITLE tanımlamanız yeterli; kod değişikliği
# gerekmez. Pano şablonu her istekte diskten okunduğu için değer, oradaki
# {{SERVICE_TITLE}} yer tutucusuna sunum anında yazılır.
SERVICE_TITLE = os.getenv("SERVICE_TITLE", "").strip() or "USOM Tehdit İstihbaratı Servisi"

# Kalıcı log dosyası ayarları
LOG_DIR = os.getenv("LOG_DIR", "logs")
LOG_FILE_NAME = "service.log"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5              # service.log.1 … service.log.5

# CrowdStrike'a basılmayacak olan global/güvenilir domainler (false-positive engelleme)
WHITELISTED_DOMAINS = {
    "t.co", "facebook.com", "instagram.com", "meta.com", "twitter.com", "x.com",
    "youtube.com", "youtu.be", "google.com", "github.com", "linkedin.com",
    "whatsapp.com", "telegram.org", "discord.com", "apple.com", "microsoft.com",
    "drive.google.com", "docs.google.com", "dropbox.com", "onedrive.live.com",
    "wordpress.com", "blogspot.com", "medium.com", "tumblr.com"
}

# Paylaşımlı altyapı alan adları — link kısaltıcılar, bulut/CDN uç noktaları ve
# ücretsiz barındırma sağlayıcıları.
#
# Bunlarda WHITELISTED_DOMAINS'ten FARKLI bir kural uygulanır:
#   • Alan adının KENDİSİ (apex) asla listeye girmez / gönderilmez.
#     "is.gd" engellenirse o servisle kısaltılmış her bağlantı, "r2.dev"
#     engellenirse tüm Cloudflare R2 kovaları kurum genelinde kesilir.
#   • Alt alan adları NORMAL şekilde işlenir.
#     "evil.000webhostapp.com" gerçek bir zararlı sitedir ve engellenmelidir.
#
# WHITELISTED_DOMAINS ise hem apex'i hem alt alan adlarını muaf tutar; bu yüzden
# paylaşımlı altyapı oraya eklenmemelidir — eklenirse gerçek zararlı alt alan
# adları da tespit dışı kalır.
SHARED_INFRA_DOMAINS = {
    # Link kısaltıcılar
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "kisa.link", "tiny.cc", "rebrand.ly", "bl.ink",
    "lnkd.in", "s.id", "v.gd", "j.mp", "clck.ru", "vk.cc", "linktr.ee",
    "t.ly", "shorte.st", "gg.gg", "short.gy", "shrtco.de", "urlz.fr", "u.to",
    # Bulut depolama / CDN uç noktaları
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "windows.net",
    "googleusercontent.com", "appspot.com", "akamaized.net", "fastly.net",
    "digitaloceanspaces.com", "b-cdn.net", "r2.dev", "backblazeb2.com",
    # Ücretsiz / paylaşımlı barındırma ve site kurucular
    "herokuapp.com", "firebaseapp.com", "web.app", "pages.dev", "workers.dev",
    "netlify.app", "vercel.app", "glitch.me", "repl.co", "github.io",
    "gitlab.io", "weebly.com", "wixsite.com", "000webhostapp.com",
    "lovestoblog.com", "myshopify.com", "square.site", "godaddysites.com",
    "onrender.com", "surge.sh", "neocities.org", "infinityfreeapp.com",
    "translate.goog", "notion.site", "sites.google.com",
    # Form / mesajlaşma / dosya paylaşımı
    "forms.gle", "wa.me", "chat.whatsapp.com", "t.me", "mediafire.com",
    "typeform.com", "jotform.com",
}


def is_shared_infra_apex(domain: str) -> bool:
    """
    Verilen alan adı, paylaşımlı bir altyapının KENDİSİ mi?

    Yalnızca apex eşleşmesi arar; alt alan adları için False döner, böylece
    zararlı alt alan adları normal şekilde işlenmeye devam eder.
    """
    d = domain.strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d in SHARED_INFRA_DOMAINS


def hash_push_block_reason(signature: str, file_name: str) -> Optional[str]:
    """
    Bir hash'in CrowdStrike'a gönderilmemesi gerekiyorsa sebebini döndürür.

    None dönerse gönderilebilir. Sebep metni doğrudan bloke kaydına ve
    panoya yazılır, bu yüzden okunabilir olmalı.

    Sıra önemli: dosya adı kontrolü imza kontrolünden ÖNCE gelir, çünkü
    bilinen bir aileye eşleşen bir örnek de "cmd.exe" adını taşıyabilir ve
    o durumda da engellenmemesi gerekir.
    """
    name = (file_name or "").strip().lower()
    if name in MB_SYSTEM_BINARIES:
        return (
            f"Dosya adı yaygın sistem/uygulama ikilisi ('{name}') — yanlış "
            f"pozitif hâlinde kurum genelinde çalıştırma engellenirdi, "
            f"gönderim dışı bırakıldı."
        )

    sig = (signature or "").strip().lower()
    if sig in MB_UNSIGNED_VALUES:
        return (
            "MalwareBazaar kaydında zararlı yazılım ailesi belirtilmemiş "
            "(signature = n/a) — aksiyon 'prevent' olduğu için "
            "sınıflandırılmamış örnekler gönderilmiyor."
        )
    return None


# ── SQLite kullanıcı fonksiyonları ──
# Dağılım sorgularının gruplama anahtarını SQL içinde üretmek gerekiyor.
# Alternatif, yüz binlerce satırı Python'a çekip orada gruplamaktı; bu
# hem belleği hem event loop'u gereksiz meşgul ederdi. SQLite kullanıcı
# fonksiyonu sayesinde gruplama motorun içinde kalır ve dışarı yalnızca
# ilk N satır çıkar.

def _sql_tld(domain: Optional[str]) -> Optional[str]:
    """
    Alan adının son etiketini ("uzantı") döndürür.

    Bu bir public-suffix çözümlemesi DEĞİLDİR: "example.co.uk" için "uk"
    döner, "co.uk" değil. Panodaki dağılım grafiği için yeterli — kaba
    bir coğrafya/uzantı dağılımı gösteriyor, engelleme kararı vermiyor.
    """
    if not domain:
        return None
    d = domain.strip().lower().rstrip(".")
    if "." not in d:
        return None
    return d.rsplit(".", 1)[1] or None


def _sql_subnet16(ip: Optional[str]) -> Optional[str]:
    """
    IPv4 adresini /16 blok etiketine indirir ("203.0.113.9" → "203.0.0.0/16").

    Yoğunluk göstergesi olarak /16 seçildi: /24 yüz binlik listede çok
    parçalı bir kuyruk üretiyor, /8 ise anlamsız derecede kaba. IPv6 ve
    ayrıştırılamayan değerler için None döner — gruplamada dışarıda kalırlar.
    """
    if not ip:
        return None
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    if not (0 <= a <= 255 and 0 <= b <= 255):
        return None
    return f"{a}.{b}.0.0/16"


# Red sebeplerini sınıflandırma.
# CrowdStrike'ın döndürdüğü mesajlar gösterge değerini içerebiliyor
# ("value 'x' is too long…"), bu yüzden ham mesajla gruplamak her red için
# ayrı bir satır üretir. Panoda işe yarayan şey "hangi sebepten kaç tane"
# olduğu; sınıflandırma bunu sağlar. Ham mesaj ayrıca saklanır.
# "warning" en başta: CrowdStrike'ın uyarı mesajları ("Warning: This hash
# could be Cmd.Exe...") başka hiçbir kalıba uymadığı için "unknown"a
# düşüyordu ve panoda "Sınıflandırılamayan hata" olarak görünüyordu. Oysa
# bu, sistemin doğru çalıştığı bir durum: CrowdStrike bilinen bir sistem
# ikilisini engellememizi engelliyor.
_REJECTION_RULES = (
    ("warning", ("warning:", "common application", "could be a common")),
    ("length_limit", ("too long", "max_length")),
    ("invalid_value", ("invalid", "not a valid", "malformed", "must be")),
    ("duplicate", ("duplicate",)),
    ("timeout", ("timeout", "timed out", "yanıt vermedi")),
    ("rate_limit", ("rate limit", "too many requests", "429")),
    ("auth", ("unauthorized", "forbidden", "401", "403", "access denied")),
    ("quota", ("quota", "limit exceeded", "maximum number")),
)

# Panoda gösterilecek Türkçe karşılıklar
REJECTION_LABELS = {
    "warning": "CrowdStrike uyarısı (yaygın uygulama olabilir)",
    "length_limit": "Uzunluk sınırı aşıldı",
    "invalid_value": "Geçersiz gösterge değeri",
    "duplicate": "Zaten kayıtlı",
    "timeout": "CrowdStrike zaman aşımı",
    "rate_limit": "Hız sınırı (rate limit)",
    "auth": "Kimlik doğrulama / yetki hatası",
    "quota": "Kota doldu",
    "api_error": "CrowdStrike API hatası",
    "unknown": "Sınıflandırılamayan hata",
}

# Tekrar denemenin ASLA farklı bir sonuç vermeyeceği red sebepleri.
#
# Bu ayrım olmadan bir gösterge sonsuz döngüye giriyordu: gönderilemiyor,
# ama "gönderildi" işaretlenmediği için her turda yeniden deneniyor. Panoda
# kalıcı olarak "bekleyen 1" görünüyor, red tablosuna saat başı mükerrer
# satır yazılıyor ve her denemede boşa bir API turu harcanıyordu.
#
# Geçici sebepler (zaman aşımı, hız sınırı, yetki, kota) BİLİNÇLİ olarak
# dışarıda: onlar düzeldiğinde gösterge gönderilebilir olmalı. "unknown"
# da dışarıda — anlamadığımız bir hata yüzünden göstergeyi kalıcı olarak
# düşürmek, gereksiz yeniden denemekten daha kötü.
PERMANENT_REJECTION_CLASSES = {"warning", "length_limit", "invalid_value"}


def _first_error_message(errors) -> str:
    """
    CrowdStrike errors[] listesinden okunabilir tek bir mesaj çıkarır.

    Listenin tamamı saklanmıyor: tek bir batch onlarca satır uyarı
    döndürebiliyor ve bunları red kaydına yazmak tabloyu şişirirdi.
    Ayrıntı zaten log'da duruyor.
    """
    if not errors:
        return "ayrıntı bildirilmedi"
    first = errors[0]
    if isinstance(first, dict):
        return str(first.get("message") or first)
    return str(first)


def classify_rejection(message: Optional[str]) -> str:
    """Ham red mesajını sabit bir sebep sınıfına indirir."""
    if not message:
        return "unknown"
    low = message.lower()
    for reason_class, needles in _REJECTION_RULES:
        if any(n in low for n in needles):
            return reason_class
    if "status" in low or "api" in low:
        return "api_error"
    return "unknown"


# ─────────────────────────────────────────────
# Loglama Konfigürasyonu
# ─────────────────────────────────────────────
_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(
    level=logging.INFO,
    format=_LOG_FORMAT,
    datefmt=_LOG_DATEFMT,
)
logger = logging.getLogger("USOMListService")


def _setup_file_logging() -> Optional[str]:
    """
    Konsola ek olarak dönen (rotating) bir log dosyası kurar.

    journald'a erişim yetkisi olmayan ortamlarda arızanın sonradan
    incelenebilmesi için gereklidir. Dosya açılamazsa servis yine de
    çalışmaya devam eder, yalnızca konsola loglar.
    """
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        log_path = os.path.join(LOG_DIR, LOG_FILE_NAME)
        handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
        handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(handler)
        return log_path
    except OSError as exc:
        logger.warning("Log dosyası açılamadı (%s) — yalnızca konsola loglanacak.", exc)
        return None


LOG_FILE_PATH = _setup_file_logging()


# ─────────────────────────────────────────────────────
# 1. VERİTABANI KATMANI (SQLite - Async)
# ─────────────────────────────────────────────────────
class IPDatabase:
    """
    Zararlı IP adreslerini SQLite veritabanında kalıcı olarak saklar.

    Tablo yapısı:
        - ip (TEXT, PRIMARY KEY): Benzersiz IP adresi.
        - added_at (TEXT): IP adresinin ilk eklenme zaman damgası (UTC).

    PRIMARY KEY kısıtlaması sayesinde duplicate IP'ler otomatik olarak engellenir.
    """

    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """Veritabanı bağlantısını aç ve tabloyu oluştur."""
        self._db = await aiosqlite.connect(self.db_path)
        # WAL modu: Eşzamanlı okuma-yazma performansını artırır
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS malicious_ips (
                ip             TEXT PRIMARY KEY,
                added_at       TEXT NOT NULL DEFAULT (datetime('now')),
                pushed_to_cs   INTEGER NOT NULL DEFAULT 0
            )
        """)
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS malicious_domains (
                domain         TEXT PRIMARY KEY,
                added_at       TEXT NOT NULL DEFAULT (datetime('now')),
                pushed_to_cs   INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Zararlı yazılım hash'leri (kaynak: abuse.ch MalwareBazaar).
        # sha256 birincil anahtar: CrowdStrike'a bu tip basılır. md5 yalnızca
        # besleme endpoint'inde sunulur — aynı dosya için ikinci bir IOC
        # oluşturmak tenant kotasını gereksiz tüketirdi.
        # signature/file_name yalnızca kayıt amaçlı değil: gönderim kararı
        # bunlara bakıyor (bkz. hash_push_block_reason). Kaynak bunları
        # veriyorsa saklanmaları gerekir, yoksa "bu hash neden
        # gönderilmedi" sorusu cevaplanamaz.
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS malicious_hashes (
                sha256         TEXT PRIMARY KEY,
                md5            TEXT,
                first_seen     TEXT,
                signature      TEXT,
                file_name      TEXT,
                added_at       TEXT NOT NULL DEFAULT (datetime('now')),
                pushed_to_cs   INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Senkronizasyon çalışma geçmişi.
        # added_at alanları "kayıt ne zaman geldi" sorusunu cevaplar ama
        # "görev ne zaman, ne kadar sürede, başarıyla çalıştı mı" sorusunu
        # cevaplamaz. Bu tablo o geçmişi biriktirir; pano güvenilirlik
        # istatistiklerini buradan üretir.
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS sync_runs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                job          TEXT NOT NULL,
                started_at   TEXT NOT NULL,
                finished_at  TEXT,
                duration_ms  INTEGER,
                new_records  INTEGER NOT NULL DEFAULT 0,
                pushed       INTEGER NOT NULL DEFAULT 0,
                status       TEXT NOT NULL DEFAULT 'running',
                detail       TEXT
            )
        """)
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_sync_runs_started "
            "ON sync_runs (started_at DESC)"
        )
        # Servis durum damgaları (ör. en son BAŞARILI sync zamanı).
        # Tazelik kontrolü buradan okunur; max(added_at) kullanılamaz çünkü o
        # yalnızca YENİ kayıt geldiğinde ilerler ve USOM sessiz kaldığında
        # sapasağlam çalışan servis "bayat" görünür.
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS service_meta (
                key        TEXT PRIMARY KEY,
                value      TEXT,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        # CrowdStrike'ın reddettiği göstergeler.
        # pushed_to_cs=0 bir göstergenin "henüz sırası gelmedi" mi yoksa
        # "gönderilmeye çalışıldı ve reddedildi" mi olduğunu ayırt etmiyor.
        # Bu tablo ikinci durumu sebebiyle birlikte kaydeder; pano
        # bekleyen kuyruğun ne kadarının aslında tıkalı olduğunu buradan
        # okur.
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS push_rejections (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                value          TEXT NOT NULL,
                reason_class   TEXT NOT NULL,
                reason         TEXT,
                occurred_at    TEXT NOT NULL
            )
        """)
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_rejections_time "
            "ON push_rejections (occurred_at DESC)"
        )
        # Operatörün bilinçli olarak sildiği göstergeler.
        #
        # Satırı tablodan silmek tek başına yetmez: USOM onu hâlâ
        # yayınladığı için bir sonraki delta sync (en geç bir saat içinde)
        # aynı değeri geri ekler, pushed_to_cs=0 olarak kuyruğa alır ve
        # CrowdStrike'a yeniden basar. Silme kararı kalıcı olsun diye
        # değer burada tutulur; insert_* yolları bu listeyi filtreler.
        #
        # Yani bu tablo "silinmişler çöp kutusu" değil, kalıcı bir
        # dışlama (deny) listesi. Kayıt tutulur çünkü "bu adres neden
        # listede yok" sorusunun cevabı başka hiçbir yerde yazmıyor.
        # cs_status üç durumu ayırır ve bu ayrım operasyonel olarak
        # önemlidir: 'disabled' (entegrasyon kapalı, yapacak bir şey yok)
        # ile 'failed' (gösterge CrowdStrike'ta DURUYOR, hâlâ engelleniyor,
        # elle müdahale gerek) aynı şey değil. Tek bir boolean bu ikisini
        # birbirine karıştırırdı.
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS deleted_iocs (
                indicator_type TEXT NOT NULL,
                value          TEXT NOT NULL,
                deleted_at     TEXT NOT NULL,
                note           TEXT,
                cs_status      TEXT NOT NULL DEFAULT 'pending',
                cs_detail      TEXT,
                PRIMARY KEY (indicator_type, value)
            )
        """)
        # Her insert_* çağrısı bu tabloya bakıyor; değer üzerinden arama hızlı olmalı.
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_deleted_value ON deleted_iocs (value)"
        )
        for column, ddl in (
            ("cs_status", "TEXT NOT NULL DEFAULT 'pending'"),
            ("cs_detail", "TEXT"),
        ):
            try:
                await self._db.execute(
                    f"ALTER TABLE deleted_iocs ADD COLUMN {column} {ddl}"
                )
                await self._db.commit()
                logger.info("deleted_iocs.%s sütunu eklendi (migration).", column)
            except Exception:
                pass
        # added_at üzerinden yapılan "son eklenenler" ve günlük/saatlik
        # gruplama sorguları bu indeksler olmadan tam tablo tarıyor.
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_ips_added ON malicious_ips (added_at DESC)"
        )
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_domains_added "
            "ON malicious_domains (added_at DESC)"
        )
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_hashes_added "
            "ON malicious_hashes (added_at DESC)"
        )
        # md5 ile arama yapılabilsin (besleme md5'i de sunuyor).
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_hashes_md5 ON malicious_hashes (md5)"
        )
        # Dağılım sorgularının gruplama anahtarlarını üreten kullanıcı
        # fonksiyonları. deterministic=True: aynı girdi aynı çıktıyı verir,
        # SQLite bunu bilirse sorguyu optimize edebilir.
        await self._db.create_function("tld", 1, _sql_tld, deterministic=True)
        await self._db.create_function("subnet16", 1, _sql_subnet16, deterministic=True)
        # Migration: kalıcı olarak gönderilemeyen göstergeler için "bloke"
        # durumu. pushed_to_cs=1 işaretlemek yanlış olurdu (gösterge
        # gönderilmedi, panoda öyle görünmemeli); 0 bırakmak da yanlış
        # (her turda yeniden denenir). Üçüncü bir durum gerekiyor.
        # blocked_reason burada tutulur, push_rejections'ta değil: o tablo
        # son N kaydı taşıyan dönen bir kayıt defteri, eski satırları
        # siliniyor — bloke sebebi göstergeyle birlikte kalıcı olmalı.
        # Kaynak kolonu. Brandefense verisi USOM'la aynı tablolara
        # yazıldığı için (mükerrer kayıt oluşmasın diye tek anahtar uzayı
        # gerekiyor), göstergenin nereden geldiği ayrı bir alanda tutulur.
        # DEFAULT 'usom': ALTER anındaki mevcut satırların tamamı USOM
        # kaynaklı, dolayısıyla geriye dönük değer doğru.
        for table, default in (
            ("malicious_ips", SOURCE_USOM),
            ("malicious_domains", SOURCE_USOM),
            ("malicious_hashes", SOURCE_MALWAREBAZAAR),
        ):
            try:
                await self._db.execute(
                    f"ALTER TABLE {table} ADD COLUMN source TEXT NOT NULL "
                    f"DEFAULT '{default}'"
                )
                await self._db.commit()
                logger.info("%s.source sütunu eklendi (migration).", table)
            except Exception:
                pass

        # malicious_hashes: gönderim kararına giren kaynak alanları.
        # Mevcut kayıtlarda NULL kalır — geriye dönük doldurulamaz, çünkü
        # MalwareBazaar "recent" dökümü yalnızca son ~48 saati kapsıyor.
        for column in ("signature", "file_name"):
            try:
                await self._db.execute(
                    f"ALTER TABLE malicious_hashes ADD COLUMN {column} TEXT"
                )
                await self._db.commit()
                logger.info("malicious_hashes.%s sütunu eklendi (migration).", column)
            except Exception:
                pass

        # last_seen_at: göstergeyi beslemede EN SON ne zaman gördük.
        #
        # Saklama (retention) temizliği bu kolona bakar, added_at'e değil.
        # Fark kritik: 60 gündür her gün raporlanan, hâlâ aktif bir IOC'nin
        # added_at'i 60 gün önceyi gösterir ve yaşa göre silinirdi — oysa
        # tehdit sürüyor. Bir sonraki sync onu geri ekler, aradaki sürede
        # koruma boşluğu oluşur ve her turda gereksiz CrowdStrike trafiği
        # üretilir. last_seen_at ile yalnızca kaynağın artık raporlamadığı
        # göstergeler silinir.
        #
        # Mevcut satırlarda added_at ile doldurulur: bu kolonun eklendiği
        # ana kadar elimizdeki tek gözlem tarihi o. İlk sync turlarında
        # hâlâ aktif olanların last_seen_at'i tazelenecek, olmayanlar
        # zaten silinmeye aday.
        for table in ("malicious_ips", "malicious_domains", "malicious_hashes"):
            try:
                await self._db.execute(
                    f"ALTER TABLE {table} ADD COLUMN last_seen_at TEXT"
                )
                await self._db.execute(
                    f"UPDATE {table} SET last_seen_at = added_at "
                    f"WHERE last_seen_at IS NULL"
                )
                await self._db.commit()
                logger.info(
                    "%s.last_seen_at sütunu eklendi ve added_at ile dolduruldu "
                    "(migration).", table,
                )
            except Exception:
                pass

            # Saklama sorgusu (source + last_seen_at) bu indeks olmadan
            # 400 binlik tabloda tam tarama yapar.
            await self._db.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{table}_retention "
                f"ON {table} (source, last_seen_at)"
            )

        for table in ("malicious_ips", "malicious_domains", "malicious_hashes"):
            for column, ddl in (
                ("push_blocked", "INTEGER NOT NULL DEFAULT 0"),
                ("blocked_reason", "TEXT"),
            ):
                try:
                    await self._db.execute(
                        f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"
                    )
                    await self._db.commit()
                    logger.info("%s.%s sütunu eklendi (migration).", table, column)
                except Exception:
                    pass  # Sütun zaten varsa sessizce geç

        # Migration: malicious_domains tablosuna pushed_to_cs yoksa ekle
        try:
            await self._db.execute("ALTER TABLE malicious_domains ADD COLUMN pushed_to_cs INTEGER NOT NULL DEFAULT 0")
            await self._db.commit()
        except Exception:
            pass
        # Mevcut tabloya pushed_to_cs sütunu yoksa ekle (migration)
        try:
            await self._db.execute("ALTER TABLE malicious_ips ADD COLUMN pushed_to_cs INTEGER NOT NULL DEFAULT 0")
            await self._db.commit()
            logger.info("pushed_to_cs sütunu eklendi (migration).")
        except Exception:
            pass  # Sütun zaten varsa sessizce geç
        await self._db.commit()
        logger.info("Veritabanı bağlantısı kuruldu: %s", self.db_path)

    # ── Zararlı yazılım hash'leri ──

    async def insert_hashes(self, records: list[tuple[str, str, str, str, str]]) -> dict:
        """
        (sha256, md5, first_seen, signature, file_name) beşlilerini ekler ve
        gönderime uygun olmayanları BLOKE işaretler.

        Gönderim kararı kayıt anında verilir, push anında değil: karar
        yalnızca MalwareBazaar'ın verdiği imza ve dosya adına bağlı,
        CrowdStrike'ın cevabına bağlı değil. Kayıt sırasında işaretlemek,
        uygun olmayan bir göstergenin gönderim kuyruğuna hiç girmemesini
        garanti eder.

        Kayıtlar veritabanında TUTULUR — /lookup ve arşiv sorguları
        çalışmaya devam eder; yalnızca CrowdStrike'a basılmazlar.

        Returns:
            {"new": yeni kayıt, "blocked": bloke işaretlenen yeni kayıt}
        """
        if not records:
            return {"new": 0, "blocked": 0}

        # Silinen hash'ler dökümde kalmaya devam ediyor; sha256 veya md5'i
        # dışlama listesindeyse kayıt hiç yazılmaz (bkz. insert_ips).
        async with self._db.execute(
            "SELECT value FROM deleted_iocs WHERE indicator_type = 'hash'"
        ) as cur:
            excluded_hashes = {row[0] for row in await cur.fetchall()}
        if excluded_hashes:
            records = [
                r for r in records
                if r[0] not in excluded_hashes and (not r[1] or r[1] not in excluded_hashes)
            ]
            if not records:
                return {"new": 0, "blocked": 0}

        before = await self.get_hash_count()
        # INSERT OR IGNORE yerine upsert: sütunlar sonradan eklendiği için
        # daha önce kaydedilmiş satırlarda signature/file_name boş. Döküm
        # kayan bir pencere olduğundan bu satırlar bir süre daha geliyor;
        # o sırada alanları dolduruyoruz. COALESCE ile yalnızca boş olanlar
        # yazılır — dolu bir değeri boş bir değerle ezmez.
        # added_at'e dokunulmuyor: "ne zaman ilk gördük" bilgisi korunmalı.
        # last_seen_at her dökümde tazelenir: MalwareBazaar "recent" kayan
        # bir pencere, örnek hâlâ dökümde görünüyorsa aktif sayılır ve
        # saklama süresi yeniden başlar.
        now = datetime.now(timezone.utc).isoformat()
        rows = [(*r, now) for r in records]
        await self._db.executemany(
            "INSERT INTO malicious_hashes "
            "(sha256, md5, first_seen, signature, file_name, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(sha256) DO UPDATE SET "
            "  signature = COALESCE(NULLIF(malicious_hashes.signature, ''), excluded.signature), "
            "  file_name = COALESCE(NULLIF(malicious_hashes.file_name, ''), excluded.file_name), "
            "  last_seen_at = excluded.last_seen_at",
            rows,
        )
        await self._db.commit()
        new_count = await self.get_hash_count() - before

        # Gönderim dışı bırakılacaklar. Yalnızca henüz gönderilmemiş
        # kayıtlar işaretlenir (mark_blocked bunu zaten garanti ediyor);
        # geçmişte gönderilmiş bir hash geriye dönük bloke edilmez —
        # CrowdStrike'tan silmek ayrı ve bilinçli bir işlem.
        to_block = [
            (sha256, reason)
            for sha256, _md5, _fs, signature, file_name in records
            if (reason := hash_push_block_reason(signature, file_name)) is not None
        ]
        blocked = await self.mark_blocked("hash", to_block) if to_block else 0
        if to_block:
            logger.info(
                "MalwareBazaar: %d kayıt gönderim dışı bırakıldı "
                "(imzasız veya sistem ikilisi adı), %d tanesi yeni işaretlendi.",
                len(to_block), blocked,
            )
        return {"new": new_count, "blocked": blocked}

    async def get_all_hashes(self, include_blocked: bool = False) -> list[str]:
        """
        sha256 değerlerini döndürür.

        Varsayılan olarak bloke kayıtlar HARİÇ tutulur. Bu besleme güvenlik
        cihazları tarafından tüketiliyor ve onlar da engelleme yapıyor:
        CrowdStrike'a basmayı güvenli bulmadığımız bir hash'i buradan
        sunmak, aynı yanlış pozitif riskini başka bir cihaz üzerinden
        geri getirirdi. Tam arşiv include_blocked ile alınabilir.
        """
        where = "" if include_blocked else " WHERE push_blocked = 0"
        async with self._db.execute(
            f"SELECT sha256 FROM malicious_hashes{where} ORDER BY added_at DESC"
        ) as cursor:
            return [row[0] for row in await cursor.fetchall()]

    async def get_all_md5(self, include_blocked: bool = False) -> list[str]:
        """md5 değerlerini döndürür (boş olanlar hariç). Bkz. get_all_hashes."""
        extra = "" if include_blocked else " AND push_blocked = 0"
        async with self._db.execute(
            "SELECT md5 FROM malicious_hashes "
            f"WHERE md5 IS NOT NULL AND md5 != ''{extra} ORDER BY added_at DESC"
        ) as cursor:
            return [row[0] for row in await cursor.fetchall()]

    async def get_hash_count(self) -> int:
        """Toplam hash sayısı."""
        async with self._db.execute("SELECT COUNT(*) FROM malicious_hashes") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def get_unpushed_hashes(self) -> list[str]:
        """CrowdStrike'a henüz gönderilmemiş sha256 değerleri."""
        async with self._db.execute(
            "SELECT sha256 FROM malicious_hashes "
            "WHERE pushed_to_cs = 0 AND push_blocked = 0"
        ) as cursor:
            return [row[0] for row in await cursor.fetchall()]

    async def mark_hashes_pushed(self, hash_list: list[str]) -> None:
        """Belirtilen hash'leri gönderildi olarak işaretler."""
        if not hash_list:
            return
        await self._db.executemany(
            "UPDATE malicious_hashes SET pushed_to_cs = 1 WHERE sha256 = ?",
            [(h,) for h in hash_list],
        )
        await self._db.commit()

    async def get_pushed_hash_count(self) -> int:
        """CrowdStrike'a gönderilmiş hash sayısı."""
        async with self._db.execute(
            "SELECT COUNT(*) FROM malicious_hashes WHERE pushed_to_cs = 1"
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    # ── Reddedilen göstergeler ──

    async def record_rejections(
        self, indicator_type: str, items: list[tuple[str, str]]
    ) -> None:
        """
        (value, reason) çiftlerini reddedilenler tablosuna yazar.

        Kayıt tutmak push akışını bozmamalı: tablo yazımı başarısız olursa
        uyarı loglanır ve gönderim devam eder.
        """
        if not items:
            return
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                indicator_type,
                value,
                classify_rejection(reason),
                (reason or "")[:REJECTION_REASON_MAX],
                now,
            )
            for value, reason in items
        ]
        try:
            await self._db.executemany(
                "INSERT INTO push_rejections "
                "(indicator_type, value, reason_class, reason, occurred_at) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
            )
            # Sabit pencere: en yeni REJECTION_RETENTION kayıt kalır.
            await self._db.execute(
                "DELETE FROM push_rejections WHERE id NOT IN "
                "(SELECT id FROM push_rejections ORDER BY id DESC LIMIT ?)",
                (REJECTION_RETENTION,),
            )
            await self._db.commit()
        except Exception as exc:
            logger.warning("Red kaydı yazılamadı (%s): %s", indicator_type, exc)

    async def get_rejection_summary(self, hours: int = 168) -> dict:
        """Son N saatteki redlerin sebep ve gösterge tipi bazında dağılımı."""
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        async with self._db.execute(
            "SELECT reason_class, indicator_type, COUNT(*) n, MAX(occurred_at) last_at "
            "FROM push_rejections WHERE occurred_at >= ? "
            "GROUP BY reason_class, indicator_type ORDER BY n DESC",
            (since,),
        ) as cur:
            rows = await cur.fetchall()
        by_reason: dict[str, dict] = {}
        total = 0
        for reason_class, indicator_type, n, last_at in rows:
            entry = by_reason.setdefault(
                reason_class,
                {
                    "reason_class": reason_class,
                    "label": REJECTION_LABELS.get(reason_class, reason_class),
                    "count": 0,
                    "types": {},
                    "last_at": last_at,
                },
            )
            entry["count"] += n
            entry["types"][indicator_type] = n
            if last_at and (not entry["last_at"] or last_at > entry["last_at"]):
                entry["last_at"] = last_at
            total += n
        return {
            "window_hours": hours,
            "total": total,
            "reasons": sorted(
                by_reason.values(), key=lambda r: r["count"], reverse=True
            ),
        }

    async def get_recent_rejections(self, limit: int = 25) -> list[dict]:
        """En son reddedilen göstergeler (ham sebep mesajıyla)."""
        async with self._db.execute(
            "SELECT indicator_type, value, reason_class, reason, occurred_at "
            "FROM push_rejections ORDER BY id DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
        return [
            {
                "type": r[0],
                "value": r[1],
                "reason_class": r[2],
                "label": REJECTION_LABELS.get(r[2], r[2]),
                "reason": r[3],
                "occurred_at": r[4],
            }
            for r in rows
        ]

    # ── Bloke göstergeler ──
    #
    # Tablo ve anahtar sütunu eşlemesi tek yerde tutulur; bloke, sayım ve
    # dışa aktarım sorguları bunu paylaşır.
    KEY_COLUMNS = {
        "ip": ("malicious_ips", "ip"),
        "domain": ("malicious_domains", "domain"),
        "hash": ("malicious_hashes", "sha256"),
    }

    async def mark_blocked(self, kind: str, items: list[tuple[str, str]]) -> int:
        """
        Göstergeleri "kalıcı olarak gönderilemez" olarak işaretler.

        Yalnızca henüz gönderilmemiş kayıtlar işaretlenir: bir gösterge
        CrowdStrike'a başarıyla yazıldıktan sonra gelen bir uyarı, onu
        listeden düşürmemeli.
        """
        if not items or kind not in self.KEY_COLUMNS:
            return 0
        table, key = self.KEY_COLUMNS[kind]
        try:
            # "AND push_blocked = 0": aynı kayıt her turda yeniden
            # işaretlenmeye çalışılıyor (MalwareBazaar dökümü kayan bir
            # pencere, imzasız kayıtlar 48 saat boyunca tekrar geliyor).
            # Bu koşul olmadan rowcount her seferinde tüm imzasız kümeyi
            # sayar ve log "300 yeni bloke" der — oysa yeni olan yok.
            cur = await self._db.executemany(
                f"UPDATE {table} SET push_blocked = 1, blocked_reason = ? "
                f"WHERE {key} = ? AND pushed_to_cs = 0 AND push_blocked = 0",
                [((reason or "")[:REJECTION_REASON_MAX], value)
                 for value, reason in items],
            )
            await self._db.commit()
            return max(0, cur.rowcount or 0)
        except Exception as exc:
            logger.warning("Bloke işaretlemesi başarısız (%s): %s", kind, exc)
            return 0

    async def get_blocked_count(self, kind: str) -> int:
        """Belirtilen tipte bloke gösterge sayısı."""
        if kind not in self.KEY_COLUMNS:
            return 0
        table, _ = self.KEY_COLUMNS[kind]
        async with self._db.execute(
            f"SELECT COUNT(*) FROM {table} WHERE push_blocked = 1"
        ) as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    async def get_blocked(self, limit: int = 50) -> list[dict]:
        """Bloke göstergelerin listesi — sebebiyle birlikte, tip karışık."""
        out: list[dict] = []
        for kind, (table, key) in self.KEY_COLUMNS.items():
            async with self._db.execute(
                f"SELECT {key}, blocked_reason, added_at FROM {table} "
                f"WHERE push_blocked = 1 ORDER BY added_at DESC LIMIT ?",
                (limit,),
            ) as cur:
                for row in await cur.fetchall():
                    out.append({
                        "type": kind, "value": row[0], "reason": row[1],
                        "reason_class": classify_rejection(row[1]),
                        "label": REJECTION_LABELS.get(
                            classify_rejection(row[1]), "bilinmiyor"),
                        "added_at": row[2],
                    })
        out.sort(key=lambda r: r["added_at"] or "", reverse=True)
        return out[:limit]

    async def unblock_all(self) -> dict:
        """
        Tüm blokeleri kaldırır; göstergeler yeniden gönderim kuyruğuna girer.

        Bloke bir gösterge kendi kendine kuyruğa dönmez — dönerse sonsuz
        döngü geri gelir. Yeniden denemek bilinçli bir karar olmalı, bu
        yüzden yalnızca bu metot üzerinden yapılır.
        """
        counts = {}
        for kind, (table, _) in self.KEY_COLUMNS.items():
            cur = await self._db.execute(
                f"UPDATE {table} SET push_blocked = 0, blocked_reason = NULL "
                f"WHERE push_blocked = 1"
            )
            counts[kind] = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        await self._db.commit()
        counts["total"] = sum(counts.values())
        return counts

    # ── Operatör silmesi ve kalıcı dışlama ──

    async def filter_excluded(self, kind: str, values: list[str]) -> list[str]:
        """
        Silinmiş (dışlanmış) göstergeleri bir insert listesinden ayıklar.

        Besleme kaynakları (USOM, MalwareBazaar, Brandefense) sildiğimiz
        değeri yayınlamaya devam ediyor. Filtre insert yolunda durmazsa
        değer bir sonraki sync'te geri gelir — silme kalıcı olmaz.

        Hash tarafında sha256 ve md5'in ikisi de dışlanmış sayılır:
        operatör md5 ile silmiş olabilir, aynı dosya sha256 ile geri
        gelmemeli.
        """
        if not values or self._db is None:
            return values

        # Tek sorguda kontrol: besleme turları 40 bin satıra kadar
        # çıkabiliyor, değer başına sorgu kabul edilemez.
        async with self._db.execute(
            "SELECT value FROM deleted_iocs WHERE indicator_type = ?", (kind,)
        ) as cur:
            excluded = {row[0] for row in await cur.fetchall()}

        if not excluded:
            return values
        return [v for v in values if v not in excluded and v.lower() not in excluded]

    async def delete_indicator(
        self, kind: str, value: str, note: Optional[str] = None
    ) -> dict:
        """
        Tek bir göstergeyi tablosundan siler ve kalıcı dışlama listesine yazar.

        İki adım ayrılamaz: yalnızca silmek göstergeyi bir sonraki sync'e
        kadar yok eder, yalnızca dışlamak mevcut satırı bırakır. İkisi
        birlikte tek bir commit'te yapılır.

        Returns:
            {"removed": silinen satır sayısı, "already_excluded": bool}
        """
        if kind not in self.KEY_COLUMNS:
            raise ValueError(f"Geçersiz gösterge tipi: {kind}")
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")

        table, key = self.KEY_COLUMNS[kind]
        now = datetime.now(timezone.utc).isoformat()

        # Hash md5 ile de silinebilmeli: operatörün elindeki değer md5
        # olabilir, ama tablo anahtarı sha256. Silinen satırın sha256'sı
        # da dışlama listesine yazılır, yoksa aynı dosya geri gelir.
        extra_values: list[str] = []
        if kind == "hash":
            async with self._db.execute(
                "SELECT sha256, md5 FROM malicious_hashes WHERE sha256 = ? OR md5 = ?",
                (value, value),
            ) as cur:
                for row in await cur.fetchall():
                    extra_values.extend(v for v in row if v)
            cur = await self._db.execute(
                "DELETE FROM malicious_hashes WHERE sha256 = ? OR md5 = ?",
                (value, value),
            )
        else:
            cur = await self._db.execute(
                f"DELETE FROM {table} WHERE {key} = ?", (value,)
            )
        removed = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

        # Eski URL tablosundaki satırlar da düşmeli. Kalırlarsa arama aynı
        # göstergeyi bir sonraki sorguda yeniden "bulur": operatör siler,
        # gösterge geri gelir, tekrar siler — CrowdStrike'ta kayıt çoktan
        # yok olmasına rağmen biten bir iş hiç olmaz.
        if kind in ("ip", "domain"):
            removed += await self.purge_legacy_urls(value)

        # Değer tabloda hiç bulunmasa bile dışlanır: operatör henüz
        # senkronize edilmemiş bir göstergeyi önden engellemek isteyebilir.
        to_exclude = {value, *extra_values}
        await self._db.executemany(
            "INSERT INTO deleted_iocs (indicator_type, value, deleted_at, note) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(indicator_type, value) DO UPDATE SET "
            "  deleted_at = excluded.deleted_at, note = excluded.note",
            [(kind, v, now, note) for v in to_exclude],
        )
        await self._db.commit()
        return {"removed": removed, "excluded_values": sorted(to_exclude)}

    async def mark_cs_result(
        self, kind: str, value: str, status: str, detail: Optional[str]
    ) -> None:
        """
        CrowdStrike tarafının sonucunu işaretler.

        status: 'removed' | 'absent' | 'disabled' | 'failed'
        'failed' tek başına aksiyon gerektiren durum — gösterge yerel
        listeden düştü ama CrowdStrike'ta duruyor.
        """
        if self._db is None:
            return
        await self._db.execute(
            "UPDATE deleted_iocs SET cs_status = ?, cs_detail = ? "
            "WHERE indicator_type = ? AND value = ?",
            (status, detail, kind, value),
        )
        await self._db.commit()

    @staticmethod
    def _deletion_row(r) -> dict:
        return {
            "type": r[0], "value": r[1], "deleted_at": r[2], "note": r[3],
            "cs_status": r[4] or "pending", "cs_detail": r[5],
            # Geriye dönük alan: yalnızca gerçekten silindiyse True.
            "cs_removed": (r[4] or "") == "removed",
        }

    async def get_deletions(self, value: str) -> list[dict]:
        """Bir değerin silinme kaydını döndürür (/lookup 'neden yok' cevabı için)."""
        if self._db is None:
            return []
        async with self._db.execute(
            "SELECT indicator_type, value, deleted_at, note, cs_status, cs_detail "
            "FROM deleted_iocs WHERE value = ? OR value = ?",
            (value, value.lower()),
        ) as cur:
            return [self._deletion_row(r) for r in await cur.fetchall()]

    async def list_deletions(self, limit: int = 100) -> list[dict]:
        """Silinmiş göstergeleri en yeniden eskiye döndürür."""
        if self._db is None:
            return []
        async with self._db.execute(
            "SELECT indicator_type, value, deleted_at, note, cs_status, cs_detail "
            "FROM deleted_iocs ORDER BY deleted_at DESC LIMIT ?",
            (limit,),
        ) as cur:
            return [self._deletion_row(r) for r in await cur.fetchall()]

    async def restore_indicator(self, kind: str, value: str) -> int:
        """
        Dışlamayı kaldırır; gösterge bir sonraki sync'te normal yoluyla geri gelir.

        Yanlışlıkla silinen bir göstergeyi geri almanın tek yolu bu.
        Satırı burada yeniden eklemiyoruz: kaynağın onu hâlâ yayınladığını
        varsaymak yerine sync'in doğrulamasını bekliyoruz.
        """
        if kind not in self.KEY_COLUMNS or self._db is None:
            return 0
        cur = await self._db.execute(
            "DELETE FROM deleted_iocs WHERE indicator_type = ? AND value = ?",
            (kind, value),
        )
        await self._db.commit()
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    # ── Saklama (retention) ──

    @staticmethod
    def retention_cutoff(days: int) -> str:
        """TTL'den kesme tarihi üretir; bu tarihten eski last_seen_at süresi dolmuştur."""
        return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    async def retention_preview(self) -> dict:
        """
        Hiçbir şey silmeden "şu an temizlense ne giderdi" tablosunu üretir.

        Silme geri alınamaz ve koruma kaldırır; operatörün tetiklemeden
        önce rakamı görebilmesi gerekir. Saklama görevi de her turda önce
        bunu çağırır, böylece log'da ne yapmaya niyetlendiği yazılı olur.
        """
        if self._db is None:
            return {"total": 0, "sources": [], "cap": RETENTION_MAX_PER_RUN}

        rows = []
        total = 0
        for kind, (table, _key) in self.KEY_COLUMNS.items():
            for source, days in sorted(RETENTION_DAYS.items()):
                if days <= 0:
                    continue          # 0 = asla silme (USOM)
                cutoff = self.retention_cutoff(days)
                async with self._db.execute(
                    f"SELECT COUNT(*) FROM {table} "
                    f"WHERE source = ? AND last_seen_at IS NOT NULL "
                    f"AND last_seen_at < ?",
                    (source, cutoff),
                ) as cur:
                    n = (await cur.fetchone())[0]
                if not n:
                    continue
                total += n
                rows.append({
                    "kind": kind, "source": source, "days": days,
                    "cutoff": cutoff, "expired": n,
                })

        return {
            "total": total,
            "cap": RETENTION_MAX_PER_RUN,
            "capped": total > RETENTION_MAX_PER_RUN,
            "policy": {s: d for s, d in sorted(RETENTION_DAYS.items())},
            "sources": rows,
        }

    async def get_expired_values(
        self, kind: str, source: str, cutoff: str, limit: int
    ) -> list[str]:
        """
        Süresi dolmuş göstergelerin değerlerini döndürür — SİLMEZ.

        Silme iki adımlı: önce CrowdStrike'tan kaldırılır, ancak başarılı
        olursa yerel satır silinir. Yerel satırı önce silmek, CrowdStrike
        çağrısı başarısız olduğunda göstergeyi orada öksüz bırakırdı:
        elimizde değeri kalmadığı için bir daha asla bulunup silinemezdi.

        En eski last_seen_at önce: sınıra takılan turlarda en bayat
        kayıtlar önce temizlenir.
        """
        if self._db is None or kind not in self.KEY_COLUMNS:
            return []
        table, key = self.KEY_COLUMNS[kind]
        async with self._db.execute(
            f"SELECT {key} FROM {table} "
            f"WHERE source = ? AND last_seen_at IS NOT NULL AND last_seen_at < ? "
            f"ORDER BY last_seen_at LIMIT ?",
            (source, cutoff, limit),
        ) as cur:
            return [r[0] for r in await cur.fetchall()]

    async def purge_values(self, kind: str, values: list[str]) -> int:
        """
        Verilen değerleri tablodan siler.

        `deleted_iocs` dışlama listesine YAZILMAZ — bu, operatör silmesinden
        (delete_indicator) en önemli farkı. Saklama temizliği "bu gösterge
        artık güncel değil" der, "bir daha asla isteme" demez. Besleme aynı
        göstergeyi yeniden raporlarsa normal yoluyla geri gelmeli; dışlama
        listesine yazmak onu kalıcı olarak kör ederdi.
        """
        if self._db is None or not values or kind not in self.KEY_COLUMNS:
            return 0
        table, key = self.KEY_COLUMNS[kind]
        removed = 0
        # Parça parça: SQLite'ın değişken sayısı sınırı (varsayılan 999).
        for i in range(0, len(values), 500):
            chunk = values[i:i + 500]
            placeholders = ",".join("?" * len(chunk))
            cur = await self._db.execute(
                f"DELETE FROM {table} WHERE {key} IN ({placeholders})", chunk
            )
            removed += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        await self._db.commit()
        return removed

    # ── Eski 'malicious_urls' tablosu (14 Mayıs 2026 öncesi miras) ──

    _legacy_urls_present: Optional[bool] = None

    @staticmethod
    def url_host(url: str) -> str:
        """
        Eski tablodaki bir URL'den CrowdStrike'a basılmış ana makine adını
        çıkarır. Eski sürüm de tam olarak bunu yapıyordu: şema yoktu,
        değer doğrudan 'host/path' biçiminde saklanıyordu.
        """
        host = url.split("/", 1)[0].strip().lower().rstrip(".")
        # IPv6 köşeli parantezli biçim bu tabloda hiç geçmiyor; port ayıklanır.
        return host.split(":", 1)[0]

    @staticmethod
    def _like_escape(value: str) -> str:
        """LIKE kalıbındaki joker karakterleri etkisizleştirir."""
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    async def _has_legacy_urls(self) -> bool:
        """
        Tablo var mı? Sıfırdan kurulan bir veritabanında yok; her aramada
        hata yakalamak yerine bir kez bakılıp sonuç hatırlanır.
        """
        if self._legacy_urls_present is None:
            async with self._db.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'malicious_urls'"
            ) as cur:
                self._legacy_urls_present = await cur.fetchone() is not None
        return self._legacy_urls_present

    async def _legacy_url_matches(
        self, candidates: set[str], existing: list[dict]
    ) -> list[dict]:
        """
        Eski URL tablosunda, verilen adaylardan birine ait ana makine adını
        taşıyan satırları arar.

        Dönen kayıt URL değil ANA MAKİNE ADIdır: CrowdStrike'ta duran
        gösterge o. Tam URL'yi döndürmek, operatöre orada bulunmayan bir
        değeri silmeyi önermek olurdu.
        """
        if self._db is None or not await self._has_legacy_urls():
            return []

        # Zaten canlı tablolarda bulunan bir değeri ikinci kez göstermek,
        # panoda aynı göstergeyi iki satır hâlinde listelemek demek.
        already = {m["value"].lower() for m in existing}

        hosts: dict[str, dict] = {}
        for cand in candidates:
            pattern = self._like_escape(cand)
            async with self._db.execute(
                "SELECT url, added_at, pushed_to_cs FROM malicious_urls "
                "WHERE lower(url) = ? OR lower(url) LIKE ? ESCAPE '\\' "
                "   OR lower(url) LIKE ? ESCAPE '\\'",
                (cand, f"{pattern}/%", f"{pattern}:%"),
            ) as cur:
                rows = await cur.fetchall()

            for url, added_at, pushed in rows:
                host = self.url_host(url)
                # LIKE 'kisa.link/%' kalıbı 'kisa.link.kotu.com/x' gibi bir
                # değeri eşleştirmez ama emin olmak ucuz: ana makine adı
                # gerçekten aranan değer mi?
                if host != cand or host in already:
                    continue
                entry = hosts.get(host)
                if entry is None:
                    entry = {
                        "type": "ip" if looks_like_ipv4(host) else "domain",
                        "value": host,
                        "added_at": added_at,
                        "pushed": bool(pushed),
                        "blocked": False,
                        "blocked_reason": None,
                        "source": SOURCE_LEGACY_URL,
                        "legacy": True,
                        "legacy_url_count": 0,
                        "legacy_sample": url,
                    }
                    hosts[host] = entry
                entry["legacy_url_count"] += 1
                entry["pushed"] = entry["pushed"] or bool(pushed)
                if added_at and added_at < entry["added_at"]:
                    entry["added_at"] = added_at

        return list(hosts.values())

    async def purge_legacy_urls(self, host: str) -> int:
        """
        Bir ana makine adına ait tüm eski URL satırlarını siler.

        Silme akışının parçası olmak zorunda: satırlar kalırsa arama aynı
        göstergeyi bir sonraki sorguda yeniden bulur ve operatör hiç
        bitmeyen bir silme döngüsüne girer.
        """
        if self._db is None or not await self._has_legacy_urls():
            return 0

        host = host.strip().lower().rstrip(".")
        pattern = self._like_escape(host)
        async with self._db.execute(
            "SELECT url FROM malicious_urls "
            "WHERE lower(url) = ? OR lower(url) LIKE ? ESCAPE '\\' "
            "   OR lower(url) LIKE ? ESCAPE '\\'",
            (host, f"{pattern}/%", f"{pattern}:%"),
        ) as cur:
            doomed = [r[0] for r in await cur.fetchall() if self.url_host(r[0]) == host]

        if not doomed:
            return 0
        await self._db.executemany(
            "DELETE FROM malicious_urls WHERE url = ?", [(u,) for u in doomed]
        )
        return len(doomed)

    # ── Gösterge arama ve son eklenenler ──

    async def lookup_indicator(self, raw: str) -> dict:
        """
        Tek bir değeri üç tablonun tamamında arar.

        Domain için normalleştirilmiş biçim (küçük harf, 'www.' kırpılmış)
        de denenir: kullanıcı "www.Kotu-Site.com" yazdığında veritabanındaki
        "kotu-site.com" kaydını bulamamak yanlış bir "kayıt yok" cevabı olurdu.
        Hash aramasında sha256 ve md5 sütunlarının ikisine de bakılır.
        """
        value = (raw or "").strip()
        if not value:
            return {"query": raw, "found": False, "matches": []}

        lower = value.lower().rstrip(".")
        domain_norm = lower[4:] if lower.startswith("www.") else lower
        # 'www.' hem kırpılır hem EKLENİR. Kırpmak tek başına yetmiyor:
        # CrowdStrike değeri basıldığı gibi saklıyor ve eski URL yolundan
        # gelen kayıtların bir kısmı 'www.' önekli yazılmış. Yalnızca
        # kırpılmış biçimi aramak, 'kisa.link' sorgusunun CrowdStrike'ta
        # duran 'www.kisa.link' kaydını ıskalaması demek.
        candidates = {value, lower, domain_norm}
        if "." in domain_norm and not looks_like_ipv4(domain_norm):
            candidates.add(f"www.{domain_norm}")

        matches: list[dict] = []

        # IP — anahtar birebir saklanıyor
        for cand in candidates:
            async with self._db.execute(
                "SELECT ip, added_at, pushed_to_cs, push_blocked, blocked_reason, source "
                "FROM malicious_ips WHERE ip = ?",
                (cand,),
            ) as cur:
                row = await cur.fetchone()
            if row:
                matches.append({"type": "ip", "value": row[0], "added_at": row[1],
                                "pushed": bool(row[2]), "blocked": bool(row[3]),
                                "blocked_reason": row[4], "source": row[5]})
                break

        # Domain — orijinal ve normalleştirilmiş biçim
        seen_domains: set[str] = set()
        for cand in candidates:
            async with self._db.execute(
                "SELECT domain, added_at, pushed_to_cs, push_blocked, blocked_reason, "
                "source FROM malicious_domains WHERE domain = ? OR lower(domain) = ?",
                (cand, cand),
            ) as cur:
                for row in await cur.fetchall():
                    if row[0] in seen_domains:
                        continue
                    seen_domains.add(row[0])
                    matches.append({"type": "domain", "value": row[0],
                                    "added_at": row[1], "pushed": bool(row[2]),
                                    "blocked": bool(row[3]),
                                    "blocked_reason": row[4],
                                    "source": row[5]})

        # Hash — sha256 veya md5.
        # signature/file_name da döner: "bu hash neden gönderilmedi"
        # sorusunun cevabı bu iki alanda.
        async with self._db.execute(
            "SELECT sha256, md5, first_seen, added_at, pushed_to_cs, "
            "push_blocked, blocked_reason, signature, file_name, source "
            "FROM malicious_hashes WHERE sha256 = ? OR md5 = ?",
            (lower, lower),
        ) as cur:
            for row in await cur.fetchall():
                matches.append({
                    "type": "hash", "value": row[0], "md5": row[1],
                    "first_seen": row[2], "added_at": row[3],
                    "pushed": bool(row[4]),
                    "blocked": bool(row[5]), "blocked_reason": row[6],
                    "signature": row[7], "file_name": row[8], "source": row[9],
                    "matched_on": "md5" if row[1] and row[1] == lower else "sha256",
                })

        # Eski 'malicious_urls' tablosu — 14 Mayıs 2026 öncesi sürümün mirası.
        # O sürüm USOM'un url tipli kayıtlarını tam URL olarak bu tabloya
        # yazıyor, CrowdStrike'a ise yalnızca ana makine adını domain IOC'si
        # olarak basıyordu. URL ayrıştırma kaldırılınca (39e2e12) tablo yetim
        # kaldı: ana makine adları CrowdStrike'ta hâlâ duruyor ama yukarıdaki
        # üç tablonun hiçbirinde yok. Aranmazsa pano "kayıt yok" der ve
        # operatör hâlâ engelleme yapan bir göstergeyi silemez.
        matches.extend(await self._legacy_url_matches(candidates, matches))

        # Bu değer daha önce reddedildi mi? "Kayıtta var ama gönderilmemiş"
        # durumunun sebebini burada görmek, log dosyasına inmekten hızlı.
        rejections: list[dict] = []
        for cand in candidates:
            async with self._db.execute(
                "SELECT indicator_type, reason_class, reason, occurred_at "
                "FROM push_rejections WHERE value = ? ORDER BY id DESC LIMIT 5",
                (cand,),
            ) as cur:
                for row in await cur.fetchall():
                    rejections.append({
                        "type": row[0], "reason_class": row[1],
                        "label": REJECTION_LABELS.get(row[1], row[1]),
                        "reason": row[2], "occurred_at": row[3],
                    })
            if rejections:
                break

        # Silinmiş bir gösterge "kayıt bulunamadı" döner — beslemelerden
        # de çıktığı için istenen davranış bu. Ancak silinme kaydı
        # taşınır: "bu adres neden listede yok" sorusunun cevabı başka
        # hiçbir yerde yazmıyor ve cevapsız kalırsa servis arızalı görünür.
        deletions: list[dict] = []
        for cand in candidates:
            deletions = await self.get_deletions(cand)
            if deletions:
                break

        return {
            "query": value,
            "found": bool(matches),
            "matches": matches,
            "rejections": rejections,
            "deletions": deletions,
        }

    async def get_recent_indicators(
        self, limit: int = 50, kind: str = "all"
    ) -> list[dict]:
        """
        En son eklenen göstergeleri tip karışık, tarihe göre azalan döndürür.

        Her tablodan ayrı ayrı `limit` kadar çekip Python'da birleştirmek,
        tek bir UNION sorgusunu sıralatmaktan daha ucuz: her alt sorgu kendi
        added_at indeksini kullanabiliyor.
        """
        wanted = {"ip", "domain", "hash"} if kind == "all" else {kind}
        rows: list[dict] = []
        specs = (
            ("ip", "SELECT ip, added_at, pushed_to_cs FROM malicious_ips "
                   "ORDER BY added_at DESC LIMIT ?"),
            ("domain", "SELECT domain, added_at, pushed_to_cs FROM malicious_domains "
                       "ORDER BY added_at DESC LIMIT ?"),
            ("hash", "SELECT sha256, added_at, pushed_to_cs FROM malicious_hashes "
                     "ORDER BY added_at DESC LIMIT ?"),
        )
        for type_name, sql in specs:
            if type_name not in wanted:
                continue
            async with self._db.execute(sql, (limit,)) as cur:
                for row in await cur.fetchall():
                    rows.append({"type": type_name, "value": row[0],
                                 "added_at": row[1], "pushed": bool(row[2])})
        rows.sort(key=lambda r: r["added_at"] or "", reverse=True)
        return rows[:limit]

    async def get_source_counts(self) -> dict:
        """
        Kaynak ve gösterge tipi bazında kayıt sayıları.

        Pano bu kırılımı gösteriyor. Önceden kaynak, gösterge tipinden
        çıkarılıyordu (IP + alan adı = USOM, hash = MalwareBazaar); birden
        fazla kaynak aynı tabloya yazmaya başladığında bu varsayım yanlış
        oldu ve panel yanlış bilgi verir hâle geldi.

        Returns:
            {"usom": {"ip": n, "domain": n, "hash": n}, ...}
        """
        out: dict[str, dict[str, int]] = {}
        for kind, (table, _key) in self.KEY_COLUMNS.items():
            async with self._db.execute(
                f"SELECT COALESCE(source, ?) s, COUNT(*) FROM {table} GROUP BY s",
                (SOURCE_USOM,),
            ) as cur:
                for source, count in await cur.fetchall():
                    out.setdefault(source, {"ip": 0, "domain": 0, "hash": 0})
                    out[source][kind] = count
        return out

    # ── Dışa aktarım ──

    EXPORT_QUERIES = {
        "ip": ("SELECT ip, added_at, pushed_to_cs FROM malicious_ips "
               "ORDER BY added_at DESC", ("value", "added_at", "pushed_to_cs")),
        "domain": ("SELECT domain, added_at, pushed_to_cs FROM malicious_domains "
                   "ORDER BY added_at DESC", ("value", "added_at", "pushed_to_cs")),
        "hash": ("SELECT sha256, md5, first_seen, added_at, pushed_to_cs "
                 "FROM malicious_hashes ORDER BY added_at DESC",
                 ("sha256", "md5", "first_seen", "added_at", "pushed_to_cs")),
    }

    async def export_rows(self, kind: str):
        """
        Dışa aktarım satırlarını tek tek üretir (async generator).

        Sonuç listeye toplanmıyor: dört yüz binlik bir tabloyu belleğe
        alıp tek parça yanıt oluşturmak süreci gereksiz şişirir. Satırlar
        imleçten okundukça akışa yazılır.

        İmleç kapatma hatası yutulur: istemci indirmeyi yarıda keserse
        üretici tüketilmeden kapatılır ve temizlik, bağlantının kapanmış
        olabileceği bir anda çalışır. Bu, kaydedilecek bir arıza değil —
        yarıda kesilen her indirme log'a yığın izi bırakmamalı.
        """
        sql, _ = self.EXPORT_QUERIES[kind]
        cur = await self._db.execute(sql)
        try:
            async for row in cur:
                yield row
        finally:
            try:
                await cur.close()
            except Exception:
                pass

    # ── Dağılım istatistikleri ──

    async def get_tld_distribution(self, limit: int = 10) -> dict:
        """Alan adı uzantılarının en yoğun ilk N'i, kalanı 'diğer' olarak."""
        async with self._db.execute(
            "SELECT tld(domain) t, COUNT(*) n FROM malicious_domains "
            "WHERE t IS NOT NULL GROUP BY t ORDER BY n DESC LIMIT ?",
            (limit,),
        ) as cur:
            top = [{"key": r[0], "count": r[1]} for r in await cur.fetchall()]
        total = await self.get_domain_count()
        shown = sum(t["count"] for t in top)
        return {"items": top, "other": max(0, total - shown), "total": total}

    async def get_subnet_distribution(self, limit: int = 10) -> dict:
        """En çok zararlı IP barındıran /16 blokları."""
        async with self._db.execute(
            "SELECT subnet16(ip) s, COUNT(*) n FROM malicious_ips "
            "WHERE s IS NOT NULL GROUP BY s ORDER BY n DESC LIMIT ?",
            (limit,),
        ) as cur:
            top = [{"key": r[0], "count": r[1]} for r in await cur.fetchall()]
        total = await self.get_ip_count()
        shown = sum(t["count"] for t in top)
        return {"items": top, "other": max(0, total - shown), "total": total}

    async def get_hour_histogram(self, days: int = 7) -> dict:
        """
        Son N günde göstergelerin hangi UTC saatinde eklendiği.

        Saat dilimi çevrimi bilinçli olarak yapılmıyor: sunucunun yerel
        saati ile panoyu açan tarayıcının saat dilimi farklı olabilir.
        UTC kovaları döndürülüp kaydırma istemcide yapılır.
        """
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(sep=" ")
        buckets = [{"hour": h, "ip": 0, "domain": 0, "hash": 0} for h in range(24)]
        specs = (("malicious_ips", "ip"), ("malicious_domains", "domain"),
                 ("malicious_hashes", "hash"))
        for table, key in specs:
            async with self._db.execute(
                "SELECT CAST(substr(replace(added_at, 'T', ' '), 12, 2) AS INTEGER) h, "
                "COUNT(*) n FROM %s WHERE replace(added_at, 'T', ' ') >= ? "
                "GROUP BY h" % table,
                (since,),
            ) as cur:
                for hour, count in await cur.fetchall():
                    if hour is not None and 0 <= hour <= 23:
                        buckets[hour][key] = count
        return {"tz": "UTC", "days": days, "buckets": buckets}

    async def get_cumulative(self, days: int = 30) -> list[dict]:
        """
        Pencere boyunca kümülatif toplam kayıt sayısı.

        Günlük çubuk grafiği "bugün ne geldi" sorusunu cevaplıyor ama
        "liste ne kadar büyüdü" sorusunu cevaplamıyor — sıfır olan bir gün
        grafiği kesintiye uğramış gibi gösteriyor. Kümülatif eğri
        birikimi tek bakışta verir. Pencere başlangıcından önceki kayıtlar
        taban değeri olarak eklenir, aksi hâlde eğri sıfırdan başlar ve
        veritabanının gerçek boyutunu gizler.
        """
        daily = await self.get_daily_additions(days)
        if not daily:
            return []
        start = daily[0]["date"]
        base = {}
        for table, key in (("malicious_ips", "ip"), ("malicious_domains", "domain"),
                           ("malicious_hashes", "hash")):
            async with self._db.execute(
                "SELECT COUNT(*) FROM %s WHERE substr(added_at, 1, 10) < ?" % table,
                (start,),
            ) as cur:
                row = await cur.fetchone()
                base[key] = row[0] if row else 0
        out = []
        run = dict(base)
        for day in daily:
            for key in ("ip", "domain", "hash"):
                run[key] += day[key]
            out.append({"date": day["date"], **run,
                        "total": run["ip"] + run["domain"] + run["hash"]})
        return out

    # ── Senkronizasyon çalışma geçmişi ──

    async def start_sync_run(self, job: str) -> Optional[int]:
        """Bir görev çalışmasını kaydeder, satır id'sini döndürür."""
        try:
            cur = await self._db.execute(
                "INSERT INTO sync_runs (job, started_at, status) VALUES (?, ?, 'running')",
                (job, datetime.now(timezone.utc).isoformat()),
            )
            await self._db.commit()
            return cur.lastrowid
        except Exception as exc:
            logger.warning("Sync geçmişi yazılamadı (%s): %s", job, exc)
            return None

    async def finish_sync_run(
        self, run_id: Optional[int], *, new_records: int = 0,
        pushed: int = 0, status: str = "ok", detail: Optional[str] = None,
    ) -> None:
        """Çalışmayı sonuçlandırır. run_id None ise sessizce geçer."""
        if run_id is None:
            return
        try:
            now = datetime.now(timezone.utc)
            async with self._db.execute(
                "SELECT started_at FROM sync_runs WHERE id = ?", (run_id,)
            ) as cur:
                row = await cur.fetchone()
            duration_ms = None
            if row:
                try:
                    started = datetime.fromisoformat(row[0])
                    duration_ms = int((now - started).total_seconds() * 1000)
                except ValueError:
                    pass
            await self._db.execute(
                "UPDATE sync_runs SET finished_at = ?, duration_ms = ?, "
                "new_records = ?, pushed = ?, status = ?, detail = ? WHERE id = ?",
                (now.isoformat(), duration_ms, new_records, pushed, status,
                 detail, run_id),
            )
            await self._db.commit()
        except Exception as exc:
            logger.warning("Sync geçmişi güncellenemedi (id=%s): %s", run_id, exc)

    async def get_recent_runs(self, limit: int = 12) -> list[dict]:
        """
        Son çalışmaları en yeniden eskiye döndürür.

        detail alanı da taşınır: "✕ hata" satırı tek başına arızayı
        anlatmıyor, sebebi görmek için log'a inmek gerekiyordu.
        """
        async with self._db.execute(
            "SELECT job, started_at, duration_ms, new_records, pushed, status, detail "
            "FROM sync_runs ORDER BY id DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [
            {"job": r[0], "started_at": r[1], "duration_ms": r[2],
             "new_records": r[3], "pushed": r[4], "status": r[5], "detail": r[6]}
            for r in rows
        ]

    async def get_last_failures(self, limit: int = 5) -> list[dict]:
        """
        Her görev için en son BAŞARISIZ çalışma.

        Görev saat başı çalıştığı için başarısız bir çalışma birkaç saat
        içinde "son çalışmalar" listesinden düşüyor ve arıza görünmez hâle
        geliyor. Bu sorgu her görevin son hatasını, ne kadar süre önce
        olduğuna bakmadan yukarıda tutar.
        """
        async with self._db.execute(
            "SELECT job, started_at, status, detail FROM sync_runs "
            "WHERE id IN (SELECT MAX(id) FROM sync_runs "
            "WHERE status != 'ok' GROUP BY job) ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
        return [
            {"job": r[0], "started_at": r[1], "status": r[2], "detail": r[3]}
            for r in rows
        ]

    async def get_run_reliability(self, hours: int = 24) -> dict:
        """Son N saatteki çalışma sayısı ve başarı oranı."""
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        async with self._db.execute(
            "SELECT status, COUNT(*) FROM sync_runs WHERE started_at >= ? "
            "GROUP BY status", (since,)
        ) as cur:
            rows = dict(await cur.fetchall())
        ok = rows.get("ok", 0)
        total = sum(rows.values())
        return {"total": total, "ok": ok, "failed": total - ok}

    async def get_daily_additions(self, days: int = 30) -> list[dict]:
        """
        Son N gün için tablo bazında günlük yeni kayıt sayısı.

        Pencere bilinçli olarak dardır: ilk tam yükleme günleri (tek günde
        yüz binlerce kayıt) pencerenin dışında kalır ve günlük akışı
        ezmez. Kayıt olmayan günler 0 olarak doldurulur, böylece grafikte
        boşluk gerçek boşluk olarak görünür.
        """
        today = datetime.now(timezone.utc).date()
        start = today - timedelta(days=days - 1)
        buckets = {
            (start + timedelta(days=i)).isoformat(): {"ip": 0, "domain": 0, "hash": 0}
            for i in range(days)
        }
        tables = (("malicious_ips", "ip"), ("malicious_domains", "domain"),
                  ("malicious_hashes", "hash"))
        for table, key in tables:
            async with self._db.execute(
                "SELECT substr(added_at, 1, 10) d, COUNT(*) n FROM %s "
                "WHERE substr(added_at, 1, 10) >= ? GROUP BY d" % table,
                (start.isoformat(),),
            ) as cur:
                for day, count in await cur.fetchall():
                    if day in buckets:
                        buckets[day][key] = count
        return [{"date": d, **v} for d, v in sorted(buckets.items())]

    async def get_additions_since(self, hours: int) -> dict:
        """Son N saatte eklenen kayıt sayısı (tip bazında)."""
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        out = {}
        for table, key in (("malicious_ips", "ip"), ("malicious_domains", "domain"),
                           ("malicious_hashes", "hash")):
            async with self._db.execute(
                "SELECT COUNT(*) FROM %s WHERE added_at >= ?" % table, (since,)
            ) as cur:
                row = await cur.fetchone()
                out[key] = row[0] if row else 0
        out["total"] = sum(out.values())
        return out

    async def set_meta(self, key: str, value: str) -> None:
        """service_meta tablosuna bir durum damgası yazar (upsert)."""
        await self._db.execute(
            "INSERT INTO service_meta (key, value, updated_at) "
            "VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(key) DO UPDATE SET "
            "value = excluded.value, updated_at = excluded.updated_at",
            (key, value),
        )
        await self._db.commit()

    async def get_meta(self, key: str) -> Optional[str]:
        """service_meta tablosundan bir durum damgası okur."""
        async with self._db.execute(
            "SELECT value FROM service_meta WHERE key = ?", (key,)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

    async def close(self) -> None:
        """Veritabanı bağlantısını kapat."""
        if self._db:
            await self._db.close()
            logger.info("Veritabanı bağlantısı kapatıldı.")

    async def insert_ips(self, ip_list: list[str], source: str = SOURCE_USOM) -> int:
        """
        IP listesini toplu olarak veritabanına ekler.

        INSERT OR IGNORE sayesinde zaten var olan IP'ler sessizce atlanır,
        böylece duplicate oluşmaz. Aynı IP birden fazla kaynakta
        görünüyorsa ilk kaydeden kaynak korunur — göstergenin kendisi aynı
        olduğu için ikinci kez yazmanın bir faydası yok, üstelik
        pushed_to_cs=1 durumunu sıfırlamak onu gereksiz yeniden gönderirdi.

        Args:
            ip_list: Eklenecek IP adresleri listesi.
            source: Göstergenin geldiği besleme (SOURCE_* sabitleri).

        Returns:
            Yeni eklenen IP adres sayısı.
        """
        if not ip_list:
            return 0

        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")

        # Operatörün sildiği adresler USOM'dan gelmeye devam ediyor;
        # filtrelenmezse silme bir sonraki sync'te geri alınmış olur.
        ip_list = await self.filter_excluded("ip", ip_list)
        if not ip_list:
            return 0

        now = datetime.now(timezone.utc).isoformat()
        data = [(ip, now, source, now) for ip in ip_list]

        async with self._db.execute("SELECT COUNT(*) FROM malicious_ips") as cur:
            row = await cur.fetchone()
            before_count = row[0] if row else 0

        # INSERT OR IGNORE yerine upsert: zaten var olan bir kayıtta
        # last_seen_at tazelenmeli, yoksa hâlâ aktif bir gösterge saklama
        # süresini doldurup silinirdi. added_at, source ve pushed_to_cs'ye
        # DOKUNULMAZ — "ne zaman ilk gördük", "hangi besleme" ve "basıldı mı"
        # bilgileri korunur.
        await self._db.executemany(
            "INSERT INTO malicious_ips (ip, added_at, source, last_seen_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET last_seen_at = excluded.last_seen_at",
            data,
        )
        await self._db.commit()

        async with self._db.execute("SELECT COUNT(*) FROM malicious_ips") as cur:
            row = await cur.fetchone()
            after_count = row[0] if row else 0

        return after_count - before_count

    async def ip_exists(self, ip: str) -> bool:
        """Belirli bir IP adresinin veritabanında mevcut olup olmadığını kontrol eder."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute(
            "SELECT 1 FROM malicious_ips WHERE ip = ?", (ip,)
        ) as cur:
            return await cur.fetchone() is not None

    async def get_all_ips(self) -> list[str]:
        """Tüm IP adreslerini sıralı liste olarak döndürür."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute(
            "SELECT ip FROM malicious_ips ORDER BY ip"
        ) as cur:
            rows = await cur.fetchall()
        return [row[0] for row in rows]

    async def get_ip_count(self) -> int:
        """Veritabanındaki toplam IP adres sayısını döndürür."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute("SELECT COUNT(*) FROM malicious_ips") as cur:
            row = await cur.fetchone()
            count = row[0] if row else 0
        return count

    async def get_last_updated(self) -> Optional[str]:
        """Veritabanına eklenen en son IP'nin zaman damgasını döndürür."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute("SELECT MAX(added_at) FROM malicious_ips") as cur:
            row = await cur.fetchone()
            return row[0] if row else None

    async def clear_all(self) -> None:
        """Tüm IP adreslerini siler (Full Sync öncesi temizlik için)."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        await self._db.execute("DELETE FROM malicious_ips")
        await self._db.commit()
        logger.warning("Veritabanındaki tüm IP kayıtları silindi (Full Sync hazırlığı).")

    async def get_unpushed_ips(self) -> list[str]:
        """CrowdStrike'a henüz gönderilmemiş IP'leri döndürür."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute(
            "SELECT ip FROM malicious_ips "
            "WHERE pushed_to_cs = 0 AND push_blocked = 0 ORDER BY added_at"
        ) as cur:
            rows = await cur.fetchall()
        return [row[0] for row in rows]

    # Saklama süresi ve etiket kaynağa göre değiştiği için gönderim de
    # kaynak kaynak yapılmalı; karışık bir batch'e tek bir expiration
    # yazmak, Brandefense'in 30 günlük TTL'ini süresiz USOM göstergelerine
    # de uygulardı (ya da tersi).
    UNPUSHED_QUERIES = {
        "ip": ("malicious_ips", "ip"),
        "domain": ("malicious_domains", "domain"),
        "hash": ("malicious_hashes", "sha256"),
    }

    async def get_unpushed_grouped(self, kind: str) -> dict[str, list[str]]:
        """
        Gönderilmemiş göstergeleri {kaynak: [değer, …]} olarak döndürür.

        Sıralama added_at: en eski bekleyen önce gider, böylece kuyruğun
        dibinde kalmış göstergeler her turda yeniden sona atılmaz.
        """
        if self._db is None or kind not in self.UNPUSHED_QUERIES:
            return {}
        table, key = self.UNPUSHED_QUERIES[kind]
        grouped: dict[str, list[str]] = {}
        async with self._db.execute(
            f"SELECT source, {key} FROM {table} "
            f"WHERE pushed_to_cs = 0 AND push_blocked = 0 ORDER BY added_at"
        ) as cur:
            for source, value in await cur.fetchall():
                grouped.setdefault(source or SOURCE_USOM, []).append(value)
        return grouped

    async def mark_ips_pushed(self, ip_list: list[str]) -> None:
        """Belirtilen IP'leri CrowdStrike'a gönderildi olarak işaretler."""
        if self._db is None or not ip_list:
            return
        await self._db.executemany(
            "UPDATE malicious_ips SET pushed_to_cs = 1 WHERE ip = ?",
            [(ip,) for ip in ip_list],
        )
        await self._db.commit()

    async def get_pushed_count(self) -> int:
        """CrowdStrike'a gönderilmiş toplam IP sayısını döndürür."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute("SELECT COUNT(*) FROM malicious_ips WHERE pushed_to_cs = 1") as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    # ── Domain Metodları ──
    async def insert_domains(
        self, domain_list: list[str], source: str = SOURCE_USOM
    ) -> int:
        """Domain listesini toplu olarak ekler (bkz. insert_ips)."""
        if not domain_list or self._db is None:
            return 0
        # bkz. insert_ips: silinen domain beslemeden geri gelmemeli.
        domain_list = await self.filter_excluded("domain", domain_list)
        if not domain_list:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        data = [(d, now, source, now) for d in domain_list]
        async with self._db.execute("SELECT COUNT(*) FROM malicious_domains") as cur:
            before = (await cur.fetchone())[0]
        # bkz. insert_ips: upsert'in tek amacı last_seen_at'i tazelemek.
        await self._db.executemany(
            "INSERT INTO malicious_domains (domain, added_at, source, last_seen_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(domain) DO UPDATE SET last_seen_at = excluded.last_seen_at",
            data)
        await self._db.commit()
        async with self._db.execute("SELECT COUNT(*) FROM malicious_domains") as cur:
            after = (await cur.fetchone())[0]
        return after - before

    async def get_all_domains(self) -> list[str]:
        """Tüm zararlı domainleri döndürür."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute("SELECT domain FROM malicious_domains ORDER BY domain") as cur:
            return [row[0] for row in await cur.fetchall()]

    async def get_domain_count(self) -> int:
        """Veritabanındaki toplam domain sayısını döndürür."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute("SELECT COUNT(*) FROM malicious_domains") as cur:
            return (await cur.fetchone())[0]

    async def domain_exists(self, domain: str) -> bool:
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute("SELECT 1 FROM malicious_domains WHERE domain = ?", (domain,)) as cur:
            return await cur.fetchone() is not None

    async def get_unpushed_domains(self) -> list[str]:
        """CrowdStrike'a henüz gönderilmemiş domainleri döndürür."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute(
            "SELECT domain FROM malicious_domains "
            "WHERE pushed_to_cs = 0 AND push_blocked = 0 ORDER BY added_at"
        ) as cur:
            return [row[0] for row in await cur.fetchall()]

    async def mark_domains_pushed(self, domain_list: list[str]) -> None:
        """Belirtilen domainleri CrowdStrike'a gönderildi olarak işaretler."""
        if self._db is None or not domain_list:
            return
        await self._db.executemany(
            "UPDATE malicious_domains SET pushed_to_cs = 1 WHERE domain = ?",
            [(d,) for d in domain_list],
        )
        await self._db.commit()

    async def get_pushed_domain_count(self) -> int:
        """CrowdStrike'a gönderilmiş toplam domain sayısını döndürür."""
        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")
        async with self._db.execute("SELECT COUNT(*) FROM malicious_domains WHERE pushed_to_cs = 1") as cur:
            return (await cur.fetchone())[0]


# ─────────────────────────────────────────────────────
# 2. VERİ ÇEKME KATMANI (USOM API Client)
# ─────────────────────────────────────────────────────
class USOMClient:
    """
    USOM API'sine asenkron HTTP istekleri gönderen istemci.

    Özellikler:
        - httpx.AsyncClient ile connection pooling
        - tenacity ile exponential backoff retry
        - asyncio.Semaphore ile eşzamanlı istek sınırlama (rate limit koruması)
    """

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async def start(self) -> None:
        """HTTP istemcisini başlat."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(HTTP_TIMEOUT),
            # USOM API bazı istemcileri engelleyebilir; tarayıcı benzeri User-Agent
            headers={
                "User-Agent": "USOMListService/1.0 (Threat Intelligence Aggregator)",
                "Accept": "application/json",
            },
            # Bağlantı havuzu - aynı host'a birden fazla bağlantıyı verimli yönetir
            limits=httpx.Limits(
                max_connections=MAX_CONCURRENT_REQUESTS + 5,
                max_keepalive_connections=MAX_CONCURRENT_REQUESTS,
            ),
        )
        logger.info("USOM HTTP istemcisi başlatıldı.")

    async def stop(self) -> None:
        """HTTP istemcisini kapat."""
        if self._client:
            await self._client.aclose()
            logger.info("USOM HTTP istemcisi kapatıldı.")

    @retry(
        stop=stop_after_attempt(MAX_RETRY_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TransportError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    async def fetch_page(self, page: int, data_type: str = "ip") -> dict:
        """
        Belirli bir sayfa numarasından veri çeker.

        Args:
            page: Çekilecek sayfa numarası (0-indexed).
            data_type: Veri tipi ('ip', 'url', 'domain').

        Returns:
            API'den dönen JSON yanıtı (dict).
        """
        if self._client is None:
            raise RuntimeError("HTTP istemcisi henüz başlatılmadı.")

        async with self._semaphore:
            response = await self._client.get(
                USOM_BASE_URL,
                params={"type": data_type, "page": page},
            )
            response.raise_for_status()
            return response.json()

    @staticmethod
    def extract_ips(api_response: dict) -> list[str]:
        """
        API yanıtındaki JSON verisinden sadece IP adreslerini ayıklar.

        USOM API formatı:
            {"totalCount": N, "models": [{"url": "1.2.3.4", ...}, ...], "pageCount": M}

        'url' alanı IP adresini içerir (isim yanıltıcı olsa da API böyle döndürür).
        """
        models = api_response.get("models", [])
        return [
            model["url"]
            for model in models
            if model.get("url") and model.get("type") == "ip"
        ]

    @staticmethod
    def extract_domains(api_response: dict) -> list[str]:
        """API yanıtındaki JSON verisinden zararlı domainleri ayıklar ve whitelist'e göre filtreler."""
        models = api_response.get("models", [])
        domains = []
        for model in models:
            domain = model.get("url")
            if domain and model.get("type") == "domain":
                domain_lower = domain.lower()
                if domain_lower.startswith("www."):
                    domain_lower = domain_lower[4:]
                
                is_whitelisted = any(
                    domain_lower == wd or domain_lower.endswith(f".{wd}")
                    for wd in WHITELISTED_DOMAINS
                )
                # Paylaşımlı altyapının apex'i hiç alınmaz: aksi hâlde yalnızca
                # CrowdStrike'a değil, /usom-domains beslemesini tüketen güvenlik
                # duvarlarına da gider ve tüm servisi kesecek bir kural doğurur.
                if is_whitelisted:
                    continue
                if is_shared_infra_apex(domain_lower):
                    logger.info(
                        "Paylaşımlı altyapı alan adı atlandı (apex): %s", domain
                    )
                    continue
                domains.append(domain)
        return domains


# ─────────────────────────────────────────────────────
# 2.b MALWAREBAZAAR (abuse.ch) HASH KAYNAĞI
# ─────────────────────────────────────────────────────
class MalwareBazaarClient:
    """
    abuse.ch MalwareBazaar'dan güncel zararlı yazılım hash'lerini çeker.

    "recent" dökümü son ~48 saatte görülen örnekleri içerir (~1.400 kayıt,
    günlük ~700 yeni). API anahtarı gerektirmez. Kalıcı arşiv yerel
    veritabanında birikir — döküm penceresi kaydırdıkça eski kayıtlar
    kaybolmaz.
    """

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(MALWAREBAZAAR_TIMEOUT),
            headers={"User-Agent": "USOMListService/1.0"},
            follow_redirects=True,
        )
        logger.info("MalwareBazaar istemcisi başlatıldı.")

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()
            logger.info("MalwareBazaar istemcisi kapatıldı.")

    @retry(
        stop=stop_after_attempt(MAX_RETRY_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TransportError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )
    async def fetch_recent(self) -> str:
        """Güncel CSV dökümünü ham metin olarak indirir."""
        response = await self._client.get(MALWAREBAZAAR_CSV_URL)
        response.raise_for_status()
        return response.text

    @staticmethod
    def parse_csv(raw: str) -> list[tuple[str, str, str, str, str]]:
        """
        CSV dökümünü (sha256, md5, first_seen, signature, file_name)
        beşlilerine ayrıştırır.

        signature ve file_name gönderim kararı için gerekli: aksiyon
        "prevent" olduğu için sınıflandırılmamış örnekler ve sistem
        ikilisi adı taşıyan dosyalar CrowdStrike'a basılmaz
        (bkz. hash_push_block_reason).

        Döküm başlıksızdır; kolon sırası MB_COL_* sabitleriyle tanımlı.
        '#' ile başlayan yorum satırları ve bozuk satırlar atlanır.
        """
        import csv as _csv
        import io as _io

        records: list[tuple[str, str, str, str, str]] = []
        seen: set[str] = set()
        malformed = 0

        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = next(_csv.reader(_io.StringIO(line), skipinitialspace=True))
            except Exception:
                malformed += 1
                continue

            if len(row) <= MB_COL_MD5:
                malformed += 1
                continue

            sha256 = row[MB_COL_SHA256].strip().lower()
            md5 = row[MB_COL_MD5].strip().lower()
            first_seen = row[MB_COL_FIRST_SEEN].strip()
            # signature/file_name kolonları eksik olabilir (döküm formatı
            # değişirse). Eksikse boş geçilir; boş imza "sınıflandırılmamış"
            # sayıldığı için sonuç güvenli tarafta kalır — gönderilmez.
            signature = (row[MB_COL_SIGNATURE].strip()
                         if len(row) > MB_COL_SIGNATURE else "")
            file_name = (row[MB_COL_FILE_NAME].strip()
                         if len(row) > MB_COL_FILE_NAME else "")

            # sha256 biçim doğrulaması — kolon kayması olursa sessizce
            # çöp veri yazmak yerine kaydı atla.
            if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
                malformed += 1
                continue
            if len(md5) != 32 or not all(c in "0123456789abcdef" for c in md5):
                md5 = ""

            if sha256 in seen:
                continue
            seen.add(sha256)
            records.append((sha256, md5, first_seen, signature, file_name))

        if malformed:
            logger.warning(
                "MalwareBazaar: %d satır ayrıştırılamadı (kolon yapısı değişmiş olabilir).",
                malformed,
            )
        return records


class BrandefenseClient:
    """
    Brandefense Threat Intelligence IOC beslemesinden gösterge çeker.

    Yalnızca alan adı ve IPv4 alınır (bkz. BRANDEFENSE_BASE_URL yorumu):
    hash beslemesi zaten doğrudan çektiğimiz MalwareBazaar'ın MD5
    kopyası ve imza alanı taşımadığı için yanlış pozitif korumasını
    devre dışı bırakırdı; URL tipinin CrowdStrike'ta karşılığı yok.

    Sayfalama cursor tabanlı: yanıttaki "next" alanı bir sonraki sayfanın
    tam URL'ini veriyor, sayfa numarası yok. Sonuç bittiğinde next null
    döner.
    """

    # data_type değerleri (doğrulanmış 2026-08-20)
    DT_IPV4 = "ipv4_address"
    DT_IPV6 = "ipv6_address"
    DT_DOMAIN = "domain"

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self.api_key = os.getenv("BRANDEFENSE_API_KEY", "").strip()
        self.enabled = bool(self.api_key)
        # Son çalışmanın özeti — /health ve pano bunu okur
        self.last_sync_time: Optional[datetime] = None
        self.last_error: Optional[str] = None

    async def start(self) -> None:
        if not self.enabled:
            logger.info("Brandefense entegrasyonu kapalı (BRANDEFENSE_API_KEY yok).")
            return
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(BRANDEFENSE_TIMEOUT),
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {self.api_key}",
                "User-Agent": "USOMListService/1.0",
            },
            follow_redirects=True,
        )
        logger.info("Brandefense istemcisi başlatıldı.")

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()
            logger.info("Brandefense istemcisi kapatıldı.")

    async def _get(self, url: str, params: Optional[dict] = None) -> Optional[dict]:
        """
        Tek bir sayfayı çeker; geçici hatalarda artan bekleme ile yeniden dener.

        API yük altında 503 döndürüyor (gözlemlendi). tenacity dekoratörü
        yerine elle döngü kullanılıyor çünkü burada "başarısızsa None dön,
        senkronizasyonu tamamen düşürme" davranışı isteniyor: yarım
        çekilmiş bir sayfa kümesi de değerlidir.
        """
        for attempt in range(BRANDEFENSE_RETRIES):
            try:
                resp = await self._client.get(url, params=params)
                if resp.status_code in (429, 500, 502, 503, 504):
                    raise httpx.HTTPStatusError(
                        f"geçici hata {resp.status_code}",
                        request=resp.request, response=resp,
                    )
                resp.raise_for_status()
                return resp.json()
            except (httpx.HTTPStatusError, httpx.TransportError,
                    json.JSONDecodeError) as exc:
                if attempt < BRANDEFENSE_RETRIES - 1:
                    wait = 2 * (attempt + 1)
                    logger.warning(
                        "Brandefense isteği başarısız (%s), %d sn sonra yeniden "
                        "denenecek (%d/%d).",
                        exc, wait, attempt + 1, BRANDEFENSE_RETRIES,
                    )
                    await asyncio.sleep(wait)
                    continue
                logger.error("Brandefense isteği kalıcı olarak başarısız: %s", exc)
                self.last_error = str(exc)[:200]
                return None
        return None

    async def iter_pages(self, ioc_type: str, period: str = BRANDEFENSE_PERIOD):
        """
        Sayfaları tek tek üretir (async generator).

        Tüm sayfaları toplayıp döndürmek yerine sayfa sayfa vermek gerekli,
        çünkü nerede duracağımıza çağıran karar veriyor:

        Ölçüldü (2026-08-20): period parametresi sonuç kümesini beklendiği
        gibi 24 saate indirmiyor. domain için 10 sayfada (4.894 kayıt)
        doğal olarak bitiyor, ama ip_address için cursor aylar geriye
        gidiyor — 20. sayfada Ocak 2025'e ulaşmıştı. Yani her turda tüm
        arşiv baştan taranır: 10+ dakika süren, API'yi 503'e sokan ve
        neredeyse tamamı zaten bilinen veriyi çeken bir tur.

        Kayıtlar yeniden eskiye sıralı olduğu için çağıran, artık yeni
        kayıt gelmediğini görünce durabilir (bkz. brandefense_sync).
        """
        if not self.enabled or self._client is None:
            return

        url: Optional[str] = BRANDEFENSE_BASE_URL
        params: Optional[dict] = {
            "ioc_type": ioc_type,
            "size": BRANDEFENSE_PAGE_SIZE,
            "period": period,
        }
        pages = 0

        while url and pages < BRANDEFENSE_MAX_PAGES:
            data = await self._get(url, params)
            if data is None:
                return
            results = data.get("results") or []
            pages += 1
            if not results:
                return
            yield results
            # "next" tam URL döndürüyor; parametreler onun içinde zaten var
            url = data.get("next")
            params = None
            if url:
                await asyncio.sleep(BRANDEFENSE_PAGE_DELAY)

        if url and pages >= BRANDEFENSE_MAX_PAGES:
            logger.warning(
                "Brandefense %s: sayfa sınırına ulaşıldı (%d sayfa). Daha eski "
                "kayıtlar bu turda ALINMADI — kırpma sessiz kalmasın diye "
                "loglanıyor.",
                ioc_type, pages,
            )

    @staticmethod
    def extract_values(records: list[dict], wanted_data_types: set[str]) -> list[str]:
        """
        Kayıtlardan yalnızca istenen data_type'lara ait değerleri süzer.

        data_type kullanılıyor, type değil: type "ip_address" derken
        data_type IPv4 ile IPv6'yı ayırıyor. CrowdStrike'a yalnızca ipv4
        tipinde gösterge basıldığı için IPv6 kayıtları burada elenir —
        gönderilseler 400 alır ve kuyruğu tıkarlardı.
        """
        out: list[str] = []
        seen: set[str] = set()
        for rec in records:
            if rec.get("data_type") not in wanted_data_types:
                continue
            value = (rec.get("data") or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            out.append(value)
        return out


# ─────────────────────────────────────────────────────
# 3. CROWDSTRIKE FALCON API KATMANI
# ─────────────────────────────────────────────────────
class CrowdStrikeService:
    """
    Zararlı IP adreslerini CrowdStrike Falcon IOC (Indicators of Compromise)
    veritabanına gönderir.
    """
    def __init__(self):
        self.client_id = os.getenv("FALCON_CLIENT_ID")
        self.client_secret = os.getenv("FALCON_CLIENT_SECRET")
        self.base_url = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com")
        self.action = os.getenv("FALCON_IOC_ACTION", "detect")

        # domain/ipv4 için geçerli aksiyona kelepçele
        if self.action in CS_NETWORK_ALLOWED_ACTIONS:
            self.network_action = self.action
        else:
            logger.warning(
                "FALCON_IOC_ACTION='%s' domain/IP tipleri için CrowdStrike "
                "tarafından kabul edilmiyor (yalnızca %s geçerli). "
                "'%s' kullanılacak.",
                self.action,
                ", ".join(sorted(CS_NETWORK_ALLOWED_ACTIONS)),
                CS_NETWORK_FALLBACK_ACTION,
            )
            self.network_action = CS_NETWORK_FALLBACK_ACTION

        # Hash aksiyonu ayrı yapılandırılır: sha256 tipinde CrowdStrike
        # "prevent"i kabul eder, yani dosya çalıştırma gerçekten engellenir.
        # Bu, domain/IP'deki "detect"ten farklı bir risk profilidir — yanlış
        # pozitif bir hash meşru bir dosyayı kurum genelinde bloke eder.
        self.hash_action = os.getenv("FALCON_HASH_ACTION", "prevent")
        if self.hash_action not in CS_HASH_ALLOWED_ACTIONS:
            logger.warning(
                "FALCON_HASH_ACTION='%s' geçersiz (yalnızca %s kabul edilir). "
                "'%s' kullanılacak.",
                self.hash_action,
                ", ".join(sorted(CS_HASH_ALLOWED_ACTIONS)),
                CS_HASH_FALLBACK_ACTION,
            )
            self.hash_action = CS_HASH_FALLBACK_ACTION

        self.enabled = bool(self.client_id and self.client_secret)

        # Gönderimi silmeden ayrı kapatabilmek için.
        #
        # Kimlik bilgilerini .env'den silmek push'u durdurur ama silme
        # özelliğini de çalışmaz hâle getirir — ikisi aynı istemciyi
        # kullanıyor. Tenant'ın gösterge limiti dolduğunda ya da bir
        # inceleme sırasında istenen genellikle "yeni basma, ama mevcut
        # göstergeleri yönetebileyim" oluyor. Bu bayrak tam olarak onu verir.
        #
        # Varsayılan açık: mevcut kurulumların davranışı değişmez.
        self.push_enabled = os.getenv(
            "FALCON_PUSH_ENABLED", "true"
        ).strip().lower() not in ("false", "0", "no", "hayir", "off")

        self.total_pushed_session = 0
        self.connection_status = "uninitialized"
        self._ioc_client = None
        self.last_push_time: Optional[datetime] = None
        # Red kayıtlarını yazmak için veritabanı referansı. Servis
        # nesnesi uygulama açılışında oluşturulduğu, veritabanı ise
        # lifespan içinde bağlandığı için sonradan atanır; None kalırsa
        # redler yalnızca log'a yazılır ve push akışı bozulmaz.
        self.db = None

        if self.enabled:
            try:
                # falconpy kütüphanesini içe aktar
                from falconpy import IOC
                # timeout ZORUNLU: verilmezse falconpy sonsuza kadar bekler ve
                # ölü bir bağlantıda zamanlanmış görev kalıcı olarak kilitlenir.
                self._ioc_client = IOC(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    base_url=self.base_url,
                    timeout=(CS_CONNECT_TIMEOUT, CS_READ_TIMEOUT),
                )
                self.connection_status = "connected"
                logger.info(
                    "CrowdStrike entegrasyonu aktif (domain/IP action: %s | hash action: %s).",
                    self.network_action,
                    self.hash_action,
                )
            except Exception as e:
                self.enabled = False
                self.connection_status = f"error: {str(e)}"
                logger.error("CrowdStrike başlatılamadı: %s", e)
        else:
            self.connection_status = "disabled (no credentials)"
            logger.info("CrowdStrike entegrasyonu kapalı (.env eksik).")

    async def _record_rejections(
        self, indicator_type: str, rejected: list[tuple[str, str]]
    ) -> None:
        """
        Redleri kaydeder ve kalıcı olanları bloke olarak işaretler.

        Ayrım kritik: geçici bir arıza (zaman aşımı, hız sınırı) sonrası
        gösterge tekrar denenmeli, ama CrowdStrike'ın kabul etmediği bir
        değer sonsuza kadar kuyrukta dönmemeli.
        """
        if not rejected or self.db is None:
            return
        await self.db.record_rejections(indicator_type, rejected)

        permanent = [
            (value, reason) for value, reason in rejected
            if classify_rejection(reason) in PERMANENT_REJECTION_CLASSES
        ]
        if permanent:
            marked = await self.db.mark_blocked(indicator_type, permanent)
            logger.warning(
                "CrowdStrike %s: %d gösterge kalıcı olarak gönderilemez "
                "kabul edildi ve kuyruktan çıkarıldı (bloke). Sebep örneği: %s",
                indicator_type, marked, permanent[0][1],
            )

    async def _send_indicator_batch(
        self, indicators: list[dict], label: str, *, ignore_warnings: bool = False
    ) -> tuple[list[str], list[str], list[tuple[str, str]]]:
        """
        Tek bir batch'i CrowdStrike'a gönderir; duplicate ve geçersiz
        göstergeleri ayıklayıp kalanı yeniden dener.

        CrowdStrike batch'te tek bir sorunlu satır bulursa isteğin TAMAMINI
        400 ile reddeder ve geçerli yeni göstergeleri de yazmaz. Bu nedenle
        400 yanıtındaki resources[] satır satır ayrıştırılır.

        Returns:
            (created, already_present, rejected).
            created + already_present CrowdStrike'ta mevcut demektir; ikisi de
            veritabanında "gönderildi" olarak işaretlenmelidir. Aksi hâlde
            zaten var olan göstergeler her turda tekrar denenip batch'i bozar.

            rejected, (değer, sebep) çiftlerinden oluşur. Sebep taşınıyor
            çünkü panoda "reddedildi" sayısı tek başına aksiyon almaya
            yetmiyor: uzunluk sınırı beklenen ve kalıcı bir durumken,
            kimlik doğrulama hatası derhal müdahale gerektirir.

        ignore_warnings:
            CrowdStrike, bir göstergenin yaygın bir uygulamaya ait
            olabileceğini düşündüğünde uyarı döndürür ve isteği yazmaz.
            Örnek: MalwareBazaar'a anonim olarak, imzasız gönderilmiş
            "cmd.exe" adlı bir dosyanın hash'i. Bu uyarıyı hash tipinde
            görmezden gelmek, aksiyon "prevent" olduğu için o sistem
            ikilisini kurum genelinde engellemek anlamına gelir.

            Bu yüzden varsayılan False'tur — zamanlanmış görevler asla
            uyarıyı ezmez. True yalnızca operatör bloke listesini görüp
            bilinçli olarak yeniden deneme tetiklediğinde geçilir.
        """
        created: list[str] = []
        already_present: list[str] = []
        rejected: list[tuple[str, str]] = []
        pending = list(indicators)

        for _ in range(CS_MAX_BATCH_RETRIES):
            if not pending:
                break

            try:
                # Bloklayıcı API çağrısını thread'e al.
                # wait_for ikinci savunma hattı: falconpy timeout'u bir şekilde
                # devreye girmezse bile görev burada takılı kalmaz.
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        self._ioc_client.indicator_create,
                        body={"indicators": pending},
                        ignore_warnings=ignore_warnings,
                    ),
                    timeout=CS_BATCH_TIMEOUT,
                )
            except asyncio.TimeoutError:
                logger.error(
                    "CrowdStrike %s batch'i %.0f sn içinde yanıt vermedi, "
                    "atlanıyor (%d gösterge).",
                    label, CS_BATCH_TIMEOUT, len(pending),
                )
                reason = f"CrowdStrike batch timeout: {CS_BATCH_TIMEOUT:.0f} sn içinde yanıt vermedi"
                rejected.extend((i["value"], reason) for i in pending)
                return created, already_present, rejected
            except Exception as exc:
                logger.error("CrowdStrike %s API Exception: %s", label, exc)
                rejected.extend((i["value"], f"API exception: {exc}") for i in pending)
                return created, already_present, rejected

            status_code = response.get("status_code", 0)
            body = response.get("body") or {}

            if status_code in (200, 201):
                created.extend(i["value"] for i in pending)
                return created, already_present, rejected

            if status_code != 400:
                errors = body.get("errors", [])
                logger.error(
                    "CrowdStrike %s batch push hatası (status %s): %s",
                    label, status_code, errors,
                )
                reason = f"HTTP {status_code}: {_first_error_message(errors)}"
                rejected.extend((i["value"], reason) for i in pending)
                return created, already_present, rejected

            # 400 → satır bazlı uyarıları ayrıştır
            dup_values: set[str] = set()
            bad_rows: dict[str, str] = {}
            for row in body.get("resources") or []:
                if not isinstance(row, dict):
                    continue
                value = row.get("value")
                if not value:
                    continue
                message = row.get("message") or ""
                if "duplicate" in message.lower():
                    dup_values.add(value)
                else:
                    bad_rows[value] = message
                    logger.warning(
                        "CrowdStrike %s göstergesi reddedildi: %s → %s",
                        label, value, message,
                    )
            bad_values = set(bad_rows)

            if not dup_values and not bad_values:
                # 400 geldi ama hangi satırın sorunlu olduğu bildirilmedi.
                # Gözlemlenen davranış: CrowdStrike bir istekte bildirdiği
                # uyarı satırı sayısını sınırlayabiliyor ve kalabalık
                # batch'lerde detayları hiç döndürmeyebiliyor. Batch'i ikiye
                # bölüp yeniden denemek bu durumu kurtarır — tüm batch'i
                # (199 geçerli göstergeyi) çöpe atmaktan çok daha iyi.
                if len(pending) > 1:
                    mid = len(pending) // 2
                    logger.warning(
                        "CrowdStrike %s batch'i satır detayı olmadan 400 döndü; "
                        "%d gösterge ikiye bölünüp yeniden denenecek.",
                        label, len(pending),
                    )
                    for half in (pending[:mid], pending[mid:]):
                        h_created, h_present, h_rejected = await self._send_indicator_batch(
                            half, label, ignore_warnings=ignore_warnings
                        )
                        created.extend(h_created)
                        already_present.extend(h_present)
                        rejected.extend(h_rejected)
                    return created, already_present, rejected

                # Tek göstergeye indik ve hâlâ hata veriyor → gerçekten geçersiz.
                errors = body.get("errors", [])
                logger.error(
                    "CrowdStrike %s göstergesi tek başına da reddedildi: %s → %s",
                    label, pending[0].get("value"), errors,
                )
                reason = f"tek başına da 400: {_first_error_message(errors)}"
                rejected.extend((i["value"], reason) for i in pending)
                return created, already_present, rejected

            already_present.extend(dup_values)
            rejected.extend((v, bad_rows[v]) for v in bad_values)
            skip = dup_values | bad_values
            pending = [i for i in pending if i["value"] not in skip]

        if pending:
            logger.error(
                "CrowdStrike %s batch'i %d denemede temizlenemedi, "
                "%d gösterge atlandı.",
                label, CS_MAX_BATCH_RETRIES, len(pending),
            )
            reason = f"{CS_MAX_BATCH_RETRIES} denemede batch temizlenemedi"
            rejected.extend((i["value"], reason) for i in pending)

        return created, already_present, rejected

    # Veritabanı tipinden CrowdStrike gösterge tipine. Hash iki tiple
    # eşleşir: operatörün elindeki değer sha256 da md5 de olabilir.
    CS_TYPES_FOR_KIND = {
        "ip": ("ipv4",),
        "domain": ("domain",),
        "hash": ("sha256", "md5"),
    }

    @staticmethod
    def _retention_fields(source: str) -> dict:
        """
        Bir göstergeye kaynağına göre süre ve etiket alanlarını üretir.

        expiration: CrowdStrike göstergeyi bu tarihten sonra kendiliğinden
        'expired' işaretler. Böylece saklama temizliği, değer değer arama
        yapmak yerine tek bir `expired:true` filtresiyle çalışabilir —
        yüz binlerce gösterge için aradaki fark saatlerle ölçülür.
        TTL'i 0 olan kaynakta (USOM) alan hiç konmaz: süresiz demektir.

        tags: CrowdStrike tarafında beslemeyi ayırt edebilmek için.
        Mevcut göstergelerin hepsi aynı `source` ve `description` ile
        basıldığı için hangisinin hangi beslemeden geldiği oradan
        anlaşılamıyor; etiket bu boşluğu bundan sonrası için kapatır.
        """
        fields = {"tags": ["usomlistservice", f"feed-{source}"]}
        days = RETENTION_DAYS.get(source, 0)
        if days > 0:
            expires = datetime.now(timezone.utc) + timedelta(days=days)
            # CrowdStrike UTC ISO bekliyor; mikrosaniye taşımaya gerek yok.
            fields["expiration"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
        return fields

    async def find_indicator(self, kind: str, value: str) -> list[dict]:
        """
        Bir göstergeyi CrowdStrike'ta arar — hiçbir şey silmez.

        Yerel veritabanı CrowdStrike'ın doğruluk kaynağı değil: oraya bir
        kez yazılmış gösterge, yerel kayıt sonradan kaybolsa da engellemeye
        devam eder. "Yerelde yok" cevabını vermeden önce asıl yere bakmak,
        operatöre var olmayan bir temizlik hissi vermemenin tek yolu.
        """
        if not self.enabled or self._ioc_client is None:
            return []
        types = self.CS_TYPES_FOR_KIND.get(kind, ())
        if not types or "'" in value or "\\" in value:
            return []

        type_filter = ",".join(f"'{t}'" for t in types)
        fql = f"value:'{value}'+type:[{type_filter}]"
        try:
            found = await asyncio.wait_for(
                asyncio.to_thread(
                    self._ioc_client.indicator_search,
                    filter=fql,
                    limit=CS_DELETE_SEARCH_LIMIT,
                ),
                timeout=CS_BATCH_TIMEOUT,
            )
        except Exception as exc:
            # Arama bir yan bilgi; başarısızlığı sorgunun tamamını
            # düşürmemeli. Operatör yerel sonucu yine de görmeli.
            logger.warning("CrowdStrike arama başarısız (%s): %s", value, exc)
            return []

        if found.get("status_code") not in (200, 201):
            return []
        ids = (found.get("body") or {}).get("resources") or []
        if not ids:
            return []

        try:
            detail = await asyncio.wait_for(
                asyncio.to_thread(self._ioc_client.indicator_get, ids=ids),
                timeout=CS_BATCH_TIMEOUT,
            )
        except Exception as exc:
            logger.warning("CrowdStrike detay alınamadı (%s): %s", value, exc)
            # id'yi biliyoruz ama ayrıntıyı bilmiyoruz; yine de "orada var"
            # demek, sessiz kalmaktan doğru.
            return [{"id": i, "type": kind, "value": value} for i in ids]

        return [
            {
                "id": r.get("id"),
                "type": kind,
                "cs_type": r.get("type"),
                "value": r.get("value"),
                "action": r.get("action"),
                "severity": r.get("severity"),
                "source": r.get("source"),
                "description": r.get("description"),
                "created_on": r.get("created_on"),
                "expired": r.get("expired"),
            }
            for r in ((detail.get("body") or {}).get("resources") or [])
        ]

    async def delete_indicator(self, kind: str, value: str) -> dict:
        """
        Bir göstergeyi CrowdStrike IOC veritabanından siler.

        İki adım: önce FQL ile değerin id'si bulunur, sonra id silinir —
        CrowdStrike değere göre doğrudan silme sunmuyor.

        "Bulunamadı" başarısızlık değildir: gösterge hiç gönderilmemiş
        ya da daha önce elle silinmiş olabilir. İki durumda da sonuç
        aynı — CrowdStrike'ta o gösterge yok. Çağıran bunu hata olarak
        raporlarsa operatör var olmayan bir sorunu kovalar.

        Returns:
            {"ok": bool, "deleted": silinen id sayısı, "detail": açıklama}
        """
        if not self.enabled or self._ioc_client is None:
            # Hata değil: entegrasyon kapalıyken CrowdStrike'ta silinecek
            # bir şey de yok. 'failed' demek operatörü var olmayan bir
            # sorunu kovalamaya iter.
            return {"ok": True, "deleted": 0, "status": "disabled",
                    "detail": "CrowdStrike entegrasyonu kapalı"}

        # FQL tek tırnakla sınırlandırılıyor; tırnak içeren bir değer
        # sorguyu bozar. IP/domain/hash'te tırnak olmaz, yine de geçmesin.
        if "'" in value or "\\" in value:
            return {"ok": False, "deleted": 0, "status": "failed",
                    "detail": "Değer FQL için geçersiz karakter içeriyor"}

        types = self.CS_TYPES_FOR_KIND.get(kind, ())
        if not types:
            return {"ok": False, "deleted": 0, "status": "failed",
                    "detail": f"Bilinmeyen tip: {kind}"}

        type_filter = ",".join(f"'{t}'" for t in types)
        fql = f"value:'{value}'+type:[{type_filter}]"

        try:
            found = await asyncio.wait_for(
                asyncio.to_thread(
                    self._ioc_client.indicator_search,
                    filter=fql,
                    limit=CS_DELETE_SEARCH_LIMIT,
                ),
                timeout=CS_BATCH_TIMEOUT,
            )
        except asyncio.TimeoutError:
            return {"ok": False, "deleted": 0, "status": "failed",
                    "detail": f"CrowdStrike arama {CS_BATCH_TIMEOUT:.0f} sn içinde yanıt vermedi"}
        except Exception as exc:
            logger.error("CrowdStrike IOC arama hatası (%s): %s", value, exc)
            return {"ok": False, "deleted": 0, "status": "failed",
                    "detail": f"Arama hatası: {exc}"}

        status = found.get("status_code", 0)
        if status not in (200, 201):
            errors = (found.get("body") or {}).get("errors", [])
            detail = f"Arama HTTP {status}: {_first_error_message(errors)}"
            logger.error("CrowdStrike IOC araması başarısız (%s): %s", value, detail)
            return {"ok": False, "deleted": 0, "status": "failed", "detail": detail}

        ids = (found.get("body") or {}).get("resources") or []
        if not ids:
            logger.info(
                "CrowdStrike'ta '%s' için kayıt bulunamadı — silinecek bir şey yok.",
                value,
            )
            return {"ok": True, "deleted": 0, "status": "absent",
                    "detail": "CrowdStrike'ta kayıt yoktu"}

        try:
            removed = await asyncio.wait_for(
                asyncio.to_thread(
                    self._ioc_client.indicator_delete,
                    ids=ids,
                    comment="USOMListService: operatör tarafından silindi",
                ),
                timeout=CS_BATCH_TIMEOUT,
            )
        except asyncio.TimeoutError:
            return {"ok": False, "deleted": 0, "status": "failed",
                    "detail": f"CrowdStrike silme {CS_BATCH_TIMEOUT:.0f} sn içinde yanıt vermedi"}
        except Exception as exc:
            logger.error("CrowdStrike IOC silme hatası (%s): %s", value, exc)
            return {"ok": False, "deleted": 0, "status": "failed",
                    "detail": f"Silme hatası: {exc}"}

        del_status = removed.get("status_code", 0)
        if del_status not in (200, 201):
            errors = (removed.get("body") or {}).get("errors", [])
            detail = f"Silme HTTP {del_status}: {_first_error_message(errors)}"
            logger.error("CrowdStrike IOC silinemedi (%s): %s", value, detail)
            return {"ok": False, "deleted": 0, "status": "failed", "detail": detail}

        logger.info(
            "CrowdStrike: '%s' göstergesi silindi (%d kayıt).", value, len(ids)
        )
        return {"ok": True, "deleted": len(ids), "status": "removed",
                "detail": f"{len(ids)} CrowdStrike kaydı silindi"}

    async def _delete_ids(self, ids: list[str], comment: str) -> tuple[int, list[str]]:
        """id listesini parçalara bölerek siler. (silinen, hata mesajları) döner."""
        deleted = 0
        errors: list[str] = []
        for i in range(0, len(ids), CS_BULK_DELETE_CHUNK):
            chunk = ids[i:i + CS_BULK_DELETE_CHUNK]
            try:
                resp = await asyncio.wait_for(
                    asyncio.to_thread(
                        self._ioc_client.indicator_delete,
                        ids=chunk, comment=comment,
                    ),
                    timeout=CS_BATCH_TIMEOUT,
                )
            except asyncio.TimeoutError:
                errors.append(f"silme zaman aşımı ({len(chunk)} id)")
                continue
            except Exception as exc:
                errors.append(f"silme hatası: {exc}")
                continue

            status = resp.get("status_code", 0)
            if status in (200, 201):
                deleted += len(chunk)
            else:
                errs = (resp.get("body") or {}).get("errors", [])
                errors.append(f"HTTP {status}: {_first_error_message(errs)}")
            await asyncio.sleep(0.2)   # nezaket beklemesi
        return deleted, errors

    async def delete_indicators_bulk(
        self, values: list[str], *, comment: str = "USOMListService: saklama süresi doldu"
    ) -> dict:
        """
        Çok sayıda göstergeyi değerlerinden yola çıkarak CrowdStrike'tan siler.

        CrowdStrike değere göre doğrudan silme sunmuyor ve indicator_delete
        yalnızca id alıyor; bu yüzden önce arama gerekiyor. Tek tek aramak
        yüz binlik temizlikte kabul edilemez (değer başına bir HTTP isteği),
        bu yüzden FQL'in liste eşleşmesi kullanılır:
        `value:['a','b',…]` — 150 değer tek sorguda.

        Bulunamayan değerler hata değildir: gösterge hiç basılmamış ya da
        daha önce silinmiş olabilir; sonuç aynı, CrowdStrike'ta yok.

        Returns:
            {"deleted": …, "searched": …, "not_found": …, "errors": [...]}
        """
        if not self.enabled or self._ioc_client is None:
            return {"deleted": 0, "searched": 0, "not_found": len(values),
                    "errors": [], "detail": "CrowdStrike entegrasyonu kapalı"}

        # FQL tek tırnakla sınırlandırılıyor; tırnak/ters bölü içeren değer
        # sorguyu bozar. IP/domain/hash'te olmaz, yine de elenir.
        clean = [v for v in values if v and "'" not in v and "\\" not in v]
        skipped = len(values) - len(clean)

        found_ids: list[str] = []
        errors: list[str] = []

        for i in range(0, len(clean), CS_BULK_SEARCH_CHUNK):
            chunk = clean[i:i + CS_BULK_SEARCH_CHUNK]
            fql = "value:[" + ",".join(f"'{v}'" for v in chunk) + "]"
            try:
                resp = await asyncio.wait_for(
                    asyncio.to_thread(
                        self._ioc_client.indicator_search, filter=fql, limit=500,
                    ),
                    timeout=CS_BATCH_TIMEOUT,
                )
            except asyncio.TimeoutError:
                errors.append(f"arama zaman aşımı ({len(chunk)} değer)")
                continue
            except Exception as exc:
                errors.append(f"arama hatası: {exc}")
                continue

            status = resp.get("status_code", 0)
            if status not in (200, 201):
                errs = (resp.get("body") or {}).get("errors", [])
                errors.append(f"arama HTTP {status}: {_first_error_message(errs)}")
                continue

            found_ids.extend((resp.get("body") or {}).get("resources") or [])
            await asyncio.sleep(0.2)

        deleted, del_errors = await self._delete_ids(found_ids, comment)
        errors.extend(del_errors)

        return {
            "deleted": deleted,
            "searched": len(clean),
            "found": len(found_ids),
            "not_found": max(0, len(clean) - len(found_ids)),
            "skipped_invalid": skipped,
            "errors": errors,
        }

    async def delete_expired(self, max_items: int = 50000) -> dict:
        """
        CrowdStrike'ın kendi 'expired' işaretlediği göstergeleri siler.

        Hızlı yol: TTL'li basılan göstergeler süresi dolunca CrowdStrike
        tarafından `expired:true` işaretleniyor. Bunları tek bir filtreyle
        toplamak, değer değer aramaya göre kıyaslanamaz ölçüde ucuz.

        Not: bu yalnızca expiration alanıyla basılmış göstergeleri yakalar.
        TTL öncesi basılan yığın için delete_indicators_bulk gerekiyor.
        """
        if not self.enabled or self._ioc_client is None:
            return {"deleted": 0, "found": 0, "errors": [],
                    "detail": "CrowdStrike entegrasyonu kapalı"}

        found_ids: list[str] = []
        errors: list[str] = []
        after = None

        while len(found_ids) < max_items:
            kwargs = {"filter": "expired:true", "limit": 500}
            if after:
                kwargs["after"] = after
            try:
                resp = await asyncio.wait_for(
                    asyncio.to_thread(self._ioc_client.indicator_search, **kwargs),
                    timeout=CS_BATCH_TIMEOUT,
                )
            except Exception as exc:
                errors.append(f"süresi dolmuş arama hatası: {exc}")
                break

            if resp.get("status_code") not in (200, 201):
                errs = (resp.get("body") or {}).get("errors", [])
                errors.append(f"arama HTTP {resp.get('status_code')}: "
                              f"{_first_error_message(errs)}")
                break

            body = resp.get("body") or {}
            page = body.get("resources") or []
            if not page:
                break
            found_ids.extend(page)
            after = ((body.get("meta") or {}).get("pagination") or {}).get("after")
            if not after:
                break
            await asyncio.sleep(0.2)

        found_ids = found_ids[:max_items]
        deleted, del_errors = await self._delete_ids(
            found_ids, "USOMListService: CrowdStrike süresi doldu"
        )
        errors.extend(del_errors)
        return {"deleted": deleted, "found": len(found_ids), "errors": errors}

    async def push_ips(
        self, ip_list: list[str], *, ignore_warnings: bool = False,
        source: str = SOURCE_USOM,
    ) -> tuple[int, list[str]]:
        """
        IP listesini CrowdStrike'a batch'ler (200'lük) halinde gönderir.

        source: göstergenin hangi beslemeden geldiği. Saklama süresi
        (expiration) ve etiket buna göre belirlenir, bu yüzden çağıran
        tek bir turda farklı kaynakları karıştırmamalı.

        Returns:
            (pushed_count, pushed_ips): CrowdStrike'ta mevcut olan (yeni yazılan
            veya zaten kayıtlı olan) IP sayısı ve listesi.
        """
        if (not self.enabled or not self.push_enabled
                or not self._ioc_client or not ip_list):
            return 0, []

        pushed_ips: list[str] = []
        created_total = duplicate_total = rejected_total = 0
        batch_size = 200
        retention = self._retention_fields(source)

        for i in range(0, len(ip_list), batch_size):
            batch = ip_list[i:i + batch_size]
            indicators = [
                {
                    "type": "ipv4",
                    "value": ip,
                    "action": self.network_action,
                    "severity": "high",
                    "source": "USOMListService",
                    "description": "USOM Malicious IP Intelligence",
                    "platforms": ["windows", "mac", "linux"],
                    "applied_globally": True,
                    **retention,
                }
                for ip in batch
            ]
            created, present, rejected = await self._send_indicator_batch(
                indicators, "IP", ignore_warnings=ignore_warnings
            )
            pushed_ips.extend(created)
            pushed_ips.extend(present)
            created_total += len(created)
            duplicate_total += len(present)
            rejected_total += len(rejected)
            await self._record_rejections("ip", rejected)

            await asyncio.sleep(0.5)  # Rate limit koruması

        pushed_count = len(pushed_ips)
        self.total_pushed_session += pushed_count
        if pushed_count > 0:
            self.last_push_time = datetime.now(timezone.utc)
        logger.info(
            "CrowdStrike IP push tamamlandı: %d/%d işlendi "
            "(yeni: %d | zaten mevcut: %d | reddedilen: %d).",
            pushed_count, len(ip_list), created_total, duplicate_total, rejected_total,
        )
        return pushed_count, pushed_ips

    async def sync_all_unpushed(
        self, db_instance, *, ignore_warnings: bool = False
    ) -> int:
        """
        Veritabanındaki CrowdStrike'a henüz gönderilmemiş tüm IP'leri toplu olarak gönderir.
        Başarıyla gönderilenleri veritabanında pushed_to_cs=1 olarak işaretler.
        """
        if not self.enabled:
            return 0

        # Kaynak bazında gruplanır: saklama süresi (expiration) ve etiket
        # kaynağa göre değişiyor, karışık bir batch yanlış TTL yazardı.
        grouped = await db_instance.get_unpushed_grouped("ip")
        queue_size = sum(len(v) for v in grouped.values())
        if not queue_size:
            logger.info("CrowdStrike: Gönderilecek yeni IP yok, tümü güncel.")
            return 0

        logger.info(
            "CrowdStrike: %d adet gönderilmemiş IP tespit edildi (%s), başlatılıyor...",
            queue_size,
            ", ".join(f"{s}: {len(v)}" for s, v in sorted(grouped.items())),
        )

        # Parça parça gönder ve HER PARÇADAN SONRA işaretle. Tüm kuyruğun
        # bitmesi beklenirse süreç ortada ölünce ilerleme kaydı kaybolur.
        total = 0
        for source, unpushed in sorted(grouped.items()):
            for i in range(0, len(unpushed), CS_CHECKPOINT_SIZE):
                chunk = unpushed[i:i + CS_CHECKPOINT_SIZE]
                pushed_count, pushed_ips = await self.push_ips(
                    chunk, ignore_warnings=ignore_warnings, source=source)
                if pushed_ips:
                    await db_instance.mark_ips_pushed(pushed_ips)
                    total += pushed_count
                logger.info(
                    "CrowdStrike IP ilerleme: %d/%d işaretlendi (%s).",
                    total, queue_size, source,
                )

        return total

    async def push_domains(
        self, domain_list: list[str], *, ignore_warnings: bool = False,
        source: str = SOURCE_USOM,
    ) -> tuple[int, list[str]]:
        """
        Domain listesini CrowdStrike'a type:domain olarak gönderir.

        source: saklama süresi ve etiket bu kaynağa göre belirlenir
        (bkz. push_ips).

        Returns:
            (pushed_count, resolved_domains)

            resolved_domains, veritabanında "işlendi" olarak işaretlenmesi
            gereken ORİJİNAL domain değerleridir: CrowdStrike'a başarıyla
            yazılanlar, orada zaten kayıtlı olanlar ve whitelist nedeniyle
            bilinçli olarak atlananlar. pushed_count yalnızca CrowdStrike'a
            gerçekten işlenen gösterge sayısını verir.
        """
        if (not self.enabled or not self.push_enabled
                or not self._ioc_client or not domain_list):
            return 0, []

        filtered_domains = []
        # Gönderim öncesi normalleştirme (küçük harf + 'www.' kırpma) yapılır,
        # ancak veritabanı anahtarı ORİJİNAL değerdir. Normalleştirilmiş değerle
        # işaretleme yapılırsa UPDATE hiçbir satırla eşleşmez ve o kayıtlar her
        # turda yeniden gönderilip sonsuza kadar kuyrukta kalır.
        # Bu yüzden normalleştirilmiş → orijinal(ler) eşlemesi korunur.
        norm_to_originals: dict[str, list[str]] = {}
        whitelisted_originals: list[str] = []
        oversized_originals: list[str] = []

        for original in domain_list:
            domain = original.lower()
            if domain.startswith("www."):
                domain = domain[4:]

            # CrowdStrike'ın uzunluk sınırını aşanları baştan ayır: gönderilseler
            # kesin 400 alırlar ve işaretlenmedikleri için her turda geri gelirler.
            if len(domain) > CS_MAX_DOMAIN_LENGTH:
                oversized_originals.append(original)
                continue

            # Domain whitelist kontrolü (örn. instagram.com veya .instagram.com)
            is_whitelisted = any(
                domain == wd or domain.endswith(f".{wd}")
                for wd in WHITELISTED_DOMAINS
            )

            # Paylaşımlı altyapının apex'i CrowdStrike'a basılmaz (alt alan
            # adları normal şekilde işlenir — is_shared_infra_apex yalnızca
            # apex eşleşmesi arar).
            if is_whitelisted or is_shared_infra_apex(domain):
                # Bilinçli olarak atlanıyor — ancak "çözümlendi" sayılmalı,
                # aksi hâlde her senkronizasyonda tekrar tekrar değerlendirilir.
                whitelisted_originals.append(original)
                logger.debug("Gönderim dışı bırakılan domain: %s", original)
            else:
                norm_to_originals.setdefault(domain, []).append(original)

        if oversized_originals:
            logger.info(
                "CrowdStrike domain push: %d kayıt %d karakter sınırını aştığı için "
                "atlandı (DNS tünelleme beacon'ları — ana alan adları ayrıca engelli).",
                len(oversized_originals), CS_MAX_DOMAIN_LENGTH,
            )
            # Bunlar CrowdStrike'a hiç gönderilmiyor ama panoda "reddedildi"
            # sayılmalı: kullanıcı açısından sonuç aynı — gösterge engelleme
            # listesine girmedi ve sebebi bilinmeli.
            #
            # _record_rejections bunları aynı zamanda BLOKE işaretler; bu
            # yüzden aşağıda "çözümlendi" listesine eklenmiyorlar. Önceden
            # pushed_to_cs=1 yazılıyordu ve panoda "gönderildi" olarak
            # sayılıyorlardı — gönderilmemiş bir göstergeyi gönderilmiş
            # göstermek, güvenlik panosunda kabul edilebilir bir yaklaşım
            # değil.
            await self._record_rejections(
                "domain",
                [
                    (o, f"value is too long for domain type: max_length="
                        f"{CS_MAX_DOMAIN_LENGTH} (gönderim öncesi ayıklandı)")
                    for o in oversized_originals
                ],
            )

        domains = list(norm_to_originals)
        # Yalnızca whitelist "çözümlendi" sayılır: bu bilinçli bir politika
        # kararı, gönderim arızası değil — göstergenin kuyruktan düşmesi
        # gerekiyor ve yeniden değerlendirilmesinin bir anlamı yok.
        # Uzunluk sınırını aşanlar yukarıda BLOKE işaretlendi; onları
        # burada da "çözümlendi" saymak, panoda gönderilmiş gibi
        # görünmelerine yol açardı.
        skipped = list(whitelisted_originals)

        if not domains:
            if skipped or oversized_originals:
                logger.info(
                    "CrowdStrike domain push: gönderilecek uygun kayıt yok "
                    "(%d whitelist, %d uzunluk sınırı).",
                    len(skipped), len(oversized_originals),
                )
            return 0, skipped

        pushed_domains: list[str] = []
        created_total = duplicate_total = rejected_total = 0
        batch_size = 200
        retention = self._retention_fields(source)

        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            indicators = [
                {
                    "type": "domain",
                    "value": d,
                    "action": self.network_action,
                    "severity": "high",
                    "source": "USOMListService",
                    "description": "USOM Malicious Domain Intelligence",
                    "platforms": ["windows", "mac", "linux"],
                    "applied_globally": True,
                    **retention,
                }
                for d in batch
            ]
            created, present, rejected = await self._send_indicator_batch(
                indicators, "domain", ignore_warnings=ignore_warnings
            )
            # Sonuçları veritabanı anahtarlarına (orijinal değerlere) geri eşle
            for normalized in created + present:
                pushed_domains.extend(norm_to_originals.get(normalized, [normalized]))
            created_total += len(created)
            duplicate_total += len(present)
            rejected_total += len(rejected)
            # Red kaydı da orijinal değerle tutulur: arama kutusuna
            # veritabanındaki hâli yazılacak, normalleştirilmiş biçim değil.
            await self._record_rejections(
                "domain",
                [
                    (original, reason)
                    for normalized, reason in rejected
                    for original in norm_to_originals.get(normalized, [normalized])
                ],
            )

            await asyncio.sleep(0.5)

        pushed_count = len(pushed_domains)
        self.total_pushed_session += pushed_count
        if pushed_count > 0:
            self.last_push_time = datetime.now(timezone.utc)
        logger.info(
            "CrowdStrike domain push tamamlandı: %d/%d gösterge işlendi "
            "(yeni: %d | zaten mevcut: %d | reddedilen: %d | whitelist: %d | "
            "uzunluk sınırı: %d).",
            pushed_count, len(domains), created_total, duplicate_total,
            rejected_total, len(whitelisted_originals), len(oversized_originals),
        )
        # Bilinçli olarak atlananlar da "çözümlendi" sayılır ki kuyruktan düşsünler.
        return pushed_count, pushed_domains + skipped

    async def push_hashes(
        self, hash_list: list[str], *, ignore_warnings: bool = False
    ) -> tuple[int, list[str]]:
        """
        sha256 hash listesini CrowdStrike'a gönderir.

        Aksiyon FALCON_HASH_ACTION ile belirlenir (varsayılan: prevent).
        ignore_warnings yalnızca bilinçli yeniden denemede True olur —
        bkz. _send_indicator_batch.

        Returns:
            (pushed_count, pushed_hashes)
        """
        if (not self.enabled or not self.push_enabled
                or not self._ioc_client or not hash_list):
            return 0, []

        pushed_hashes: list[str] = []
        created_total = duplicate_total = rejected_total = 0
        batch_size = 200
        # Hash'ler yalnızca MalwareBazaar'dan geliyor; kaynak sabit.
        retention = self._retention_fields(SOURCE_MALWAREBAZAAR)

        for i in range(0, len(hash_list), batch_size):
            batch = hash_list[i:i + batch_size]
            indicators = [
                {
                    "type": "sha256",
                    "value": h,
                    "action": self.hash_action,
                    "severity": "high",
                    "source": "USOMListService-MalwareBazaar",
                    "description": "abuse.ch MalwareBazaar Malicious File Hash",
                    "platforms": ["windows", "mac", "linux"],
                    "applied_globally": True,
                    **retention,
                }
                for h in batch
            ]
            created, present, rejected = await self._send_indicator_batch(
                indicators, "hash", ignore_warnings=ignore_warnings
            )
            pushed_hashes.extend(created)
            pushed_hashes.extend(present)
            created_total += len(created)
            duplicate_total += len(present)
            rejected_total += len(rejected)
            await self._record_rejections("hash", rejected)

            await asyncio.sleep(0.5)  # Rate limit koruması

        pushed_count = len(pushed_hashes)
        self.total_pushed_session += pushed_count
        if pushed_count > 0:
            self.last_push_time = datetime.now(timezone.utc)
        logger.info(
            "CrowdStrike hash push tamamlandı (action: %s): %d/%d işlendi "
            "(yeni: %d | zaten mevcut: %d | reddedilen: %d).",
            self.hash_action, pushed_count, len(hash_list),
            created_total, duplicate_total, rejected_total,
        )
        return pushed_count, pushed_hashes

    async def sync_all_unpushed_hashes(
        self, db_instance, *, ignore_warnings: bool = False
    ) -> int:
        """Gönderilmemiş hash'leri CrowdStrike'a basar (checkpoint'li)."""
        if not self.enabled:
            return 0

        unpushed = await db_instance.get_unpushed_hashes()
        if not unpushed:
            logger.info("CrowdStrike: Gönderilecek yeni hash yok.")
            return 0

        logger.info("CrowdStrike: %d hash gönderilecek...", len(unpushed))
        total = 0
        for i in range(0, len(unpushed), CS_CHECKPOINT_SIZE):
            chunk = unpushed[i:i + CS_CHECKPOINT_SIZE]
            pushed_count, pushed_hashes = await self.push_hashes(
                chunk, ignore_warnings=ignore_warnings)
            if pushed_hashes:
                await db_instance.mark_hashes_pushed(pushed_hashes)
                total += pushed_count
            logger.info(
                "CrowdStrike hash ilerleme: %d/%d işaretlendi.", total, len(unpushed)
            )

        return total

    async def sync_all_unpushed_domains(
        self, db_instance, *, ignore_warnings: bool = False
    ) -> int:
        """Gönderilmemiş domain'leri CrowdStrike'a basar."""
        if not self.enabled:
            return 0
        # Kaynak bazında (bkz. sync_all_unpushed).
        grouped = await db_instance.get_unpushed_grouped("domain")
        queue_size = sum(len(v) for v in grouped.values())
        if not queue_size:
            logger.info("CrowdStrike: Gönderilecek yeni domain yok.")
            return 0
        logger.info(
            "CrowdStrike: %d domain gönderilecek (%s)...",
            queue_size,
            ", ".join(f"{s}: {len(v)}" for s, v in sorted(grouped.items())),
        )

        # Parça parça gönder ve HER PARÇADAN SONRA işaretle (bkz.
        # sync_all_unpushed). 400 binlik kuyrukta bu, saatlerce görünmeyen
        # ve süreç ölünce tamamen kaybolan ilerleme sorununu ortadan kaldırır.
        total = 0
        for source, unpushed in sorted(grouped.items()):
            for i in range(0, len(unpushed), CS_CHECKPOINT_SIZE):
                chunk = unpushed[i:i + CS_CHECKPOINT_SIZE]
                pushed_count, pushed_domains = await self.push_domains(
                    chunk, ignore_warnings=ignore_warnings, source=source)
                if pushed_domains:
                    await db_instance.mark_domains_pushed(pushed_domains)
                    total += pushed_count
                logger.info(
                    "CrowdStrike domain ilerleme: %d/%d işaretlendi (%s).",
                    total, queue_size, source,
                )

        return total

# ─────────────────────────────────────────────────────
# 4. SENKRONİZASYON SERVİSİ
# ─────────────────────────────────────────────────────
class SyncService:
    """
    USOM API ile veritabanı arasındaki senkronizasyon mantığını yönetir.

    Üç farklı senkronizasyon stratejisi:
        1. full_sync()  → Tüm sayfaları baştan sona tarar (initial + haftalık)
        2. delta_sync() → Sadece yeni eklenen IP'leri çeker (saatlik)
    """

    def __init__(
        self,
        client: USOMClient,
        db: IPDatabase,
        cs: CrowdStrikeService = None,
        mb_client: "MalwareBazaarClient" = None,
        bd_client: "BrandefenseClient" = None,
    ):
        self.client = client
        self.db = db
        self.cs = cs
        self.mb_client = mb_client
        self.bd_client = bd_client
        # Kilitler ayrı tutulur. CrowdStrike push'u yüz binlik kuyrukta
        # saatlerce sürebilir; bunu veri çekme kilidinin içinde tutmak, o süre
        # boyunca TÜM zamanlanmış sync'leri bloke eder (max_instances=1 ile
        # birlikte sessiz durma anlamına gelir).
        self._sync_lock = asyncio.Lock()   # USOM'dan çekme + DB yazma
        self._hash_lock = asyncio.Lock()   # MalwareBazaar'dan çekme + DB yazma
        # Push kilitleri tip bazında ayrı: hash push'u, saatler süren domain
        # kuyruğunun arkasında aç kalmasın.
        self._push_lock = asyncio.Lock()        # domain / IP push'ları
        self._hash_push_lock = asyncio.Lock()   # hash push'ları
        self._bd_lock = asyncio.Lock()          # Brandefense'ten çekme + DB yazma

    async def _record_sync_ok(self) -> None:
        """
        Başarıyla tamamlanan bir senkronizasyonu damgalar.

        /health tazelik kontrolü bu damgayı kullanır. max(added_at) kullanılamaz:
        USOM yeni gösterge yayınlamadığında sync başarıyla çalışsa bile o değer
        ilerlemez ve sağlıklı servis "bayat" görünürdü.
        """
        try:
            await self.db.set_meta(
                META_LAST_SYNC_OK, datetime.now(timezone.utc).isoformat()
            )
        except Exception as exc:
            logger.warning("Sync damgası yazılamadı: %s", exc)

    async def retention_sync(
        self, *, dry_run: bool = False, limit: Optional[int] = None
    ) -> dict:
        """
        Saklama Temizliği (Retention)
        ==============================
        Saklama süresi dolmuş göstergeleri CrowdStrike'tan ve yerel
        veritabanından kaldırır.

        Neden gerekli: CrowdStrike tenant başına 1 milyon gösterge kabul
        ediyor. Sınır dolduğunda YENİ gösterge yazılamaz — yani eski
        kayıtları tutmanın bedeli, en güncel tehditlerin EDR'a hiç
        ulaşmamasıdır. Temizlik sürekli yer açarak bu döngüyü kırar.

        Sıra bilinçli: ÖNCE CrowdStrike, SONRA yerel. Tersi olursa ve
        CrowdStrike çağrısı başarısız olursa, elimizde değer kalmadığı
        için gösterge orada öksüz kalır ve bir daha hiç bulunamaz.

        `deleted_iocs` dışlama listesine yazılmaz: besleme göstergeyi
        yeniden raporlarsa geri gelmeli (bkz. IPDatabase.purge_values).
        """
        cap = limit if limit and limit > 0 else RETENTION_MAX_PER_RUN
        preview = await self.db.retention_preview()

        # CrowdStrike kapalıyken temizlik YAPILMAZ (kuru çalıştırma hariç).
        #
        # Yerel satırı silip CrowdStrike'a dokunamamak, göstergeyi orada
        # öksüz bırakır: değeri artık veritabanında olmadığı için bir daha
        # bulunup silinemez ve tenant kotasını sonsuza kadar işgal eder.
        # Üstelik temizliğin tek amacı kotada yer açmak; CrowdStrike'a
        # ulaşamıyorsak yerel silme hiçbir soruna çözüm üretmez, yalnızca
        # beslemelerden veri eksiltir.
        if not dry_run and not (self.cs and self.cs.enabled):
            logger.warning(
                "Saklama temizliği atlandı: CrowdStrike entegrasyonu kapalı. "
                "Yerel kayıtları silmek göstergeleri CrowdStrike'ta öksüz "
                "bırakırdı (%d aday bekliyor).", preview["total"],
            )
            return {"dry_run": False, "skipped": "crowdstrike_kapali",
                    "total_candidates": preview["total"],
                    "cs_deleted": 0, "db_removed": 0, "details": []}

        if not preview["total"]:
            logger.info("Saklama: süresi dolmuş gösterge yok.")
            return {"dry_run": dry_run, "total_candidates": 0,
                    "cs_deleted": 0, "db_removed": 0, "details": []}

        logger.info(
            "Saklama: %d gösterge süresini doldurdu (üst sınır %d)%s.",
            preview["total"], cap, " — KURU ÇALIŞTIRMA" if dry_run else "",
        )

        if dry_run:
            return {"dry_run": True, "total_candidates": preview["total"],
                    "cs_deleted": 0, "db_removed": 0,
                    "details": preview["sources"]}

        run_id = await self.db.start_sync_run("retention")
        details = []
        cs_total = db_total = 0
        budget = cap
        errors: list[str] = []

        try:
            for row in preview["sources"]:
                if budget <= 0:
                    break
                kind, source, cutoff = row["kind"], row["source"], row["cutoff"]
                values = await self.db.get_expired_values(
                    kind, source, cutoff, min(budget, row["expired"])
                )
                if not values:
                    continue

                cs = await self.cs.delete_indicators_bulk(values) if self.cs else {
                    "deleted": 0, "errors": ["CrowdStrike servisi yok"]}

                # CrowdStrike hata verdiyse yerel satır SİLİNMEZ: gösterge
                # orada duruyor olabilir, değeri kaybedersek temizleyemeyiz.
                if cs.get("errors"):
                    errors.extend(f"{kind}/{source}: {e}" for e in cs["errors"][:3])
                    logger.error(
                        "Saklama: %s/%s için CrowdStrike silme hatalı, yerel "
                        "kayıtlar KORUNDU (%d hata). İlk hata: %s",
                        kind, source, len(cs["errors"]), cs["errors"][0],
                    )
                    details.append({**row, "cs_deleted": cs.get("deleted", 0),
                                    "db_removed": 0, "status": "cs_hatasi"})
                    continue

                removed = await self.db.purge_values(kind, values)
                cs_total += cs.get("deleted", 0)
                db_total += removed
                budget -= len(values)
                details.append({**row, "cs_deleted": cs.get("deleted", 0),
                                "cs_not_found": cs.get("not_found", 0),
                                "db_removed": removed, "status": "ok"})
                logger.info(
                    "Saklama: %s/%s → CrowdStrike %d silindi (%d zaten yoktu), "
                    "yerel %d satır kaldırıldı.",
                    kind, source, cs.get("deleted", 0),
                    cs.get("not_found", 0), removed,
                )

            if preview["total"] > cap:
                logger.warning(
                    "Saklama: %d adaydan yalnızca %d tanesi bu turda işlendi "
                    "(üst sınır). Kalan %d bir sonraki turda temizlenecek.",
                    preview["total"], cap, preview["total"] - cap,
                )

            await self.db.finish_sync_run(
                run_id, status="ok" if not errors else "partial",
                new_records=0, pushed=cs_total,
                detail=f"CS {cs_total} silindi, yerel {db_total} kaldırıldı"
                       + (f" | {len(errors)} hata" if errors else ""),
            )
            await self._record_sync_ok()
        except Exception as exc:
            logger.error("Saklama temizliği hata ile sonlandı: %s", exc, exc_info=True)
            await self.db.finish_sync_run(run_id, status="error", detail=str(exc))
            raise

        logger.info(
            "═══ SAKLAMA TEMİZLİĞİ TAMAMLANDI | CrowdStrike: %d | Yerel: %d ═══",
            cs_total, db_total,
        )
        return {"dry_run": False, "total_candidates": preview["total"],
                "cs_deleted": cs_total, "db_removed": db_total,
                "cap": cap, "errors": errors, "details": details}

    async def hash_sync(self) -> None:
        """
        Zararlı Yazılım Hash Senkronizasyonu (MalwareBazaar)
        =====================================================
        abuse.ch MalwareBazaar'ın son ~48 saatlik dökümünü çeker, yeni
        hash'leri veritabanına ekler ve CrowdStrike'a basar.

        Döküm kayan bir pencere olduğu için saatlik çalışması önemlidir:
        kaçırılan bir pencere kalıcı veri kaybı demektir.
        """
        if not self.mb_client:
            return

        # USOM sync'lerinden bağımsız kaynak → kendi kilidi
        new_count = 0
        run_id = await self.db.start_sync_run("hash")
        async with self._hash_lock:
            logger.info("── Hash Sync başladı (MalwareBazaar) ──")
            try:
                raw = await self.mb_client.fetch_recent()
                records = self.mb_client.parse_csv(raw)
                if not records:
                    logger.warning(
                        "MalwareBazaar dökümü boş döndü — kaynak formatı "
                        "değişmiş olabilir, hash sync atlanıyor."
                    )
                    await self.db.finish_sync_run(
                        run_id, status="error", detail="döküm boş döndü"
                    )
                    return

                result = await self.db.insert_hashes(records)
                new_count = result["new"]
                db_total = await self.db.get_hash_count()
                logger.info(
                    "── Hash Sync tamamlandı | Dökümde: %d | Yeni: %d | "
                    "Gönderim dışı: %d | Toplam DB: %d ──",
                    len(records), new_count, result["blocked"], db_total,
                )
                await self._record_sync_ok()

            except Exception as e:
                logger.error("Hash sync hatası: %s", e, exc_info=True)
                await self.db.finish_sync_run(
                    run_id, new_records=new_count, status="error", detail=str(e)[:200]
                )
                return

        # CrowdStrike push'u çekme kilidinin DIŞINDA; push'lar kendi aralarında
        # _hash_push_lock ile sıraya girer.
        pushed = 0
        if self.cs and self.cs.enabled:
            async with self._hash_push_lock:
                pushed = await self.cs.sync_all_unpushed_hashes(self.db)
        await self.db.finish_sync_run(run_id, new_records=new_count, pushed=pushed)

    async def _bd_ingest(
        self, ioc_type: str, data_types: set[str], insert_fn, period: str,
    ) -> tuple[int, dict]:
        """
        Bir Brandefense gösterge tipini sayfa sayfa çeker ve yazar.

        Sayfa sayfa yazmanın sebebi erken durabilmek: kayıtlar yeniden
        eskiye sıralı, dolayısıyla üst üste BRANDEFENSE_STALE_PAGES sayfa
        hiç yeni kayıt getirmediyse geri kalanı da zaten biliyoruz.
        Bu olmadan her saatlik tur tüm arşivi baştan tarıyor (ölçüldü:
        ip_address için 20. sayfada hâlâ devam ediyordu).

        Returns:
            (yeni kayıt sayısı, {"pages": …, "seen": …, "skipped": …})
        """
        new_total = 0
        pages = seen = skipped = 0
        stale_streak = 0

        async for page in self.bd_client.iter_pages(ioc_type, period):
            pages += 1
            seen += len(page)
            skipped += sum(
                1 for r in page if r.get("data_type") not in data_types
            )
            values = BrandefenseClient.extract_values(page, data_types)
            added = await insert_fn(values, source=SOURCE_BRANDEFENSE) if values else 0
            new_total += added

            if added == 0:
                stale_streak += 1
                if stale_streak >= BRANDEFENSE_STALE_PAGES:
                    logger.info(
                        "Brandefense %s: %d ardışık sayfada yeni kayıt yok, "
                        "çekim durduruldu (%d sayfa tarandı).",
                        ioc_type, stale_streak, pages,
                    )
                    break
            else:
                stale_streak = 0

        return new_total, {"pages": pages, "seen": seen, "skipped": skipped}

    async def brandefense_sync(self, period: str = BRANDEFENSE_PERIOD) -> None:
        """
        Brandefense Threat Intelligence Senkronizasyonu
        ===============================================
        Alan adı ve IPv4 göstergelerini çeker, mevcut tablolara ekler ve
        CrowdStrike'a basar.

        Aynı tablolara yazılıyor (malicious_ips / malicious_domains) çünkü
        gösterge uzayı tek olmalı: bir alan adı hem USOM'da hem
        Brandefense'te varsa iki kez saklanıp iki kez gönderilmemeli.
        INSERT OR IGNORE bunu birincil anahtar üzerinden garanti ediyor —
        var olan kayıt atlanır, pushed_to_cs durumu bozulmaz, yeniden
        gönderilmez.

        Hash ve URL çekilmiyor; sebebi BRANDEFENSE_BASE_URL yorumunda.
        """
        if not self.bd_client or not self.bd_client.enabled:
            return

        run_id = await self.db.start_sync_run("brandefense")
        new_ips = new_domains = 0
        async with self._bd_lock:
            logger.info("── Brandefense Sync başladı (period=%s) ──", period)
            try:
                stats = {}
                # Alan adları
                new_domains, stats["domain"] = await self._bd_ingest(
                    "domain", {BrandefenseClient.DT_DOMAIN},
                    self.db.insert_domains, period,
                )
                # IP'ler — yalnızca IPv4. IPv6 kayıtları CrowdStrike'a ipv4
                # tipinde basılamaz; gönderilseler 400 alıp kuyrukta kalırlardı.
                new_ips, stats["ip_address"] = await self._bd_ingest(
                    "ip_address", {BrandefenseClient.DT_IPV4},
                    self.db.insert_ips, period,
                )

                logger.info(
                    "── Brandefense Sync tamamlandı | Alan adı: %d yeni "
                    "(%d sayfa, %d kayıt tarandı) | IPv4: %d yeni "
                    "(%d sayfa, %d kayıt tarandı, %d IPv6 atlandı) ──",
                    new_domains, stats["domain"]["pages"], stats["domain"]["seen"],
                    new_ips, stats["ip_address"]["pages"],
                    stats["ip_address"]["seen"], stats["ip_address"]["skipped"],
                )
                self.bd_client.last_sync_time = datetime.now(timezone.utc)
                self.bd_client.last_error = None
                await self._record_sync_ok()

            except Exception as exc:
                logger.error("Brandefense sync hatası: %s", exc, exc_info=True)
                self.bd_client.last_error = str(exc)[:200]
                await self.db.finish_sync_run(
                    run_id, new_records=new_ips + new_domains,
                    status="error", detail=str(exc)[:200],
                )
                return

        # Push, çekme kilidinin dışında (bkz. hash_sync)
        pushed = 0
        if self.cs and self.cs.enabled and (new_ips or new_domains):
            async with self._push_lock:
                pushed += await self.cs.sync_all_unpushed_domains(self.db)
                pushed += await self.cs.sync_all_unpushed(self.db)
        await self.db.finish_sync_run(
            run_id, new_records=new_ips + new_domains, pushed=pushed
        )

    async def full_sync(self) -> None:
        """
        Tam Senkronizasyon (Full Sync)
        ================================
        USOM API'deki tüm sayfaları asenkron olarak tarar ve veritabanını günceller.

        Kullanım senaryoları:
            - İlk başlatma (Initial Sync)
            - Haftalık tam senkronizasyon (tutarlılık garantisi)

        Strateji:
            - Önce sayfa 0'ı çekerek toplam sayfa sayısını öğren
            - Kalan sayfaları Semaphore korumasıyla eşzamanlı çek
            - Veritabanını temizlemeden INSERT OR IGNORE ile ekle
              (full sync sırasında veri kaybı riskini minimize eder)
        """
        run_id = await self.db.start_sync_run("ip_full")
        async with self._sync_lock:
            logger.info("═══ TAM SENKRONİZASYON BAŞLADI ═══")
            start_time = datetime.now(timezone.utc)
            total_new = 0

            try:
                # 1. Adım: İlk sayfayı çek → toplam sayfa sayısını öğren
                first_page = await self.client.fetch_page(0)
                page_count = first_page.get("pageCount", 1)
                total_count = first_page.get("totalCount", 0)
                logger.info(
                    "USOM API: %d IP adresi, %d sayfa tespit edildi.",
                    total_count,
                    page_count,
                )

                # İlk sayfanın IP'lerini kaydet
                ips = self.client.extract_ips(first_page)
                new_count = await self.db.insert_ips(ips)
                total_new += new_count

                # 2. Adım: Kalan sayfaları paralel olarak çek
                # Çok fazla eşzamanlı görev oluşturmamak için batch'ler halinde işle
                batch_size = MAX_CONCURRENT_REQUESTS * 2  # 6 sayfa/batch
                for batch_start in range(1, page_count, batch_size):
                    batch_end = min(batch_start + batch_size, page_count)
                    tasks = [
                        self._fetch_and_store(page)
                        for page in range(batch_start, batch_end)
                    ]
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    for i, result in enumerate(results):
                        page_num = batch_start + i
                        if isinstance(result, BaseException):
                            logger.error(
                                "Sayfa %d çekilemedi: %s", page_num, result
                            )
                        else:
                            total_new += result

                    # İlerleme logu
                    progress = min(batch_end, page_count)
                    logger.info(
                        "İlerleme: %d/%d sayfa işlendi...", progress, page_count
                    )

                    # Batch'ler arası bekleme — 429 rate limit koruması
                    await asyncio.sleep(1.0)

                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                db_total = await self.db.get_ip_count()
                logger.info(
                    "═══ TAM SENKRONİZASYON TAMAMLANDI ═══ "
                    "Süre: %.1fs | Yeni IP: %d | Toplam DB: %d",
                    elapsed,
                    total_new,
                    db_total,
                )
                await self._record_sync_ok()
                await self.db.finish_sync_run(run_id, new_records=total_new)

            except Exception as e:
                logger.error("Tam senkronizasyon hatası: %s", e, exc_info=True)
                await self.db.finish_sync_run(
                    run_id, new_records=total_new, status="error", detail=str(e)[:200]
                )

    async def delta_sync(self) -> None:
        """
        Kısmi Senkronizasyon (Delta Sync)
        ===================================
        Sadece yeni eklenen IP adreslerini çeker. API en yeni kayıtları ilk
        sayfadan döndürdüğü için, zaten veritabanında bulunan bir IP'ye
        rastlayana kadar sayfaları tarar.

        Optimizasyon:
            - Maksimum DELTA_SYNC_MAX_PAGES sayfa tarar (varsayılan: 10)
            - Bilinen bir IP'ye rastladığında erken durur
            - Bu sayede API'ye gereksiz yük binmez
        """
        run_id = await self.db.start_sync_run("ip_delta")
        async with self._sync_lock:
            logger.info("── Kısmi senkronizasyon (Delta Sync) başladı ──")
            total_new = 0
            stop_early = False

            try:
                for page in range(DELTA_SYNC_MAX_PAGES):
                    data = await self.client.fetch_page(page)
                    ips = self.client.extract_ips(data)

                    if not ips:
                        logger.info("Sayfa %d boş döndü, delta sync durduruluyor.", page)
                        break

                    # Sayfadaki IP'lerin mevcut durumunu kontrol et
                    new_ips = []
                    for ip in ips:
                        if await self.db.ip_exists(ip):
                            # Bilinen bir IP'ye rastladık → artık yeni veri yok
                            stop_early = True
                            break
                        new_ips.append(ip)

                    if new_ips:
                        count = await self.db.insert_ips(new_ips)
                        total_new += count
                        if self.cs and self.cs.enabled:
                            # Bu yol yalnızca USOM delta'sını taşıyor;
                            # kaynak açıkça verilir ki varsayılan değişirse
                            # yanlış saklama süresi yazılmasın.
                            cs_pushed, cs_pushed_ips = await self.cs.push_ips(
                                new_ips, source=SOURCE_USOM)
                            if cs_pushed_ips:
                                await self.db.mark_ips_pushed(cs_pushed_ips)
                                logger.info("CrowdStrike'a %d IP eklendi ve işaretlendi.", cs_pushed)

                    if stop_early:
                        logger.info(
                            "Sayfa %d'de bilinen IP'ye rastlandı, erken durduruluyor.",
                            page,
                        )
                        break

                    # Sayfalar arası kısa bekleme (rate limit koruması)
                    await asyncio.sleep(0.5)

                db_total = await self.db.get_ip_count()
                logger.info(
                    "── Delta Sync tamamlandı | Yeni IP: %d | Toplam DB: %d ──",
                    total_new,
                    db_total,
                )
                await self._record_sync_ok()
                await self.db.finish_sync_run(run_id, new_records=total_new)

            except Exception as e:
                logger.error("Delta sync hatası: %s", e, exc_info=True)
                await self.db.finish_sync_run(
                    run_id, new_records=total_new, status="error", detail=str(e)[:200]
                )

    async def _fetch_and_store(self, page: int) -> int:
        """
        Tek bir sayfayı çekip IP'lerini veritabanına kaydeden yardımcı metot.

        Args:
            page: Çekilecek sayfa numarası.

        Returns:
            Bu sayfadan eklenen yeni IP sayısı.
        """
        data = await self.client.fetch_page(page)
        ips = self.client.extract_ips(data)
        return await self.db.insert_ips(ips)

    # ── Domain Senkronizasyon Metodları ──
    async def domain_full_sync(self) -> None:
        """Tüm zararlı domainleri baştan sona çeker."""
        run_id = await self.db.start_sync_run("domain_full")
        async with self._sync_lock:
            logger.info("═══ DOMAIN TAM SENKRONİZASYON BAŞLADI ═══")
            start_time = datetime.now(timezone.utc)
            total_new = 0
            try:
                first_page = await self.client.fetch_page(0, data_type="domain")
                page_count = first_page.get("pageCount", 1)
                total_count = first_page.get("totalCount", 0)
                logger.info("Domain API: %d Domain, %d sayfa tespit edildi.", total_count, page_count)

                domains = self.client.extract_domains(first_page)
                total_new += await self.db.insert_domains(domains)

                batch_size = MAX_CONCURRENT_REQUESTS * 2
                for batch_start in range(1, page_count, batch_size):
                    batch_end = min(batch_start + batch_size, page_count)
                    tasks = [self._fetch_and_store_domains(p) for p in range(batch_start, batch_end)]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in results:
                        if not isinstance(result, BaseException):
                            total_new += result
                    await asyncio.sleep(1.0)

                db_total = await self.db.get_domain_count()
                logger.info("═══ DOMAIN TAM SENKRONİZASYON TAMAMLANDI ═══ Yeni: %d | Toplam: %d", total_new, db_total)
                await self._record_sync_ok()
            except Exception as e:
                logger.error("Domain tam senkronizasyon hatası: %s", e, exc_info=True)
                await self.db.finish_sync_run(
                    run_id, new_records=total_new, status="error", detail=str(e)[:200]
                )
                run_id = None

        # Push, çekme kilidinin DIŞINDA: uzun sürer, diğer sync'leri bekletmemeli.
        pushed = 0
        if self.cs and self.cs.enabled:
            async with self._push_lock:
                pushed = await self.cs.sync_all_unpushed_domains(self.db)
        await self.db.finish_sync_run(run_id, new_records=total_new, pushed=pushed)

    async def domain_delta_sync(self) -> None:
        """Sadece yeni eklenen domainleri çeker."""
        run_id = await self.db.start_sync_run("domain_delta")
        async with self._sync_lock:
            logger.info("── Domain Delta Sync başladı ──")
            total_new = 0
            stop_early = False
            try:
                for page in range(DELTA_SYNC_MAX_PAGES):
                    data = await self.client.fetch_page(page, data_type="domain")
                    domains = self.client.extract_domains(data)
                    if not domains:
                        break
                    new_domains = []
                    for domain in domains:
                        if await self.db.domain_exists(domain):
                            stop_early = True
                            break
                        new_domains.append(domain)
                    if new_domains:
                        total_new += await self.db.insert_domains(new_domains)
                    if stop_early:
                        break
                    await asyncio.sleep(0.5)
                db_total = await self.db.get_domain_count()
                logger.info("── Domain Delta Sync tamamlandı | Yeni: %d | Toplam: %d ──", total_new, db_total)
                await self._record_sync_ok()
            except Exception as e:
                logger.error("Domain delta sync hatası: %s", e, exc_info=True)
                await self.db.finish_sync_run(
                    run_id, new_records=total_new, status="error", detail=str(e)[:200]
                )
                run_id = None

        # Push, çekme kilidinin DIŞINDA (bkz. domain_full_sync).
        pushed = 0
        if self.cs and self.cs.enabled:
            async with self._push_lock:
                pushed = await self.cs.sync_all_unpushed_domains(self.db)
        await self.db.finish_sync_run(run_id, new_records=total_new, pushed=pushed)

    async def _fetch_and_store_domains(self, page: int) -> int:
        data = await self.client.fetch_page(page, data_type="domain")
        domains = self.client.extract_domains(data)
        return await self.db.insert_domains(domains)


# ─────────────────────────────────────────────────────
# 5. ZAMANLAYICI KATMANI (APScheduler)
# ─────────────────────────────────────────────────────
def setup_scheduler(sync_service: SyncService) -> AsyncIOScheduler:
    """
    APScheduler ile zamanlanmış görevleri yapılandırır.

    Görevler:
        1. Saatlik Delta Sync  → Her saat başı çalışır (XX:05)
        2. Haftalık Full Sync  → Her Pazar gecesi 03:00'te çalışır

    Returns:
        Yapılandırılmış AsyncIOScheduler nesnesi.
    """
    scheduler = AsyncIOScheduler(timezone="Europe/Istanbul")

    # Saatlik Kısmi Senkronizasyon: Her saatin 5. dakikasında
    scheduler.add_job(
        sync_service.delta_sync,
        trigger=CronTrigger(minute=5),
        id="delta_sync_hourly",
        name="USOM Saatlik Delta Sync",
        max_instances=1,               # Önceki iş bitmeden yeni iş başlamasın
        replace_existing=True,
        misfire_grace_time=300,         # 5 dakika gecikmeye tolerans
    )

    # Haftalık Tam Senkronizasyon: Her Pazar gecesi saat 03:00'te
    scheduler.add_job(
        sync_service.full_sync,
        trigger=CronTrigger(day_of_week="sun", hour=3, minute=0),
        id="full_sync_weekly",
        name="USOM Haftalık Full Sync",
        max_instances=1,
        replace_existing=True,
        misfire_grace_time=3600,        # 1 saat gecikmeye tolerans
    )

    # Domain Saatlik Delta Sync: Her saatin 10. dakikasında (IP sync'ten 5dk sonra)
    scheduler.add_job(
        sync_service.domain_delta_sync,
        trigger=CronTrigger(minute=10),
        id="domain_delta_sync_hourly",
        name="Domain Saatlik Delta Sync",
        max_instances=1,
        replace_existing=True,
        misfire_grace_time=300,
    )

    # Domain Haftalık Full Sync: Her Pazar 04:00'te
    scheduler.add_job(
        sync_service.domain_full_sync,
        trigger=CronTrigger(day_of_week="sun", hour=4, minute=0),
        id="domain_full_sync_weekly",
        name="Domain Haftalık Full Sync",
        max_instances=1,
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # Hash Saatlik Sync: Her saatin 15. dakikasında (domain sync'ten 5 dk sonra)
    scheduler.add_job(
        sync_service.hash_sync,
        trigger=CronTrigger(minute=15),
        id="hash_sync_hourly",
        name="MalwareBazaar Saatlik Hash Sync",
        max_instances=1,
        replace_existing=True,
        misfire_grace_time=300,
    )

    # Brandefense Saatlik Sync: Her saatin 30. dakikasında.
    # Hash sync'ten 15 dakika sonra: iki görev de CrowdStrike push'u
    # yapıyor ve push kilitleri farklı olsa da API'yi aynı anda
    # zorlamamak için aralık bırakılıyor.
    if sync_service.bd_client and sync_service.bd_client.enabled:
        scheduler.add_job(
            sync_service.brandefense_sync,
            trigger=CronTrigger(minute=30),
            id="brandefense_sync_hourly",
            name="Brandefense Saatlik IOC Sync",
            max_instances=1,
            replace_existing=True,
            misfire_grace_time=300,
        )

    # Saklama Temizliği: her gün 02:30.
    #
    # Saat seçimi: saatlik delta sync'ler :05/:10/:15/:30'da çalışıyor ve
    # Pazar full sync'leri 03:00/04:00'te. 02:30 ikisinin de dışında —
    # temizlik tam da yeniden ekleme yapan bir sync'le çakışırsa, aynı
    # göstergeyi bir görev silerken diğeri geri yazabilirdi.
    # Full sync'ten ÖNCE olması ayrıca iyi: temizlik yer açar, hemen
    # ardından gelen full sync açılan yere yazabilir.
    if any(days > 0 for days in RETENTION_DAYS.values()):
        scheduler.add_job(
            sync_service.retention_sync,
            trigger=CronTrigger(hour=2, minute=30),
            id="retention_daily",
            name="Günlük Saklama Temizliği",
            max_instances=1,
            replace_existing=True,
            misfire_grace_time=3600,
        )
    else:
        logger.warning(
            "Saklama temizliği zamanlanmadı: tüm kaynakların TTL'i 0 "
            "(süresiz). CrowdStrike gösterge limiti dolarsa yeni "
            "göstergeler basılamaz."
        )

    # Görev arızalarını görünür kıl.
    # max_instances=1 olduğu için önceki çalışma bitmezse APScheduler sonraki
    # tetiklemeleri sessizce atlar — 2026 Haziran'daki 55 günlük sessiz duruşun
    # sebebi buydu. Artık her atlama ERROR olarak loglanır.
    def _job_event_listener(event) -> None:
        if event.code == EVENT_JOB_MAX_INSTANCES:
            logger.error(
                "ZAMANLAYICI ALARM: '%s' görevi hâlâ çalışıyor olduğu için bu "
                "tetikleme atlandı. Görev takılmış olabilir.", event.job_id
            )
        elif event.code == EVENT_JOB_MISSED:
            logger.error(
                "ZAMANLAYICI ALARM: '%s' görevi kaçırıldı (planlanan: %s).",
                event.job_id, getattr(event, "scheduled_run_time", "?")
            )
        elif event.code == EVENT_JOB_ERROR:
            logger.error(
                "ZAMANLAYICI ALARM: '%s' görevi hata ile sonlandı: %s",
                event.job_id, getattr(event, "exception", "?"), exc_info=True
            )

    scheduler.add_listener(
        _job_event_listener,
        EVENT_JOB_ERROR | EVENT_JOB_MISSED | EVENT_JOB_MAX_INSTANCES,
    )

    logger.info(
        "Zamanlayıcı yapılandırıldı: "
        "IP Delta → :05 | IP Full → Pazar 03:00 | "
        "Domain Delta → :10 | Domain Full → Pazar 04:00 | "
        "Hash Sync → :15 | Saklama → her gün 02:30"
    )
    return scheduler


# ─────────────────────────────────────────────────────
# 6. FASTAPI UYGULAMA FABRİKASI
# ─────────────────────────────────────────────────────

# Servis bileşenlerini modül seviyesinde tanımla (endpoint'lerin erişebilmesi için)
db = IPDatabase()
usom_client = USOMClient()
mb_client = MalwareBazaarClient()
bd_client = BrandefenseClient()
cs_service = CrowdStrikeService()
sync_service = SyncService(
    client=usom_client, db=db, cs=cs_service, mb_client=mb_client,
    bd_client=bd_client,
)
scheduler: Optional[AsyncIOScheduler] = None

# Dağılım sorgularının süreç içi önbelleği.
# Redis gibi bir dış bileşen eklenmedi: servis tek süreç olarak çalışıyor
# ve önbelleğin kaybolmasının tek maliyeti bir sorgunun yeniden koşması.
_DISTRIBUTION_CACHE: dict = {"at": 0.0, "data": None}

# Kapanış sinyali. Uzun ömürlü SSE akışları bunu bekler.
#
# Bu olayı lifespan'in kapanış bloğunda set etmek İŞE YARAMAZ: uvicorn
# önce açık bağlantıların boşalmasını bekler, lifespan kapanışını ondan
# SONRA çalıştırır. Yani akış olayı, olay da akışı bekler — kilitlenme.
# Doğrulandı: SIGTERM sonrası süreç 2 dakikada kapanmadı.
# Bu yüzden olay doğrudan sinyal yakalanarak set edilir (bkz.
# _install_shutdown_signal_hook).
SHUTDOWN_EVENT = asyncio.Event()


def _install_shutdown_signal_hook() -> None:
    """
    SIGTERM/SIGINT geldiğinde SHUTDOWN_EVENT'i set eden bir kanca kurar ve
    ardından uvicorn'un kendi işleyicisini çağırır.

    Uvicorn sinyalleri signal.signal() ile yakaladığı için mevcut
    işleyici okunup zincirlenebiliyor. Kanca kurulamazsa (farklı bir
    çalıştırıcı, ana thread dışı çağrı) servis normal çalışmaya devam
    eder; o durumda akışlar SSE_MAX_TICKS dolduğunda kapanır ve
    uvicorn'un --timeout-graceful-shutdown değeri devreye girer.
    """
    import signal

    def make_handler(previous):
        def handler(signum, frame):
            SHUTDOWN_EVENT.set()
            if callable(previous):
                previous(signum, frame)
        return handler

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, make_handler(signal.getsignal(sig)))
        except (ValueError, OSError, RuntimeError) as exc:
            logger.warning("Kapanış sinyali kancası kurulamadı (%s): %s", sig, exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI yaşam döngüsü yöneticisi.

    Başlatma (Startup):
        1. Veritabanı bağlantısını aç
        2. HTTP istemcisini başlat
        3. İlk tam senkronizasyonu (Initial Sync) arka planda başlat
        4. Zamanlanmış görevleri aktifleştir

    Kapanma (Shutdown):
        1. Zamanlayıcıyı durdur
        2. HTTP istemcisini kapat
        3. Veritabanı bağlantısını kapat
    """
    global scheduler

    # ── STARTUP ──
    logger.info("🚀 USOMListService başlatılıyor...")

    # Saklama yapılandırması logger kurulmadan önce okunuyor; orada
    # biriken uyarılar ilk iş olarak burada görünür hâle gelir.
    for warning in _CONFIG_WARNINGS:
        logger.warning("YAPILANDIRMA: %s", warning)
    logger.info(
        "Saklama politikası: %s | tur başına üst sınır: %d",
        " | ".join(
            f"{src}: {days} gün" if days else f"{src}: süresiz"
            for src, days in sorted(RETENTION_DAYS.items())
        ),
        RETENTION_MAX_PER_RUN,
    )

    await db.connect()
    await usom_client.start()
    await mb_client.start()
    await bd_client.start()

    # CrowdStrike servisi red kayıtlarını veritabanına yazabilsin.
    # Bağlantı burada kurulduğu için referans açılışta değil, şimdi atanır.
    cs_service.db = db

    # Uvicorn sinyal işleyicilerini sunucu başlarken kurduğu için kanca
    # burada zincirlenebiliyor.
    _install_shutdown_signal_hook()

    # Mevcut veri sayısını kontrol et
    existing_count = await db.get_ip_count()
    logger.info("Veritabanında mevcut IP sayısı: %d", existing_count)

    # İlk senkronizasyonu arka plan görevi olarak başlat
    # (Uygulama isteklere hemen yanıt verebilsin)
    if existing_count == 0:
        logger.info("Veritabanı boş → İlk Tam Senkronizasyon başlatılıyor...")
        asyncio.create_task(sync_service.full_sync())
    else:
        logger.info(
            "Veritabanında %d IP mevcut → Delta Sync başlatılıyor...",
            existing_count,
        )
        asyncio.create_task(sync_service.delta_sync())

    # Domain senkronizasyonu başlat
    domain_count = await db.get_domain_count()
    if domain_count == 0:
        logger.info("Domain veritabanı boş → Domain Tam Senkronizasyon başlatılıyor...")
        asyncio.create_task(sync_service.domain_full_sync())
    else:
        logger.info("Veritabanında %d domain mevcut → Domain Delta Sync başlatılıyor...", domain_count)
        asyncio.create_task(sync_service.domain_delta_sync())

    # Hash senkronizasyonu (MalwareBazaar) — açılışta bir kez, sonra saatlik
    hash_count = await db.get_hash_count()
    logger.info("Veritabanında mevcut hash sayısı: %d → Hash Sync başlatılıyor...", hash_count)
    asyncio.create_task(sync_service.hash_sync())

    # CrowdStrike: Veritabanında gönderilmemiş IP varsa topluca gönder
    if cs_service.enabled and cs_service.push_enabled:
        async def _initial_cs_sync():
            await asyncio.sleep(5)  # DB sync başlayana kadar kısa bekleme
            await cs_service.sync_all_unpushed(db)
        asyncio.create_task(_initial_cs_sync())
    elif cs_service.enabled:
        logger.warning(
            "CrowdStrike GÖNDERİMİ KAPALI (FALCON_PUSH_ENABLED=false). "
            "Göstergeler toplanmaya devam edecek ama CrowdStrike'a "
            "basılmayacak; silme işlemleri çalışmaya devam eder."
        )

    # Zamanlanmış görevleri başlat
    scheduler = setup_scheduler(sync_service)
    scheduler.start()
    logger.info("✅ USOMListService hazır — istekler kabul ediliyor.")

    yield  # ── Uygulama çalışıyor ──

    # ── SHUTDOWN ──
    logger.info("⏹ USOMListService kapatılıyor...")
    # Sinyal kancası kurulamadığı durumda son bir güvence — normalde olay
    # buraya gelinmeden önce sinyal işleyicisinde set edilmiş olur.
    SHUTDOWN_EVENT.set()
    if scheduler:
        scheduler.shutdown(wait=False)
    await usom_client.stop()
    await mb_client.stop()
    await bd_client.stop()
    await db.close()
    logger.info("👋 USOMListService kapatıldı.")


# FastAPI uygulama örneği
app = FastAPI(
    title=SERVICE_TITLE,
    description=(
        "Siber Güvenlik Başkanlığı API'sinden zararlı IP adresleri ve Domainleri "
        "toplayan ve güvenlik cihazlarına plain-text formatında sunan "
        "tehdit istihbaratı mikroservisi."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ─────────────────────────────────────────────────────
# 7. ENDPOINT'LER
# ─────────────────────────────────────────────────────

@app.get(
    "/",
    response_class=HTMLResponse,
    summary="Durum Panosu",
    description=(
        "Servisin durumunu, veritabanı istatistiklerini ve CrowdStrike "
        "gönderim ilerlemesini gösteren, kendini otomatik yenileyen web panosu."
    ),
    tags=["System"],
    include_in_schema=False,
)
async def dashboard():
    """
    Gösterge panosunu döndürür.

    Sayfa statiktir; tüm veriyi tarayıcı tarafında /health uç noktasından
    15 saniyede bir çekerek tazeler. Böylece sunucu tarafında şablon
    motoruna veya ek bir bağımlılığa gerek kalmaz.

    Tek istisna {{SERVICE_TITLE}} yer tutucusudur: şablon zaten her istekte
    diskten okunduğu için tek bir string değişimi, bir şablon motoru
    bağımlılığı eklemeden servis adını yapılandırılabilir kılıyor.
    """
    try:
        html = DASHBOARD_PATH.read_text(encoding="utf-8")
        return HTMLResponse(html.replace("{{SERVICE_TITLE}}", escape(SERVICE_TITLE)))
    except OSError as exc:
        logger.error("Gösterge panosu okunamadı (%s): %s", DASHBOARD_PATH, exc)
        return HTMLResponse(
            f"<h1>{escape(SERVICE_TITLE)}</h1>"
            "<p>Pano şablonu bulunamadı. Servis çalışmaya devam ediyor — "
            "<a href='/health'>/health</a> üzerinden durumu görebilirsiniz.</p>",
            status_code=503,
        )


@app.get(
    "/usom-ips",
    response_class=PlainTextResponse,
    summary="Zararlı IP Listesi (Plain Text)",
    description=(
        "Güvenlik duvarlarının doğrudan okuyabileceği formatta tüm zararlı IP "
        "adreslerini döndürür. Her satırda bir IP adresi bulunur."
    ),
    tags=["Threat Intelligence"],
)
async def get_usom_ips():
    """
    Tüm zararlı IP adreslerini newline ile ayrılmış plain-text olarak döndürür.

    Güvenlik cihazları bu endpoint'i doğrudan blocklist olarak kullanabilir:
        - Firewall: External threat feed olarak eklenebilir
        - WAF: IP deny-list olarak import edilebilir
        - Mail Gateway: Spam/phishing kaynağı olarak engellenebilir

    Response Headers:
        Content-Type: text/plain; charset=utf-8
    """
    ips = await db.get_all_ips()
    return PlainTextResponse(
        content="\r\n".join(ips) + "\r\n" if ips else "",
        media_type="text/plain",
        headers={
            "X-Total-Count": str(len(ips)),
            "Cache-Control": "public, max-age=300",  # 5 dakika cache
        },
    )


@app.get(
    "/usom-domains",
    response_class=PlainTextResponse,
    summary="Zararlı Domain Listesi (Plain Text)",
    description="Tüm zararlı domainleri döndürür. Her satırda bir domain bulunur.",
    tags=["Threat Intelligence"],
)
async def get_usom_domains():
    """Tüm zararlı domainleri newline ile ayrılmış plain-text olarak döndürür."""
    domains = await db.get_all_domains()
    return PlainTextResponse(
        content="\r\n".join(domains) + "\r\n" if domains else "",
        media_type="text/plain",
        headers={
            "X-Total-Count": str(len(domains)),
            "Cache-Control": "public, max-age=300",
        },
    )


@app.get(
    "/malware-hashes",
    response_class=PlainTextResponse,
    summary="Zararlı Yazılım Hash Listesi — SHA256 (Plain Text)",
    description=(
        "abuse.ch MalwareBazaar kaynaklı zararlı yazılım SHA256 hash'lerini "
        "düz metin olarak döndürür. Her satırda bir hash bulunur."
    ),
    tags=["Threat Intelligence"],
)
async def get_malware_hashes(
    include_unverified: bool = Query(
        False,
        description=(
            "Gönderim dışı bırakılmış (imzasız / sistem ikilisi adı taşıyan) "
            "hash'leri de dahil et. Varsayılan: hayır."
        ),
    ),
):
    """
    Zararlı yazılım SHA256 hash'lerini plain-text olarak döndürür.

    Varsayılan olarak yalnızca aksiyon alınması güvenli bulunan kayıtlar
    döner: MalwareBazaar'da bir zararlı yazılım ailesine eşleşmiş ve dosya
    adı yaygın bir sistem ikilisi olmayanlar. Bu beslemeyi tüketen cihazlar
    engelleme yaptığı için ayrım burada da uygulanır.
    """
    hashes = await db.get_all_hashes(include_blocked=include_unverified)
    blocked = await db.get_blocked_count("hash")
    return PlainTextResponse(
        content="\r\n".join(hashes) + "\r\n" if hashes else "",
        media_type="text/plain",
        headers={
            "X-Total-Count": str(len(hashes)),
            # Neyin dışarıda kaldığı sessiz kalmamalı: besleme tüketen
            # tarafın listenin filtrelendiğini bilmesi gerekir.
            "X-Excluded-Unverified": str(0 if include_unverified else blocked),
            "Cache-Control": "public, max-age=300",
        },
    )


@app.get(
    "/malware-hashes/md5",
    response_class=PlainTextResponse,
    summary="Zararlı Yazılım Hash Listesi — MD5 (Plain Text)",
    description=(
        "Aynı örneklerin MD5 karşılıkları. Yalnızca MD5 kabul eden eski "
        "sistemler için sunulur; CrowdStrike'a SHA256 basılır."
    ),
    tags=["Threat Intelligence"],
)
async def get_malware_hashes_md5(
    include_unverified: bool = Query(
        False,
        description="Gönderim dışı bırakılmış hash'leri de dahil et.",
    ),
):
    """Zararlı yazılım MD5 hash'lerini plain-text olarak döndürür."""
    hashes = await db.get_all_md5(include_blocked=include_unverified)
    blocked = await db.get_blocked_count("hash")
    return PlainTextResponse(
        content="\r\n".join(hashes) + "\r\n" if hashes else "",
        media_type="text/plain",
        headers={
            "X-Total-Count": str(len(hashes)),
            "X-Excluded-Unverified": str(0 if include_unverified else blocked),
            "Cache-Control": "public, max-age=300",
        },
    )


@app.get(
    "/stats",
    summary="Detaylı İstatistikler",
    description=(
        "Zaman serisi ve çalışma geçmişi istatistikleri: son 30 günün "
        "günlük yeni gösterge sayıları, dönemsel toplamlar ve son "
        "senkronizasyon çalışmaları."
    ),
    tags=["System"],
)
async def stats():
    """
    Panonun grafik ve geçmiş bölümlerini besleyen istatistikler.

    /health anlık durumu verir; burası zaman içindeki değişimi verir.
    İkisi ayrı tutulur çünkü /health izleme sistemleri tarafından sık
    çağrılır ve hafif kalmalıdır — buradaki sorgular daha maliyetlidir.
    """
    daily = await db.get_daily_additions(30)
    ip_n = await db.get_ip_count()
    dom_n = await db.get_domain_count()
    hash_n = await db.get_hash_count()
    grand = ip_n + dom_n + hash_n

    def share(n: int) -> float:
        return round(100 * n / grand, 2) if grand else 0.0

    # Kaynak bazında dağılım artık veritabanındaki source kolonundan
    # üretiliyor. Sabit listede tutulamaz: birden fazla kaynak aynı
    # tabloya yazıyor ve kaynak sayısı yapılandırmayla değişebiliyor.
    type_labels = {"ip": "IP", "domain": "Domain", "hash": "Hash"}
    source_counts = await db.get_source_counts()
    sources = []
    for key, counts in source_counts.items():
        label, detail = SOURCE_LABELS.get(key, (key, ""))
        total = sum(counts.values())
        if not total:
            continue
        sources.append({
            "source": label,
            "detail": detail,
            "total": total,
            "share": share(total),
            "types": [
                {"type": t, "label": type_labels[t], "count": counts[t],
                 "share": share(counts[t])}
                for t in ("ip", "domain", "hash") if counts.get(t)
            ],
        })
    sources.sort(key=lambda s: s["total"], reverse=True)

    return {
        "sources": sources,
        "grand_total": grand,
        "daily_additions": daily,
        "periods": {
            "last_24h": await db.get_additions_since(24),
            "last_7d": await db.get_additions_since(24 * 7),
            "last_30d": await db.get_additions_since(24 * 30),
        },
        "reliability_24h": await db.get_run_reliability(24),
        "recent_runs": await db.get_recent_runs(10),
        # Hata görünürlüğü. Bekleyen kuyruk büyükken "neden ilerlemiyor"
        # sorusunun cevabı burada: kalıcı bir red (uzunluk sınırı) ile
        # geçici bir arıza (rate limit, yetki) farklı aksiyon gerektirir.
        "rejections": await db.get_rejection_summary(24 * 7),
        "recent_rejections": await db.get_recent_rejections(20),
        "last_failures": await db.get_last_failures(6),
        # Bloke göstergeler: reddedilenlerden ayrı tutulur çünkü farklı bir
        # şey söylüyorlar. "Reddedildi" bir olay (dönen kayıt defteri),
        # "bloke" ise kalıcı bir durum — aksiyon gerektiren liste bu.
        "blocked": {
            "ip": await db.get_blocked_count("ip"),
            "domain": await db.get_blocked_count("domain"),
            "hash": await db.get_blocked_count("hash"),
            "items": await db.get_blocked(25),
        },
        "totals": {"ip": ip_n, "domain": dom_n, "hash": hash_n},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


@app.get(
    "/stats/distribution",
    summary="Dağılım İstatistikleri",
    description=(
        "Alan adı uzantısı (TLD) dağılımı, en yoğun /16 IP blokları, "
        "gösterge eklenme saatlerinin dağılımı ve kümülatif büyüme eğrisi. "
        "Sonuç sunucuda kısa süreli önbelleğe alınır."
    ),
    tags=["System"],
)
async def stats_distribution():
    """
    Ağır dağılım sorguları — /stats'tan ayrı tutulur.

    Bu sorgular tam tablo tarar. /stats panoda dakikada bir çağrılıyor;
    dağılımlar o hızda değişmediği için ayrı bir endpoint'te ve
    DISTRIBUTION_CACHE_TTL boyunca önbellekte tutulur. Böylece pano
    açık kalan bir sekmede saatlerce dursa bile veritabanı gereksiz
    taranmaz.
    """
    now = time.time()
    cached = _DISTRIBUTION_CACHE.get("data")
    if cached is not None and now - _DISTRIBUTION_CACHE["at"] < DISTRIBUTION_CACHE_TTL:
        return {**cached, "cached": True,
                "cache_age_seconds": int(now - _DISTRIBUTION_CACHE["at"])}

    data = {
        "tld": await db.get_tld_distribution(10),
        "subnet16": await db.get_subnet_distribution(10),
        "hourly": await db.get_hour_histogram(7),
        "cumulative": await db.get_cumulative(30),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    _DISTRIBUTION_CACHE["data"] = data
    _DISTRIBUTION_CACHE["at"] = now
    return {**data, "cached": False, "cache_age_seconds": 0}


@app.get(
    "/lookup",
    summary="Gösterge Sorgulama",
    description=(
        "Tek bir IP, alan adı, sha256 veya md5 değerinin veritabanında "
        "bulunup bulunmadığını, ne zaman eklendiğini, CrowdStrike'a "
        "gönderilip gönderilmediğini ve daha önce reddedilmişse sebebini "
        "döndürür."
    ),
    tags=["System"],
)
async def lookup(
    q: str = Query(
        ...,
        min_length=1,
        max_length=LOOKUP_MAX_LENGTH,
        description="Aranacak IP, alan adı, sha256 veya md5 değeri",
    ),
):
    """
    Tek gösterge sorgusu.

    Yeni bir bilgi açığa çıkarmıyor: aynı göstergeler /usom-ips,
    /usom-domains ve /malware-hashes uçlarından tam liste hâlinde zaten
    yayımlanıyor. Buradaki fark, 400 binlik bir listeyi indirmek yerine
    tek bir değerin durumunu — özellikle "gönderildi mi, gönderilmediyse
    neden" bilgisini — doğrudan sorabilmek.

    Yerelde kayıt yoksa CrowdStrike'a da bakılır. "Veritabanında yok"
    cevabı tek başına yanıltıcı: gösterge orada durup engellemeye devam
    ediyor olabilir ve operatörün silmesi gereken asıl kayıt odur.
    """
    result = await db.lookup_indicator(q)

    # Eski URL kayıtlarında yerel 'pushed' bayrağı CrowdStrike'ın bugünkü
    # durumunu anlatmıyor: o bayrak "eski akış bu satırı işledi" demek,
    # "gösterge şu an orada duruyor" demek değil — ikisi ayrışabiliyor
    # (eski akış kısaltıcı apex'lerini eliyordu ama 'www.' biçimini
    # elemiyordu). Gönderildi deyip silinecek bir şey bulamamak, bu işin
    # ta kendisi; o yüzden bu satırlarda asıl yere bakılır.
    for m in result.get("matches") or []:
        if m.get("source") == SOURCE_LEGACY_URL:
            m["cs_present"] = bool(
                await cs_service.find_indicator(m["type"], m["value"])
            )

    if not result.get("matches"):
        orphans: list[dict] = []
        for kind, probe in cs_probe_targets(q):
            orphans.extend(await cs_service.find_indicator(kind, probe))
        if orphans:
            logger.warning(
                "YETİM GÖSTERGE: '%s' yerel veritabanında yok ama "
                "CrowdStrike'ta %d kayıt olarak duruyor.", q, len(orphans),
            )
        result["crowdstrike_only"] = orphans
    return result


@app.get(
    "/recent",
    summary="Son Eklenen Göstergeler",
    description="Veritabanına en son eklenen göstergeleri tarihe göre azalan döndürür.",
    tags=["System"],
)
async def recent(
    limit: int = Query(50, ge=1, le=RECENT_MAX_LIMIT),
    indicator_type: str = Query(
        "all", alias="type", pattern="^(all|ip|domain|hash)$",
        description="all | ip | domain | hash",
    ),
):
    """Panonun 'son eklenenler' akışını besler."""
    items = await db.get_recent_indicators(limit, indicator_type)
    return {"count": len(items), "type": indicator_type, "items": items}


def _csv_cell(value) -> str:
    """Tek bir CSV hücresini RFC 4180'e uygun biçimde kaçışlar."""
    if value is None:
        return ""
    text = str(value)
    if any(ch in text for ch in (',', '"', "\n", "\r")):
        return '"' + text.replace('"', '""') + '"'
    return text


@app.get(
    "/export/{kind}.csv",
    summary="CSV Dışa Aktarım",
    description=(
        "Göstergeleri eklenme tarihi ve gönderim durumuyla birlikte CSV "
        "olarak indirir. kind: ip | domain | hash"
    ),
    tags=["Feeds"],
)
async def export_csv(kind: str):
    """
    Plain-text beslemeler güvenlik cihazları için tasarlandı: yalnızca
    değer listesi döndürüyorlar. Bir analistin "bu kayıt ne zaman geldi,
    gönderildi mi" sorusunu cevaplamak için tarih ve durum sütunları da
    gerekiyor — CSV bu ihtiyacı karşılar.

    Yanıt akış hâlinde üretilir; büyük tabloda bellekte tam kopya oluşmaz.
    """
    if kind not in IPDatabase.EXPORT_QUERIES:
        return PlainTextResponse(
            f"Geçersiz tür: {kind} (ip | domain | hash)\n", status_code=400
        )
    _, header = IPDatabase.EXPORT_QUERIES[kind]

    async def rows():
        yield ",".join(header) + "\n"
        async for row in db.export_rows(kind):
            yield ",".join(_csv_cell(c) for c in row) + "\n"

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        rows(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition":
                f'attachment; filename="usom-{kind}-{stamp}.csv"',
            "Cache-Control": "no-store",
        },
    )


@app.get(
    "/events",
    summary="Canlı Durum Akışı (SSE)",
    description=(
        "Server-Sent Events akışı: /health yükünü periyodik olarak iletir. "
        "Pano bunu kullanarak sürekli yeni istek açmak zorunda kalmaz."
    ),
    tags=["System"],
)
async def events(request: Request):
    """
    Panonun her 15 saniyede yeni bir /health isteği açması yerine tek bir
    bağlantıdan beslenmesini sağlar.

    Akışın kapanması üç koşula bağlı:
      • istemci bağlantıyı kapattı (is_disconnected),
      • SSE_MAX_TICKS doldu — tarayıcı kendiliğinden yeniden bağlanır,
      • servis kapanıyor.
    Üçüncüsü olmasa uvicorn'un düzgün kapanışı uçuştaki bu isteği bekler
    ve `systemctl restart` zaman aşımına kadar takılırdı; bekleme
    asyncio.sleep yerine kapanış olayı üzerinden yapıldığı için sinyal
    anında görülür.

    Pano bu uç kullanılamazsa polling'e geri döner — akış zorunlu bir
    bağımlılık değildir.
    """
    async def stream():
        for _ in range(SSE_MAX_TICKS):
            if SHUTDOWN_EVENT.is_set() or await request.is_disconnected():
                break
            try:
                payload = await health_check()
                yield "event: health\ndata: " + json.dumps(
                    payload, ensure_ascii=False, default=str
                ) + "\n\n"
            except Exception as exc:
                logger.warning("SSE yükü üretilemedi: %s", exc)
                yield "event: error\ndata: " + json.dumps(
                    {"error": str(exc)}, ensure_ascii=False
                ) + "\n\n"
            try:
                # Kapanış sinyali gelirse beklemeyi hemen böl
                await asyncio.wait_for(SHUTDOWN_EVENT.wait(), timeout=SSE_INTERVAL)
                break
            except asyncio.TimeoutError:
                pass

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Ters vekil (nginx) yanıtı tamponlarsa akış anlamını yitirir.
            "X-Accel-Buffering": "no",
        },
    )


@app.get(
    "/health",
    summary="Sağlık Kontrolü",
    description="Servisin çalışır durumda olup olmadığını ve senkronizasyon metriklerini kontrol eder.",
    tags=["System"],
)
async def health_check():
    """
    Servis sağlık durumunu ve ek metrikleri raporlar.
    Information disclosure olmaması adına sistem içi yollar (path) veya versiyonlar (Python, OS) gizlenmiştir.
    """
    ip_count = await db.get_ip_count()
    domain_count = await db.get_domain_count()
    hash_count = await db.get_hash_count()
    pushed_ips = await db.get_pushed_count()
    pushed_domains = await db.get_pushed_domain_count()
    pushed_hashes = await db.get_pushed_hash_count()
    blocked_ips = await db.get_blocked_count("ip")
    blocked_domains = await db.get_blocked_count("domain")
    blocked_hashes = await db.get_blocked_count("hash")
    last_updated = await db.get_last_updated()
    uptime_seconds = int(time.time() - APP_START_TIME)
    
    next_sync_time = None
    if scheduler and scheduler.running:
        for job in scheduler.get_jobs():
            if job.next_run_time:
                if next_sync_time is None or job.next_run_time < next_sync_time:
                    next_sync_time = job.next_run_time

    def format_ts(ts_val) -> Optional[str]:
        if not ts_val:
            return None
        if isinstance(ts_val, str):
            try:
                if ts_val.endswith("Z"):
                    ts_val = ts_val[:-1] + "+00:00"
                dt = datetime.fromisoformat(ts_val)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                return ts_val
        if isinstance(ts_val, datetime):
            if ts_val.tzinfo:
                ts_val = ts_val.astimezone(timezone.utc)
            return ts_val.strftime("%Y-%m-%d %H:%M:%S UTC")
        return None

    def to_datetime(ts_val) -> Optional[datetime]:
        """Tazelik hesabı için değeri timezone-aware datetime'a çevirir."""
        if not ts_val:
            return None
        if isinstance(ts_val, str):
            try:
                if ts_val.endswith("Z"):
                    ts_val = ts_val[:-1] + "+00:00"
                ts_val = datetime.fromisoformat(ts_val)
            except ValueError:
                return None
        if isinstance(ts_val, datetime):
            if ts_val.tzinfo is None:
                ts_val = ts_val.replace(tzinfo=timezone.utc)
            return ts_val.astimezone(timezone.utc)
        return None

    # ── Tazelik kontrolü ──
    # Süreç ayakta diye "healthy" demek yeterli değil: görev takılırsa servis
    # cevap vermeye devam ederken veri aylarca bayatlayabilir.
    #
    # Ölçüt olarak son BAŞARILI SYNC damgası kullanılır, son eklenen kaydın
    # tarihi değil. USOM saatlerce yeni gösterge yayınlamayabilir; bu, servisin
    # arızalı olduğu anlamına gelmez.
    last_sync_ok = await db.get_meta(META_LAST_SYNC_OK)
    last_sync_dt = to_datetime(last_sync_ok)
    sync_age_seconds: Optional[int] = None
    if last_sync_dt is not None:
        sync_age_seconds = int(
            (datetime.now(timezone.utc) - last_sync_dt).total_seconds()
        )

    if sync_age_seconds is None:
        status = "degraded"
        status_reason = "Henüz başarılı bir senkronizasyon yapılmadı."
    elif sync_age_seconds > SYNC_STALENESS_THRESHOLD:
        status = "degraded"
        status_reason = (
            f"Son senkronizasyonun üzerinden {sync_age_seconds // 3600} saat geçti "
            f"(eşik: {SYNC_STALENESS_THRESHOLD // 3600} saat)."
        )
    elif not (scheduler and scheduler.running):
        status = "degraded"
        status_reason = "Zamanlayıcı çalışmıyor."
    else:
        status = "healthy"
        status_reason = None

    return {
        "status": status,
        "status_reason": status_reason,
        "service": "USOMListService",
        "uptime_seconds": uptime_seconds,
        "metrics": {
            "total_malicious_ips": ip_count,
            "total_malicious_domains": domain_count,
            "total_malicious_hashes": hash_count,
            # Gönderim kuyruğu — pano ilerleme çubukları bu alanları okur.
            # Bloke göstergeler bekleyenden DÜŞÜLÜR: kuyrukta değiller,
            # tekrar denenmeyecekler. Aksi hâlde pano kalıcı olarak
            # boşalmayan bir kuyruk gösterir ve "bekleyen" sayısı hiçbir
            # zaman sıfırlanmaz.
            "pending_ips": max(0, ip_count - pushed_ips - blocked_ips),
            "pending_domains": max(0, domain_count - pushed_domains - blocked_domains),
            "pending_hashes": max(0, hash_count - pushed_hashes - blocked_hashes),
            # Kalıcı olarak gönderilemeyenler — sebepleri /stats'ta
            "blocked_ips": blocked_ips,
            "blocked_domains": blocked_domains,
            "blocked_hashes": blocked_hashes,
            # last_sync_timestamp  → en son YENİ kayıt eklendiği an (veri tazeliği)
            # last_successful_sync → en son sync'in BAŞARIYLA bittiği an (servis sağlığı)
            # sync_age_seconds     → last_successful_sync üzerinden geçen süre
            "last_sync_timestamp": format_ts(last_updated),
            "last_successful_sync": format_ts(last_sync_ok),
            "sync_age_seconds": sync_age_seconds,
            "next_sync_timestamp": format_ts(next_sync_time),
            "scheduler_active": scheduler.running if scheduler else False,
        },
        "crowdstrike": {
            "enabled": cs_service.enabled,
            # Gönderim ayrıca kapatılmış olabilir; "bağlı ama basmıyor"
            # durumu yalnızca buradan görülür.
            "push_enabled": cs_service.push_enabled,
            # Saklama politikası: panonun ve operatörün "neden siliniyor"
            # sorusuna bakacağı tek yer.
            "retention_days": dict(sorted(RETENTION_DAYS.items())),
            "retention_cap": RETENTION_MAX_PER_RUN,
            "connection_status": cs_service.connection_status,
            "network_action": cs_service.network_action,   # domain + ipv4
            "hash_action": cs_service.hash_action,         # sha256
            "total_pushed_session": cs_service.total_pushed_session,
            "total_pushed_all_time": pushed_ips,
            "total_pushed_domain_all_time": pushed_domains,
            "total_pushed_hash_all_time": pushed_hashes,
            "last_pushed_timestamp": format_ts(cs_service.last_push_time),
            "next_push_timestamp": format_ts(next_sync_time),
        },
        "timestamp": format_ts(datetime.now(timezone.utc)),
    }


@app.post(
    "/sync/full",
    summary="Manuel Tam Senkronizasyon",
    description="Tüm USOM verilerini baştan sona tekrar çeker.",
    tags=["Administration"],
)
async def trigger_full_sync():
    """
    Manuel olarak tam senkronizasyon başlatır.

    ⚠ Bu işlem uzun sürebilir (~709 sayfa). Arka planda çalışır,
    endpoint hemen yanıt döner.
    """
    asyncio.create_task(sync_service.full_sync())
    return {"message": "Tam senkronizasyon arka planda başlatıldı."}


@app.post(
    "/sync/delta",
    summary="Manuel Delta Senkronizasyon",
    description="Sadece yeni eklenen IP'leri çeker.",
    tags=["Administration"],
)
async def trigger_delta_sync():
    """Manuel olarak delta senkronizasyon başlatır."""
    asyncio.create_task(sync_service.delta_sync())
    return {"message": "Delta senkronizasyon arka planda başlatıldı."}


@app.post(
    "/sync/crowdstrike/push-all",
    summary="CrowdStrike Toplu Gönderim",
    description="Veritabanında CrowdStrike'a henüz gönderilmemiş tüm IP ve Domainleri toplu olarak gönderir.",
    tags=["Administration"],
)
async def crowdstrike_push_all():
    """CrowdStrike'a gönderilmemiş tüm IP ve Domainleri toplu gönderir (arka planda çalışır)."""
    if not cs_service.enabled:
        return {"status": "error", "message": "CrowdStrike entegrasyonu aktif değil (.env eksik)."}

    unpushed_ips = len(await db.get_unpushed_ips())
    unpushed_domains = len(await db.get_unpushed_domains())
    unpushed_hashes = len(await db.get_unpushed_hashes())

    if unpushed_ips == 0 and unpushed_domains == 0 and unpushed_hashes == 0:
        return {"status": "info", "message": "Gönderilecek yeni veri yok, tümü güncel."}

    async def _push_all():
        await cs_service.sync_all_unpushed(db)
        await cs_service.sync_all_unpushed_domains(db)
        await cs_service.sync_all_unpushed_hashes(db)

    asyncio.create_task(_push_all())
    return {
        "status": "started",
        "message": (
            f"{unpushed_ips} IP, {unpushed_domains} Domain ve {unpushed_hashes} Hash "
            f"CrowdStrike'a arka planda gönderilmeye başlandı. "
            f"/health üzerinden takip edebilirsiniz."
        ),
    }


@app.post(
    "/sync/hashes",
    summary="Manuel Hash Senkronizasyonu",
    description="MalwareBazaar'dan güncel zararlı yazılım hash'lerini çeker ve CrowdStrike'a basar.",
    tags=["Administration"],
)
async def trigger_hash_sync():
    """Manuel olarak hash senkronizasyonu başlatır."""
    asyncio.create_task(sync_service.hash_sync())
    return {"message": "Hash senkronizasyonu arka planda başlatıldı."}


@app.post(
    "/sync/brandefense",
    summary="Manuel Brandefense Senkronizasyonu",
    description=(
        "Brandefense Threat Intelligence'tan alan adı ve IPv4 göstergelerini "
        "çeker, veritabanında olmayanları ekleyip CrowdStrike'a basar. "
        "period: 24h (varsayılan) veya 7d."
    ),
    tags=["Administration"],
)
async def trigger_brandefense_sync(
    period: str = Query(
        BRANDEFENSE_PERIOD,
        pattern="^(24h|7d)$",
        description="Çekilecek pencere: 24h veya 7d",
    ),
):
    """
    Manuel Brandefense senkronizasyonu.

    İlk kurulumda 7d ile çalıştırılıp arşiv doldurulabilir; sonrasında
    saatlik görev 24h penceresiyle devam eder.
    """
    if not bd_client.enabled:
        return {
            "message": "Brandefense entegrasyonu kapalı — "
                       "BRANDEFENSE_API_KEY tanımlı değil.",
        }
    asyncio.create_task(sync_service.brandefense_sync(period))
    return {
        "message": f"Brandefense senkronizasyonu arka planda başlatıldı "
                   f"(period={period}).",
    }


@app.post(
    "/sync/retry-blocked",
    summary="Bloke Göstergeleri Yeniden Dene",
    description=(
        "Kalıcı olarak gönderilemez işaretlenmiş göstergelerin blokesini "
        "kaldırır ve yeniden gönderim kuyruğuna alır. ignore_warnings=true "
        "verilirse CrowdStrike'ın 'yaygın uygulama olabilir' uyarıları "
        "görmezden gelinir — DİKKAT: hash aksiyonu prevent olduğunda bu, "
        "meşru bir sistem ikilisinin kurum genelinde engellenmesine yol "
        "açabilir."
    ),
    tags=["Administration"],
)
async def retry_blocked(
    ignore_warnings: bool = Query(
        False,
        description="CrowdStrike uyarılarını görmezden gel (bilinçli karar)",
    ),
):
    """
    Bloke göstergeleri yeniden kuyruğa alır.

    Neden ayrı bir uç: bloke bir gösterge kendi kendine kuyruğa dönmez,
    dönerse sonsuz yeniden deneme döngüsü geri gelir. Yeniden denemek
    bilinçli bir karar olmalı — operatör /stats'taki bloke listesine
    bakıp neyi neden yeniden denediğini bilerek tetikler.

    ignore_warnings bir zamanlanmış görevde ASLA True olmaz; yalnızca
    burada, çağrı başına verilir. Böylece "bir kez şu göstergeyi zorla
    gönder" kararı, kalıcı bir yapılandırmaya dönüşmez.
    """
    if not cs_service.enabled:
        return {"message": "CrowdStrike entegrasyonu kapalı — işlem yapılmadı."}

    counts = await db.unblock_all()
    if not counts.get("total"):
        return {"message": "Bloke gösterge yok.", "unblocked": counts}

    if ignore_warnings:
        logger.warning(
            "BLOKE YENİDEN DENEME: %d gösterge, CrowdStrike uyarıları "
            "GÖRMEZDEN GELİNEREK gönderilecek (aksiyon: hash=%s, ağ=%s).",
            counts["total"], cs_service.hash_action, cs_service.network_action,
        )

    async def _retry():
        await cs_service.sync_all_unpushed(db, ignore_warnings=ignore_warnings)
        await cs_service.sync_all_unpushed_domains(db, ignore_warnings=ignore_warnings)
        await cs_service.sync_all_unpushed_hashes(db, ignore_warnings=ignore_warnings)

    asyncio.create_task(_retry())
    return {
        "message": "Blokeler kaldırıldı, yeniden gönderim arka planda başlatıldı.",
        "unblocked": counts,
        "ignore_warnings": ignore_warnings,
    }


@app.delete(
    "/indicators",
    summary="Gösterge Sil",
    description=(
        "Tek bir göstergeyi CrowdStrike IOC veritabanından ve yerel "
        "veritabanından siler, ardından kalıcı dışlama listesine yazar. "
        "Dışlama olmadan silme kalıcı olmaz: USOM göstergeyi yayınlamaya "
        "devam ettiği için bir sonraki delta sync onu geri ekler."
    ),
    tags=["Administration"],
)
async def delete_indicator(
    value: str = Query(
        ..., min_length=1, max_length=LOOKUP_MAX_LENGTH,
        description="Silinecek IP, alan adı, sha256 veya md5 değeri",
    ),
    indicator_type: str = Query(
        "auto", alias="type", pattern="^(auto|ip|domain|hash)$",
        description="auto | ip | domain | hash — auto, değerin bulunduğu tüm tipleri siler",
    ),
):
    """
    Operatör silmesi.

    Sıra önemli: önce yerel veritabanı, sonra CrowdStrike. Yerel silme
    her koşulda tutar ve göstergeyi beslemelerden (/usom-ips vb.) derhal
    düşürür. CrowdStrike çağrısı ağ hatasıyla başarısız olabilir; bu
    durumda dışlama yine kalıcıdır, yalnızca cs_status='failed' kalır ve
    yanıtta bildirilir — operatör neyin eksik kaldığını görür.
    """
    value = value.strip()
    if not value:
        raise HTTPException(status_code=400, detail="Boş değer silinemez.")

    # Hangi (tip, değer) çiftlerinin silineceğini belirle. Değer de çifte
    # dahil: CrowdStrike'taki kayıt aranandan farklı yazılmış olabilir
    # ('kisa.link' sorgusu 'www.kisa.link' kaydını bulur) ve silme çağrısı
    # oradaki BİREBİR değerle yapılmazsa hiçbir şey silinmez.
    if indicator_type == "auto":
        found = await db.lookup_indicator(value)
        targets = sorted({(m["type"], m["value"]) for m in found.get("matches", [])})

        if not targets:
            # Yerelde yok — ama CrowdStrike'ta durup engelliyor olabilir.
            # Eski URL yolundan kalan göstergeler tam olarak bu durumda:
            # yerel kaydı yok, CrowdStrike kaydı var. Burada durmak,
            # operatöre silemeyeceği bir gösterge bırakmak demek.
            for kind, probe in cs_probe_targets(value):
                for hit in await cs_service.find_indicator(kind, probe):
                    if hit.get("value"):
                        targets.append((kind, hit["value"]))
            targets = sorted(set(targets))

        if not targets:
            # Kayıt yok ama operatör yine de dışlamak isteyebilir
            # (henüz senkronize edilmemiş bir göstergeyi önden engellemek).
            # Tipi tahmin etmek yerine açıkça sorulur.
            raise HTTPException(
                status_code=404,
                detail=(
                    f"'{value}' ne veritabanında ne de CrowdStrike'ta bulundu. "
                    f"Henüz eklenmemiş bir göstergeyi önden engellemek için "
                    f"type parametresini açıkça verin (ip | domain | hash)."
                ),
            )
    else:
        targets = [(indicator_type, value)]

    results = []
    for kind, target in targets:
        local = await db.delete_indicator(kind, target, note="dashboard")
        cs = await cs_service.delete_indicator(kind, target)
        await db.mark_cs_result(kind, target, cs["status"], cs["detail"])
        logger.warning(
            "GÖSTERGE SİLİNDİ: %s '%s' | yerel satır: %d | CrowdStrike: %s (%s)",
            kind, target, local["removed"], cs["status"], cs["detail"],
        )
        results.append({
            "type": kind,
            "value": target,
            "db_removed": local["removed"],
            "excluded_values": local["excluded_values"],
            "crowdstrike_ok": cs["ok"],
            "crowdstrike_status": cs["status"],
            "crowdstrike_deleted": cs["deleted"],
            "crowdstrike_detail": cs["detail"],
        })

    failed = [r for r in results if not r["crowdstrike_ok"]]
    return {
        "value": value,
        "deleted": results,
        "message": (
            "Yerel silme tamamlandı, ancak gösterge CrowdStrike'ta DURUYOR "
            "ve engellenmeye devam ediyor — crowdstrike_detail alanına bakın."
            if failed else
            "Gösterge silindi ve kalıcı dışlama listesine alındı."
        ),
    }


@app.get(
    "/retention/preview",
    summary="Saklama Önizleme",
    description=(
        "Hiçbir şey silmeden, saklama politikası şu an uygulansa hangi "
        "kaynaktan kaç göstergenin temizleneceğini döndürür."
    ),
    tags=["Administration"],
)
async def retention_preview():
    """
    Kuru çalıştırma.

    Saklama temizliği CrowdStrike'tan koruma kaldırıyor; rakamı görmeden
    tetiklemek doğru değil. Bu uç hiçbir yan etki üretmez.
    """
    preview = await db.retention_preview()
    return {
        **preview,
        "note": (
            "Bu uç yalnızca sayar. Temizlik için POST /retention/run "
            "kullanın. TTL'i 0 olan kaynaklar (süresiz) hiç işlenmez."
        ),
    }


@app.post(
    "/retention/run",
    summary="Saklama Temizliğini Çalıştır",
    description=(
        "Saklama süresi dolmuş göstergeleri CrowdStrike'tan ve veritabanından "
        "kaldırır. dry_run=true verilirse hiçbir şey silinmez, yalnızca ne "
        "yapılacağı döner."
    ),
    tags=["Administration"],
)
async def trigger_retention(
    dry_run: bool = Query(
        True,
        description="Varsayılan TRUE — silmek için açıkça false verilmeli",
    ),
    limit: int = Query(
        0, ge=0,
        description="Bu turda işlenecek azami gösterge (0 = yapılandırılmış üst sınır)",
    ),
):
    """
    Saklama temizliğini elle tetikler.

    dry_run varsayılanı bilinçli olarak TRUE: bu uç CrowdStrike'tan
    koruma kaldırıyor ve kimlik doğrulaması yok. Yanlışlıkla atılan bir
    POST'un on binlerce göstergeyi silmesi kabul edilemez, bu yüzden
    silme açık bir `dry_run=false` gerektirir.

    Kuru çalıştırma anında döner; gerçek tur arka planda çalışır çünkü
    yüz binlik temizlik dakikalar sürebilir.
    """
    if dry_run:
        return await sync_service.retention_sync(dry_run=True, limit=limit or None)

    if not cs_service.enabled:
        return {
            "message": (
                "CrowdStrike entegrasyonu kapalı — temizlik yalnızca yerel "
                "veritabanında etkili olurdu ve göstergeler CrowdStrike'ta "
                "kalırdı. İşlem yapılmadı."
            ),
        }

    preview = await db.retention_preview()
    asyncio.create_task(sync_service.retention_sync(limit=limit or None))
    return {
        "message": "Saklama temizliği arka planda başlatıldı.",
        "candidates": preview["total"],
        "cap": limit or RETENTION_MAX_PER_RUN,
        "note": "İlerleme için logları veya /stats güvenilirlik bölümünü izleyin.",
    }


@app.get(
    "/indicators/deleted",
    summary="Silinmiş Göstergeler",
    description="Operatör tarafından silinip kalıcı olarak dışlanmış göstergeleri listeler.",
    tags=["Administration"],
)
async def list_deleted_indicators(
    limit: int = Query(100, ge=1, le=1000),
):
    """Dışlama listesi — 'bu adres neden beslemede yok' sorusunun cevabı."""
    items = await db.list_deletions(limit)
    return {"count": len(items), "items": items}


@app.post(
    "/indicators/restore",
    summary="Silinmiş Göstergeyi Geri Al",
    description=(
        "Dışlamayı kaldırır. Gösterge satırı burada yeniden yazılmaz; "
        "kaynak onu hâlâ yayınlıyorsa bir sonraki sync normal yoluyla geri getirir."
    ),
    tags=["Administration"],
)
async def restore_indicator(
    value: str = Query(..., min_length=1, max_length=LOOKUP_MAX_LENGTH),
    indicator_type: str = Query(..., alias="type", pattern="^(ip|domain|hash)$"),
):
    """
    Yanlışlıkla silinen bir göstergeyi geri almanın tek yolu.

    Silme yıkıcı bir işlem: yanlış yazılmış tek bir değer zararlı bir
    adresin kurum genelinde engellenmemesi demek. Geri alma olmadan bu
    hatanın telafisi veritabanını elle düzenlemekten geçerdi.
    """
    removed = await db.restore_indicator(indicator_type, value.strip())
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"'{value}' dışlama listesinde ({indicator_type}) bulunamadı.",
        )
    logger.warning("DIŞLAMA KALDIRILDI: %s '%s'", indicator_type, value)
    return {
        "value": value,
        "type": indicator_type,
        "message": (
            "Dışlama kaldırıldı. Gösterge kaynakta hâlâ varsa bir sonraki "
            "senkronizasyonda geri gelecek ve CrowdStrike'a yeniden gönderilecek."
        ),
    }


# ─────────────────────────────────────────────────────
# 8. UYGULAMA GİRİŞ NOKTASI
# ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
        access_log=True,
    )
