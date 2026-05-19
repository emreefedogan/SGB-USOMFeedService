"""
USOM Zararlı IP Listesi Servisi (USOMListService)
===================================================

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
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os
import time
from typing import Optional
from urllib.parse import urlparse

from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

import aiosqlite
import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
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
PAGE_SIZE = 20                    # USOM API sayfada dönen kayıt sayısı
MAX_CONCURRENT_REQUESTS = 3       # API'ye eşzamanlı istek limiti (rate-limit koruması)
HTTP_TIMEOUT = 30.0               # Her bir HTTP isteği için zaman aşımı (saniye)
MAX_RETRY_ATTEMPTS = 5            # Başarısız istekler için yeniden deneme sayısı
DELTA_SYNC_MAX_PAGES = 10         # Saatlik delta sync'te taranacak maks. sayfa sayısı
APP_START_TIME = time.time()      # Uptime hesabı için başlangıç zamanı

# CrowdStrike'a basılmayacak olan global/güvenilir domainler (false-positive engelleme)
WHITELISTED_DOMAINS = {
    "t.co", "facebook.com", "instagram.com", "meta.com", "twitter.com", "x.com",
    "youtube.com", "youtu.be", "google.com", "github.com", "linkedin.com",
    "whatsapp.com", "telegram.org", "discord.com", "apple.com", "microsoft.com",
    "drive.google.com", "docs.google.com", "dropbox.com", "onedrive.live.com",
    "wordpress.com", "blogspot.com", "medium.com", "tumblr.com"
}
# ─────────────────────────────────────────────
# Loglama Konfigürasyonu
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("USOMListService")


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

    async def close(self) -> None:
        """Veritabanı bağlantısını kapat."""
        if self._db:
            await self._db.close()
            logger.info("Veritabanı bağlantısı kapatıldı.")

    async def insert_ips(self, ip_list: list[str]) -> int:
        """
        IP listesini toplu olarak veritabanına ekler.

        INSERT OR IGNORE sayesinde zaten var olan IP'ler sessizce atlanır,
        böylece duplicate oluşmaz.

        Args:
            ip_list: Eklenecek IP adresleri listesi.

        Returns:
            Yeni eklenen IP adres sayısı.
        """
        if not ip_list:
            return 0

        if self._db is None:
            raise RuntimeError("Veritabanı bağlantısı henüz kurulmadı.")

        now = datetime.now(timezone.utc).isoformat()
        data = [(ip, now) for ip in ip_list]

        async with self._db.execute("SELECT COUNT(*) FROM malicious_ips") as cur:
            row = await cur.fetchone()
            before_count = row[0] if row else 0

        await self._db.executemany(
            "INSERT OR IGNORE INTO malicious_ips (ip, added_at) VALUES (?, ?)",
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
            "SELECT ip FROM malicious_ips WHERE pushed_to_cs = 0 ORDER BY added_at"
        ) as cur:
            rows = await cur.fetchall()
        return [row[0] for row in rows]

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
    async def insert_domains(self, domain_list: list[str]) -> int:
        """Domain listesini toplu olarak veritabanına ekler."""
        if not domain_list or self._db is None:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        data = [(d, now) for d in domain_list]
        async with self._db.execute("SELECT COUNT(*) FROM malicious_domains") as cur:
            before = (await cur.fetchone())[0]
        await self._db.executemany("INSERT OR IGNORE INTO malicious_domains (domain, added_at) VALUES (?, ?)", data)
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
            "SELECT domain FROM malicious_domains WHERE pushed_to_cs = 0 ORDER BY added_at"
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
                if not is_whitelisted:
                    domains.append(domain)
        return domains


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
        self.action = os.getenv("FALCON_IOC_ACTION", "prevent")
        self.enabled = bool(self.client_id and self.client_secret)
        self.total_pushed_session = 0
        self.connection_status = "uninitialized"
        self._ioc_client = None
        self.last_push_time: Optional[datetime] = None

        if self.enabled:
            try:
                # falconpy kütüphanesini içe aktar
                from falconpy import IOC
                self._ioc_client = IOC(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    base_url=self.base_url
                )
                self.connection_status = "connected"
                logger.info("CrowdStrike entegrasyonu aktif (Action: %s).", self.action)
            except Exception as e:
                self.enabled = False
                self.connection_status = f"error: {str(e)}"
                logger.error("CrowdStrike başlatılamadı: %s", e)
        else:
            self.connection_status = "disabled (no credentials)"
            logger.info("CrowdStrike entegrasyonu kapalı (.env eksik).")

    async def push_ips(self, ip_list: list[str]) -> tuple[int, list[str]]:
        """
        IP listesini CrowdStrike'a batch'ler (200'lük) halinde gönderir.
        
        Returns:
            (pushed_count, pushed_ips): Başarıyla gönderilen sayı ve IP listesi.
        """
        if not self.enabled or not self._ioc_client or not ip_list:
            return 0, []

        pushed_count = 0
        pushed_ips = []
        batch_size = 200
        
        # CPU'yu kitlememek için asenkron içinde senkron kodu çalıştırıyoruz
        def _push_batch(batch):
            indicators = []
            for ip in batch:
                indicators.append({
                    "type": "ipv4",
                    "value": ip,
                    "action": "detect",
                    "severity": "high",
                    "source": "USOMListService",
                    "description": "USOM Malicious IP Intelligence",
                    "platforms": ["windows", "mac", "linux"],
                    "applied_globally": True
                })
            return self._ioc_client.indicator_create(body={"indicators": indicators})

        for i in range(0, len(ip_list), batch_size):
            batch = ip_list[i:i + batch_size]
            try:
                # Bloklayıcı API çağrısını event loop'ta çalıştır
                response = await asyncio.to_thread(_push_batch, batch)
                status_code = response.get("status_code", 0)
                if status_code in [200, 201]:
                    pushed_count += len(batch)
                    pushed_ips.extend(batch)
                else:
                    logger.error("CrowdStrike batch push hatası (status %d): %s", status_code, response.get("body", {}).get("errors", []))
            except Exception as e:
                logger.error("CrowdStrike API Exception: %s", e)
                
            await asyncio.sleep(0.5) # Rate limit koruması

        self.total_pushed_session += pushed_count
        if pushed_count > 0:
            self.last_push_time = datetime.now(timezone.utc)
        logger.info("CrowdStrike push tamamlandı: %d/%d IP başarıyla gönderildi.", pushed_count, len(ip_list))
        return pushed_count, pushed_ips

    async def sync_all_unpushed(self, db_instance) -> int:
        """
        Veritabanındaki CrowdStrike'a henüz gönderilmemiş tüm IP'leri toplu olarak gönderir.
        Başarıyla gönderilenleri veritabanında pushed_to_cs=1 olarak işaretler.
        """
        if not self.enabled:
            return 0

        unpushed = await db_instance.get_unpushed_ips()
        if not unpushed:
            logger.info("CrowdStrike: Gönderilecek yeni IP yok, tümü güncel.")
            return 0

        logger.info("CrowdStrike: %d adet gönderilmemiş IP tespit edildi, başlatılıyor...", len(unpushed))
        pushed_count, pushed_ips = await self.push_ips(unpushed)
        
        if pushed_ips:
            await db_instance.mark_ips_pushed(pushed_ips)
            logger.info("CrowdStrike: %d IP başarıyla gönderildi ve veritabanında işaretlendi.", pushed_count)

        return pushed_count

    async def push_domains(self, domain_list: list[str]) -> tuple[int, list[str]]:
        """
        Domain listesini CrowdStrike'a type:domain olarak gönderir.
        """
        if not self.enabled or not self._ioc_client or not domain_list:
            return 0, []

        filtered_domains = []
        for domain in domain_list:
            # Başında 'www.' varsa temizle
            domain = domain.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            
            # Domain whitelist kontrolü (örn. instagram.com veya .instagram.com)
            is_whitelisted = any(
                domain == wd or domain.endswith(f".{wd}")
                for wd in WHITELISTED_DOMAINS
            )
            
            if not is_whitelisted:
                filtered_domains.append(domain)
            else:
                logger.debug("Whitelist'te olan domain atlandı: %s", domain)

        domains = list(set(filtered_domains))

        if not domains:
            return 0, []

        pushed_count = 0
        pushed_domains = []
        batch_size = 200

        def _push_domain_batch(batch):
            indicators = []
            for d in batch:
                indicators.append({
                    "type": "domain",
                    "value": d,
                    "action": "detect",
                    "severity": "high",
                    "source": "USOMListService",
                    "description": "USOM Malicious Domain Intelligence",
                    "platforms": ["windows", "mac", "linux"],
                    "applied_globally": True
                })
            return self._ioc_client.indicator_create(body={"indicators": indicators})

        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            try:
                response = await asyncio.to_thread(_push_domain_batch, batch)
                status_code = response.get("status_code", 0)
                if status_code in [200, 201]:
                    pushed_count += len(batch)
                    pushed_domains.extend(batch)
                else:
                    logger.error("CrowdStrike domain push hatası (status %d): %s", status_code, response.get("body", {}).get("errors", []))
            except Exception as e:
                logger.error("CrowdStrike Domain API Exception: %s", e)
            await asyncio.sleep(0.5)

        self.total_pushed_session += pushed_count
        if pushed_count > 0:
            self.last_push_time = datetime.now(timezone.utc)
        logger.info("CrowdStrike domain push: %d domain başarıyla gönderildi.", pushed_count)
        return pushed_count, pushed_domains

    async def sync_all_unpushed_domains(self, db_instance) -> int:
        """Gönderilmemiş domain'leri CrowdStrike'a basar."""
        if not self.enabled:
            return 0
        unpushed = await db_instance.get_unpushed_domains()
        if not unpushed:
            logger.info("CrowdStrike: Gönderilecek yeni domain yok.")
            return 0
        logger.info("CrowdStrike: %d domain gönderilecek...", len(unpushed))
        pushed_count, pushed_domains = await self.push_domains(unpushed)
        if pushed_domains:
            await db_instance.mark_domains_pushed(pushed_domains)
        return pushed_count

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

    def __init__(self, client: USOMClient, db: IPDatabase, cs: CrowdStrikeService = None):
        self.client = client
        self.db = db
        self.cs = cs
        self._sync_lock = asyncio.Lock()  # Eşzamanlı sync operasyonlarını engeller

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

            except Exception as e:
                logger.error("Tam senkronizasyon hatası: %s", e, exc_info=True)

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
                            cs_pushed, cs_pushed_ips = await self.cs.push_ips(new_ips)
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

            except Exception as e:
                logger.error("Delta sync hatası: %s", e, exc_info=True)

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
            except Exception as e:
                logger.error("Domain tam senkronizasyon hatası: %s", e, exc_info=True)

            if self.cs and self.cs.enabled:
                await self.cs.sync_all_unpushed_domains(self.db)

    async def domain_delta_sync(self) -> None:
        """Sadece yeni eklenen domainleri çeker."""
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
            except Exception as e:
                logger.error("Domain delta sync hatası: %s", e, exc_info=True)

            if self.cs and self.cs.enabled:
                await self.cs.sync_all_unpushed_domains(self.db)

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

    logger.info(
        "Zamanlayıcı yapılandırıldı: "
        "IP Delta → :05 | IP Full → Pazar 03:00 | "
        "Domain Delta → :10 | Domain Full → Pazar 04:00"
    )
    return scheduler


# ─────────────────────────────────────────────────────
# 6. FASTAPI UYGULAMA FABRİKASI
# ─────────────────────────────────────────────────────

# Servis bileşenlerini modül seviyesinde tanımla (endpoint'lerin erişebilmesi için)
db = IPDatabase()
usom_client = USOMClient()
cs_service = CrowdStrikeService()
sync_service = SyncService(client=usom_client, db=db, cs=cs_service)
scheduler: Optional[AsyncIOScheduler] = None


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

    await db.connect()
    await usom_client.start()

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

    # CrowdStrike: Veritabanında gönderilmemiş IP varsa topluca gönder
    if cs_service.enabled:
        async def _initial_cs_sync():
            await asyncio.sleep(5)  # DB sync başlayana kadar kısa bekleme
            await cs_service.sync_all_unpushed(db)
        asyncio.create_task(_initial_cs_sync())

    # Zamanlanmış görevleri başlat
    scheduler = setup_scheduler(sync_service)
    scheduler.start()
    logger.info("✅ USOMListService hazır — istekler kabul ediliyor.")

    yield  # ── Uygulama çalışıyor ──

    # ── SHUTDOWN ──
    logger.info("⏹ USOMListService kapatılıyor...")
    if scheduler:
        scheduler.shutdown(wait=False)
    await usom_client.stop()
    await db.close()
    logger.info("👋 USOMListService kapatıldı.")


# FastAPI uygulama örneği
app = FastAPI(
    title="USOM Zararlı IP Listesi Servisi",
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

    return {
        "status": "healthy",
        "service": "USOMListService",
        "uptime_seconds": uptime_seconds,
        "metrics": {
            "total_malicious_ips": ip_count,
            "total_malicious_domains": await db.get_domain_count(),
            "last_sync_timestamp": format_ts(last_updated),
            "next_sync_timestamp": format_ts(next_sync_time),
            "scheduler_active": scheduler.running if scheduler else False,
        },
        "crowdstrike": {
            "enabled": cs_service.enabled,
            "connection_status": cs_service.connection_status,
            "total_pushed_session": cs_service.total_pushed_session,
            "total_pushed_all_time": await db.get_pushed_count(),
            "total_pushed_domain_all_time": await db.get_pushed_domain_count(),
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
    
    if unpushed_ips == 0 and unpushed_domains == 0:
        return {"status": "info", "message": "Gönderilecek yeni veri yok, tümü güncel."}

    async def _push_both():
        await cs_service.sync_all_unpushed(db)
        await cs_service.sync_all_unpushed_domains(db)
        
    asyncio.create_task(_push_both())
    return {
        "status": "started",
        "message": f"{unpushed_ips} adet IP ve {unpushed_domains} adet Domain CrowdStrike'a arka planda gönderilmeye başlandı. /health üzerinden takip edebilirsiniz."
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
