# Test Suite

> **Yalnizca gercek sistem.** Hicbir seyin yerine gecen kod, veri ya da akis yoktur. Testler gercek
> HTTP rotalarini, gercek PostgreSQL'i, gercek kriptoyu (gercek ciphertext) ve her calistirmada
> CSPRNG'den uretilen secret'lari kullanir. Gecersiz girdiler, gercek bir ciktinin bozulmasiyla
> elde edilir. Sabit girdiler yalnizca yayinlanmis RFC vektorleri ve Go-JS uyum vektorleridir.

## Dizin Yapisi

```
backend/tests/
|-- auth/                      # Authentication tests (22 test)
|-- database/                  # Migration tests (10 test)
|-- encryption/                # Encryption tests (11 test)
|-- identity/                  # HKDF / X25519 RFC vectors + derivations + tag separation (5 test)
|-- integration/               # noaddx end-to-end flows, real E2E ciphertext (23 test)
|-- middleware/                # Middleware tests (21 test)
|-- testutil/                  # Test utilities
|   |-- db.go                  # Database setup helpers
|   |-- db_helper.go           # Database env setup
|   |-- env.go                 # Environment setup (secrets drawn from the CSPRNG per run)
|   `-- values.go              # Real generators: AccountNumber, auth key, ids
`-- utils/                     # Utils, SafeMutex, supervised goroutines, logger (22 test)
```

Paket ici testler: `internal/pow` (13, gercek cozum/gercek sure dolumu, bosta kalan istemcinin unutulmasi), `internal/realtime` (3, SSE hub), `internal/handlers` (2, rota/sorgu beyaz listesi), `internal/e2e` (6, Go istemci protokolu + tarayici ciphertext'i + bes padding boyutu).
Frontend testleri: `frontend/tests/` (crypto.test.mjs 10, validation.test.mjs 2, pow-worker.test.mjs 3) -> `node --test frontend/tests/*.test.mjs`
Kripto motoru: `internal/cryptoengine` (10, bilinen-cevap vektorleri, secili motorda), `internal/cryptoengine/equivalence` (9, iki motoru ayni binary'de karsilastirir; `-tags openssl` ile).
Fuzz hedefleri: `internal/e2e`, `internal/pow`, `tests/auth`, `tests/utils` (`go test -tags test -run '^$' -fuzz '^FuzzX$' -fuzztime 30s <paket>`).

## Test Calistirma Sirasi

### ONEMLI: Migration Testleri Once Calistirilmalidir

Migration testleri **backend ayaga kalkmadan once** calistirilmalidir:

```bash
# 1. Migration testleri (database hazirligi)
cd backend
go test -tags=test ./tests/database -v

# 2. Testler basariliysa backend'i baslat
go run ./cmd/server
```

### Tum Testler

```bash
# Migration testleri (oncelikli)
go test -tags=test ./tests/database -v

# Diger testler
go test -p 1 -tags=test ./tests/... -v
```

### Kategori Bazli

```bash
# Migration tests (database hazirligi)
go test -tags=test ./tests/database -v

# Authentication tests
go test -tags=test ./tests/auth -v

# Encryption tests
go test -tags=test ./tests/encryption -v

# Middleware tests
go test -tags=test ./tests/middleware -v

# Integration tests
go test -tags=test ./tests/integration -v

# Identity derivation tests (no DB)
go test -tags=test ./tests/identity -v

# Utils tests
go test -tags=test ./tests/utils -v
```

## Test Istatistikleri

| Kategori | Test Sayisi | Durum |
|---|---|---|
| **Database Migration** | **10** | Gecti |
| Authentication | 22 | Gecti |
| Encryption | 11 | Gecti |
| Middleware | 21 | Gecti |
| Identity | 5 | Gecti |
| Integration (noaddx flows) | 23 | Gecti |
| Utils | 22 | Gecti |
| **TOPLAM (tests/)** | **114** | Gecti |

## Migration Testleri

### Amac

Migration testleri backend baslamadan once:
1. [x] Database baglantisini test eder
2. [x] Migration'larin basariyla calistigini dogrular
3. [x] Database schema'sinin dogru olusturuldugunu test eder
4. [x] Index'lerin ve constraint'lerin dogru ayarlandigini dogrular
5. [x] **Database'in backend baslamadan once hazir oldugunu garantiler**

### Testler

- `TestDatabaseMigration`: Migration'larin calistigini test eder
- `TestUserTableSchema`: User tablosu schema'sini test eder
- `TestChatTableSchema`: Mesajlasma tablolarini ve yasak kolonlari (user_uuid, created_at) test eder
- `TestUserTableIndexes`: Index'leri test eder
- `TestDatabaseConstraints`: Constraint'leri test eder
- `TestDatabaseConnection`: Baglantiyi test eder
- `TestDatabaseMasterKey`: Master key'i test eder

### Detayli Bilgi

Bkz: `tests/database/README.md` ve `tests/MIGRATION_TEST_GUIDE.md`

## Test Kategorileri

### 1. Unit Tests

**Lokasyon:** `tests/auth/`, `tests/encryption/`, `tests/utils/`, `tests/identity/`

**Ozellikler:**
- Hizli calisir
- Database gerektirmez (cogu)
- Izole edilmis testler

### 2. Migration Tests

**Lokasyon:** `tests/database/`

**Ozellikler:**
- Database gerektirir
- Backend baslamadan once calistirilmalidir
- Database'in hazir oldugunu garantiler

### 3. Middleware Tests

**Lokasyon:** `tests/middleware/`

**Testler:**
- JWT authentication
- Rate limiting (IPv6 /64 gruplama; Tor devreleri ayri anahtar alir)
- Guvenilir proxy (X-Forwarded-For sagdan okunur)
- CORS policy
- Security headers

### 4. Integration Tests

**Lokasyon:** `tests/integration/`

**Testler:** gercek route tablosu (`internal/server`) uzerinden
- Kayit (PoW dahil) -> turetilmis anahtarla giris; ham AccountNumber kabul edilmez
- PoW atlatma regresyonlari (difficulty=0, trailing JSON)
- Davet -> eslesme -> mesaj; tek kullanimlik davet, kendi davetini kullanamama
- Uye olmayan erisimi (IDOR), girdi beyaz listesi, burn, oturum iptali, davet limiti
- SSE: mesajda durtme, logout'ta akisin kapanmasi
- DB'de sosyal graf ve sekli sizmamasi (konusma basina takma ad, padding'li sifreli liste, konusma basina seq)
- Saklama suresi (gun hassasiyetli silinme, purge), dolu kullanicida davetin geri alinmasi, burn sonrasi liste temizligi
- Davet basina PoW (eksik govde 415, eksik cozum 412, zayif/tekrar cozum 403; reddedilen istek davet olusturmaz)
- Kimlik silme: hesap numarasi yeniden kanitlanir, yanlis anahtar islemi geri alir (davetler kalir), iki taraf icin konusmalar silinir, karsi taraf SSE ile haberdar olur
- CSRF: capraz-koken yazmalar reddedilir; reddedilen istek PoW'u tuketmez

**Not:** PostgreSQL erisilemezse paket FAIL verir (TestMain) - hicbir test calismadan "gecti" denmez. Lokal ornek:
`DB_HOST=127.0.0.1 DB_PORT=5432 go test -p 1 -tags=test ./tests/... -v` (`-p 1`: DB paketleri ayni veritabanini paylasir)

## Test Infrastructure

### Test Environment Setup

`tests/testutil/env.go`:
- `SetupTestEnv()`: Test environment variables
- `TeardownTestEnv()`: Cleanup

### Database Setup

`tests/testutil/db.go`:
- `InitializeTestDatabase()`: Global database init

`tests/testutil/db_helper.go`:
- `SetupTestDatabaseEnv()`: Database environment variables

## Notlar

### Database Bagimliligi

Bazi testler database baglantisi gerektirir:
- Migration tests: Database gerektirir
- Integration tests: Database gerektirir
- JWT middleware test: Database gerektirir

### Environment Variables

Testler icin gerekli environment variables:
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSL_MODE`
- `JWT_SECRET`, `JWT_SECRET_MIN_LEN`, `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_EXPIRATION_MINUTES`
- `MASTER_KEY_ACTIVE`, `MASTER_KEY_ACTIVE_ID`, `MASTER_KEY_OLD`, `ACCOUNT_LOOKUP_PEPPER`
- `ALLOWED_ORIGINS`, `BACKEND_PORT`, `APP_ENV`, `LOG_LEVEL`
- `MAX_REQUEST_BODY_BYTES`, `MAX_JSON_DEPTH`, `POW_DIFFICULTY`
- `INVITE_TTL_SEC`, `MAX_ACTIVE_INVITES`, `MAX_CONVERSATIONS_PER_USER`, `MAX_MESSAGE_BYTES`, `MESSAGE_PAGE_LIMIT`
- `ARGON2_MEMORY_KIB`, `ARGON2_TIME`, `ARGON2_PARALLELISM`, `ARGON2_SALT_LENGTH`, `ARGON2_HASH_LENGTH`
- `PENDING_TOKEN_TTL_SEC`, `PENDING_CLEANUP_INTERVAL_SEC`, `PENDING_ID_BYTES`, `INTERNAL_ID_LENGTH`
- `RATE_LIMIT_MAX_TOKENS`, `RATE_LIMIT_REFILL_INTERVAL_SEC`, `RATE_LIMIT_CLEANUP_INTERVAL_SEC`, `RATE_LIMIT_MAX_BUCKETS`
- `SERVER_READ_HEADER_TIMEOUT_SEC`, `SERVER_READ_TIMEOUT_SEC`, `SERVER_WRITE_TIMEOUT_SEC`, `SERVER_IDLE_TIMEOUT_SEC`, `SERVER_MAX_HEADER_BYTES`

## Dokumantasyon

- `tests/README.md`: Bu dosya
- `tests/database/README.md`: Migration testleri detaylari

---

**Son Guncelleme:** Ekim 2026
