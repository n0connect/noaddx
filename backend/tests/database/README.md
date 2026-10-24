# Database Migration Tests

## Amac

Bu testler **backend ayaga kalkmadan once** calistirilmalidir. Amaclari:

1. [x] Database baglantisinin dogru calistigini dogrulamak
2. [x] Migration'larin basariyla calistigini test etmek
3. [x] Database schema'sinin dogru olusturuldugunu dogrulamak
4. [x] Index'lerin ve constraint'lerin dogru ayarlandigini test etmek
5. [x] Database'in backend baslamadan once hazir oldugunu garantilemek

## Kullanim

### Test Database Setup

Testler otomatik olarak test database'ine baglanir. Environment variables:

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=postgres
export DB_PASSWORD=postgres
export DB_NAME=noaddress_test
export DB_SSL_MODE=disable
```

### Test Calistirma

```bash
# Tum migration testleri
cd backend
go test -tags=test ./tests/database -v

# Sadece migration testi
go test -tags=test ./tests/database -v -run TestDatabaseMigration

# Schema testleri
go test -tags=test ./tests/database -v -run TestUserTableSchema
go test -tags=test ./tests/database -v -run TestChatTableSchema

# Connection testi
go test -tags=test ./tests/database -v -run TestDatabaseConnection
```

### Backend Baslatmadan Once

```bash
# 1. Migration testlerini calistir
go test -tags=test ./tests/database -v

# 2. Testler basariliysa backend'i baslat
go run ./cmd/server
```

## Test Kategorileri

### 1. Migration Tests

- `TestDatabaseMigration`: Migration'larin basariyla calistigini test eder
- `TestDatabaseConnection`: Database baglantisini test eder
- `TestDatabaseMasterKey`: Master key'in initialize edildigini test eder

### 2. Schema Tests

- `TestUserTableSchema`: User tablosunun dogru schema'ya sahip oldugunu test eder
- `TestChatTableSchema`: Mesajlasma tablolarinin dogru schema'ya sahip oldugunu ve kullaniciya baglanabilecek kolon icermedigini test eder

### 3. Constraint Tests

- `TestUserTableIndexes`: User tablosundaki index'leri test eder
- `TestDatabaseConstraints`: NOT NULL constraint'lerini test eder

## Onemli Notlar

1. **Test Database**: Testler `noaddress_test` database'ini kullanir (production database'i degil)
2. **Migration**: `database.Init()` cagrildiginda migration'lar otomatik calisir
3. **Clean State**: Her test oncesi database temizlenmez (manuel cleanup gerekebilir)
4. **Production**: Production'da bu testler calistirilmamali

## Test Infrastructure

Testler `tests/testutil/db.go` icindeki utility fonksiyonlarini kullanir:

- `InitializeTestDatabase()`: Gercek `database.Init()` ile baglanir ve migration'lari calistirir
- `CleanupTestData()`: Test sonrasi tum tablolari bosaltir
- `InitializeTestDatabase()`: Global database connection'i initialize eder

---

**Son Guncelleme:** Ekim 2026
