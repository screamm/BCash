# 🏦 Sparappen - Barnens Sparpengar

En mobilanpassad Progressive Web App (PWA) för barn att hålla koll på sina sparpengar och för föräldrar att hantera barnens ekonomi.

## ✨ Funktioner

### För Barn

- 🔐 Säker inloggning med eget användarnamn
- 💰 Se sitt aktuella saldo
- 📋 Visa alla egna transaktioner
- 📱 Mobiloptimerad design

### För Föräldrar

- 👨‍👩‍👧‍👦 Översikt över alla barns saldo
- ➕ Lägg till pengar (veckopeng, extra belöning)
- ➖ Ta bort pengar (utgifter, köp)
- 📝 Spåra alla transaktioner med beskrivning och datum
- 🔍 Se fullständig transaktionshistorik

## 🆕 Senaste uppdateringar (v3.0)

### 🔒 **Säkerhetsförbättringar**

- 🔐 **Hashade lösenord** - SHA-256 hashing med salt
- 🛡️ **Brute force-skydd** - Kontolåsning efter 5 misslyckade försök
- 📊 **Säkerhetsloggning** - Spårning av alla inloggningsförsök
- 🚫 **SQL injection-skydd** - Prepared statements och validering

### 👶 **Barnhantering**

- ➕ **Lägg till barn** - Skapa nya barnkonton dynamiskt
- ✏️ **Redigera barn** - Ändra namn och användarnamn
- 🗑️ **Ta bort barn** - Soft delete för säker borttagning
- 👥 **Flexibel användarhantering** - Inga hårdkodade användare

### 🏥 **Självtester & Övervakning**

- 🧪 **Automatiska tester** - Komplett testsvit för alla funktioner
- 📈 **Health checks** - API-endpoint för systemstatus
- 🔍 **Detaljerad loggning** - Spårning av systemhälsa
- ⚡ **Prestanda-övervakning** - Databas och API-status

### 🛠️ **Tekniska förbättringar**

- ⬆️ **Wrangler 4.20.5** - Senaste versionen
- 🔧 **ESLint 9.29.0** - Modern kodkvalitetskontroll
- 🎨 **Favicon** - Snygg bank-ikon i browser-fliken
- 📦 **Moderna verktyg** - TypeScript, Prettier, och uppdaterade beroenden

## 🚀 Deploy till Cloudflare

### 1. Förberedelser

```bash
# Installera dependencies
npm install

# Logga in på Cloudflare (om du inte redan gjort det)
npx wrangler login
```

### 2. Skapa databas

```bash
# Skapa D1 databas
npx wrangler d1 create sparappen-db

# Kopiera database_id från output och uppdatera wrangler.toml
```

### 3. Initiera databas

```bash
# Skapa tabeller
npx wrangler d1 execute sparappen-db --file=./schema.sql

# Lägg till testdata
npx wrangler d1 execute sparappen-db --file=./seed.sql
```

### 4. Deploy appen

```bash
# Deploy till Cloudflare Workers
npx wrangler deploy
```

## 🧪 Testanvändare

Efter deployment kan du logga in med:

**Barn:**

- anna / barn123
- erik / barn123
- lila / barn123

**Förälder:**

- mamma / förälder456

> **Obs:** Lösenorden är nu säkert hashade och följer starkare säkerhetsstandarder!

## 📱 PWA Installation

Appen kan installeras som en vanlig app:

1. **Android**: Öppna i Chrome → "Lägg till på startskärmen"
2. **iOS**: Öppna i Safari → Dela → "Lägg till på hemskärmen"
3. **Desktop**: Klicka på installationsikonen i adressfältet

## 🔧 Utveckling

```bash
# Starta utvecklingsserver
npm run dev

# Formatera kod
npm run format

# Kontrollera kodkvalitet
npm run lint

# TypeScript typkontroll
npm run type-check

# Kör självtester
npm run test

# Migrera databas (schema + seed)
npm run db:migrate

# Testa databas lokalt
npx wrangler d1 execute sparappen-db --local --file=./schema.sql

# Kontrollera systemhälsa
curl http://localhost:8787/api/health
```

## 💾 Databasstruktur

### children

- id, name, username, password, balance
- Lagrar barnens konton och saldo

### parents

- id, name, username, password
- Föräldrakonton för administration

### transactions

- id, child_id, amount, description, type, created_by, created_at
- Alla pengatransaktioner med fullständig spårning

## 🔒 Säkerhet

- ✅ CORS-skydd aktiverat
- ✅ Autentisering med tokens
- ✅ Input-validering
- ✅ SQL injection-skydd
- ✅ HTTPS automatiskt via Cloudflare

## 💰 Kostnad

**Cloudflare Free Tier räcker för de flesta familjer:**

- Pages: 500 builds/månad
- D1: 100k läsningar + 1k skrivningar/dag
- Workers: 100k requests/dag

## 🛠️ Teknologi

- **Frontend**: Vanilla HTML/CSS/JavaScript (PWA)
- **Backend**: Cloudflare Workers
- **Databas**: Cloudflare D1 (SQLite)
- **Hosting**: Cloudflare Pages
- **CDN**: Cloudflare (global distribution)
- **Utvecklingsverktyg**: Wrangler 4.x, ESLint 9.x, Prettier, TypeScript

## 📞 Support

Vid problem:

1. Kontrollera Cloudflare Dashboard för logs
2. Använd `npx wrangler tail` för realtidsloggar
3. Testa API-endpoints direkt via curl/Postman

## 🔄 Uppdateringar

```bash
# Deploy nya versioner
git add .
git commit -m "Uppdatering"
git push origin main
npx wrangler deploy
```

Appen uppdateras automatiskt för alla användare!

## 📋 Changelog

### v3.0.0 (2025-06-21) - 🔒 Säkerhet & Funktionalitet

- 🔐 **SÄKERHET**: Hashade lösenord med SHA-256 + salt
- 🛡️ **SÄKERHET**: Brute force-skydd med kontolåsning
- 📊 **SÄKERHET**: Komplett säkerhetsloggning
- ➕ **FUNKTION**: Lägg till nya barn dynamiskt
- ✏️ **FUNKTION**: Redigera barnens namn och användarnamn
- 🗑️ **FUNKTION**: Ta bort barn (soft delete)
- 🧪 **TESTER**: Komplett testsvit med 20+ tester
- 📈 **ÖVERVAKNING**: Health check API-endpoint
- 🔍 **LOGGNING**: Detaljerad systemloggning
- 🚫 **SÄKERHET**: Förbättrat SQL injection-skydd

### v2.0.0 (2025-06-21) - 🛠️ Modernisering

- ⬆️ Uppdaterat Wrangler till 4.20.5
- 🔧 Migrerat till ESLint 9.x med flat config
- 🎨 Lagt till favicon med bank-ikon
- ✨ Fixat alla kodkvalitetsvarningar
- 📦 Uppdaterat alla beroenden till senaste versioner
- ⚡ Förbättrad caching och prestanda

### v1.0.0 (Initial release)

- 🏦 Grundläggande sparapp-funktionalitet
- 👨‍👩‍👧‍👦 Barn- och föräldrakonton
- 💰 Transaktionshantering
- 📱 PWA-stöd
