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

## 🆕 Senaste uppdateringar (v2.0)

- ⬆️ **Wrangler 4.20.5** - Senaste versionen med förbättrad prestanda
- 🔧 **ESLint 9.29.0** - Modern kodkvalitetskontroll
- 🎨 **Favicon** - Snygg bank-ikon i browser-fliken
- ✨ **Ren kod** - Inga ESLint-varningar eller fel
- 📦 **Moderna verktyg** - TypeScript, Prettier, och uppdaterade beroenden
- ⚡ **Optimerad caching** - Snabbare laddningstider

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

- anna / 123
- erik / 123
- lila / 123

**Förälder:**

- mamma / 456

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

# Testa databas lokalt
npx wrangler d1 execute sparappen-db --local --file=./schema.sql
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

### v2.0.0 (2025-06-21)
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
