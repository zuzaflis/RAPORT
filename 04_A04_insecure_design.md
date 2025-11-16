# A04:2021 - Insecure Design

### 5.4. A04:2021 - Insecure Design

#### 📚 Wyjaśnienie Zagadnienia

**Insecure Design** (Niebezpieczny Projekt) to nowa kategoria w OWASP Top 10 2021, która koncentruje się na **błędach w projektowaniu i architekturze** aplikacji, a nie na błędach implementacji.

Różnica między Insecure Design a błędami implementacji:
- **Insecure Design**: Brak wymaganych mechanizmów bezpieczeństwa w projekcie (np. brak rate limitingu w projekcie)
- **Błąd implementacji**: Źle zaimplementowany mechanizm bezpieczeństwa (np. rate limiting z błędną logiką)

Główne obszary:
- **Brak rate limiting** - brak ograniczenia liczby żądań
- **Brak walidacji logiki biznesowej** - możliwość ominięcia workflow
- **Niewłaściwe zarządzanie stanem** - race conditions
- **Brak threat modeling** - nieprzewidziane scenariusze ataku
- **Nadmierne zaufanie do danych klienta** - client-side security

Ta kategoria podkreśla znaczenie **Security by Design** i **Secure Development Lifecycle (SDL)**.

---

#### 🔍 PODATNOŚĆ #1: Brak Rate Limiting - możliwość ataku Brute Force

**Identyfikator:** `VUL-A04-001`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**CVSS v4.0:** 7.1 (High)
**Wektor:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N`

##### 📍 Lokalizacja

**Plik:**
* `src/main/java/com/portal/demo/controller/AuthenticationController.java`
* `src/main/java/com/portal/demo/config/SecurityConfig.java` (Brak globalnej konfiguracji Throttlingu)

**Endpoint:**
* `POST /api/v1/auth/authenticate`

##### 📝 Opis Podatności

Aplikacja nie implementuje żadnego mechanizmu ograniczającego liczbę żądań (Rate Limiting) na krytycznym punkcie końcowym, jakim jest logowanie. Atakujący może wysłać tysiące nieudanych prób logowania w krótkim czasie, próbując odgadnąć hasło do konta (np. administratora).

System odpowiada na każde żądanie błędem `403 Forbidden`, ale nigdy nie blokuje ani nie spowalnia atakującego IP, co czyni atak Brute Force lub Credential Stuffing w 100% skutecznym.

##### 💥 Proof of Concept
**Scenariusz:** Atakujący używa narzędzia (np. Postman Runner lub skryptu), aby wysłać 50 nieudanych prób logowania na konto `admin1` w ciągu kilku sekund.

**Krok 1: Uruchomienie zautomatyzowanego ataku**

Za pomocą Postman Runner skonfigurowano 50 iteracji żądania `POST /api/v1/auth/authenticate` z opóźnieniem 0ms.

```json
// Ciało każdego żądania w pętli
{
  "username": "admin1",
  "password": "zlehaslo123" 
}
```
**Krok 2: Wynik (Podatność potwierdzona)** 
Narzędzie Runner pokazało, że wszystkie 50 prób zostało wykonanych, a serwer odpowiedział na każdą z nich tym samym błędem, nie aktywując żadnego mechanizmu obronnego.
```json
// Odpowiedź serwera (powtórzona 50 razy)
{
    "timestamp": "2025-11-16T12:05:01.023+00:00",
    "status": 403,
    "error": "Forbidden",
    "path": "/api/v1/auth/authenticate"
}
```

##### ⚠️ Wpływ Biznesowy

- **Poufność:** 🟠 WYSOKA - Wysokie prawdopodobieństwo przejęcia konta (w tym konta admina) przez atak Brute Force, zwłaszcza przy słabych hasłach (zidentyfikowanych w A07).
- **Integralność:** 🟠 WYSOKA - Przejęcie konta prowadzi do naruszenia integralności danych.
- **Dostępność:** 🔴 KRYTYCZNA - Tysiące żądań na sekundę może obciążyć serwer i bazę danych, prowadząc do ataku DoS (Denial of Service).

**Konsekwencje:**
- Przejęcie kont przez brute force
- Przeciążenie serwera i niedostępność usługi
- Zwiększone koszty infrastruktury

##### 🛡️ Rekomendacje Naprawy

1. **Implementacja rate limiting**
    - Należy natychmiast zaimplementować mechanizm Rate Limitingu dla endpointu logowania.

    - W ekosystemie Spring Boot popularnym rozwiązaniem jest biblioteka Bucket4j lub ręczna implementacja za pomocą interceptora i cache (np. Caffein lub Redis).

2. **Blokowanie kont po nieudanych próbach**
    - Oprócz limitu żądań, należy zaimplementować logikę blokowania konta.

    - Po 5 nieudanych próbach logowania z rzędu, konto użytkownika (admin1) powinno zostać tymczasowo zablokowane na 15 minut.

---
