# RAPORT Z AUDYTU BEZPIECZEŃSTWA KODU

## APLIKACJA QUIZOWA    

---

## 1. INFORMACJE O DOKUMENCIE

### 1.1. Autorzy Raportu

| Rola | Imię i Nazwisko           |
|------|---------------------------|
| Audytor wiodący | inż. Zuzanna Flis |
| Audytor wiodący | inż. Dagmara Pasek |
| Audytor wiodący | inż. Barbara Kowalska |

### 1.2. Informacje o Audycie

- **Nazwa projektu:** Aplikacja Quizowa
- **Wersja aplikacji:** 1.0.0 (git: )
- **Data audytu:** 16 listopada 2025
- **Metodyka:** OWASP Top 10 2021
- **Typ audytu:** White Box (z pełnym dostępem do kodu źródłowego)

---

## 2. SKALA OCENY RYZYKA

Podczas audytu stosowano czterostopniową skalę oceny ryzyka podatności:

### 2.1. Definicje Poziomów Ryzyka

| Poziom | Opis | Kryteria | Rekomendowany czas naprawy |
|--------|------|----------|---------------------------|
| **🔴 KRYTYCZNY** | Podatność umożliwiająca natychmiastowe przejęcie kontroli nad systemem, kradzież wszystkich danych lub całkowite naruszenie poufności/integralności | - Możliwość wykonania kodu po stronie serwera<br>- Nieautoryzowany dostęp do wszystkich danych<br>- Przejęcie kont administratorów<br>- Dostęp do haseł/kluczy | **Natychmiast (0-24h)** |
| **🟠 WYSOKI** | Podatność umożliwiająca znaczące naruszenie bezpieczeństwa z potencjalnym wpływem na wiele użytkowników lub krytyczne funkcje systemu | - Dostęp do danych innych użytkowników<br>- Ominięcie autoryzacji<br>- SQL Injection z dostępem do wrażliwych danych<br>- Brak szyfrowania krytycznych danych | **Pilnie (1-7 dni)** |
| **🟡 ŚREDNI** | Podatność wymagająca spełnienia dodatkowych warunków, ale mogąca prowadzić do naruszenia bezpieczeństwa | - Ujawnienie informacji systemowych<br>- Podatności wymagające interakcji użytkownika<br>- Słabe mechanizmy zabezpieczeń<br>- Brak logowania zdarzeń bezpieczeństwa | **Ważne (7-30 dni)** |
| **🔵 NISKI** | Podatność o ograniczonym wpływie, trudna do wykorzystania lub ujawniająca niewrażliwe informacje | - Ujawnienie wersji oprogramowania<br>- Niewłaściwe nagłówki bezpieczeństwa<br>- Podatności informacyjne<br>- Drobne błędy konfiguracyjne | **Normalnie (30-90 dni)** |

---

## 3. STRESZCZENIE WYKONAWCZE
//TODO
### 3.1. Podsumowanie wyników

Przeprowadzony audyt bezpieczeństwa aplikacji e-commerce opartej na frameworku NestJS wykazał **liczne krytyczne podatności** stanowiące bezpośrednie zagrożenie dla bezpieczeństwa systemu, danych użytkowników oraz ciągłości działania biznesu.

**🔴 OGÓLNA OCENA BEZPIECZEŃSTWA: KRYTYCZNA**

Aplikacja w obecnym stanie **NIE POWINNA BYĆ WDROŻONA** w środowisku produkcyjnym bez natychmiastowego usunięcia zidentyfikowanych podatności krytycznych i wysokich.

### 3.2. Statystyki Zidentyfikowanych Podatności
//TODO
```
┌─────────────────────────────────────────────────────────────┐
│           ROZKŁAD PODATNOŚCI WEDŁUG POZIOMU RYZYKA          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  🔴 KRYTYCZNE:    ████████████████████  10 podatności       │
│  🟠 WYSOKIE:      ████████████          6 podatności        │
│  🟡 ŚREDNIE:      ████                  2 podatności        │
│  🔵 NISKIE:       ██                    1 podatność         │
│                                                             │
│  📊 RAZEM:        19 zidentyfikowanych podatności           │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│         ROZKŁAD WEDŁUG KATEGORII OWASP TOP 10 2021          │
├─────────────────────────────────────────────────────────────┤
│  A01 - Broken Access Control               █████  (2)       │
│  A02 - Cryptographic Failures              █████  (2)       │
│  A03 - Injection                           █████  (2)       │
│  A04 - Insecure Design                     █████  (2)       │
│  A05 - Security Misconfiguration           █████  (2)       │
│  A06 - Vulnerable Components               █████  (2)       │
│  A07 - Authentication Failures             █████  (2)       │
│  A08 - Software/Data Integrity Failures    █████  (2)       │
│  A09 - Logging/Monitoring Failures         █████  (2)       │
│  A10 - Server-Side Request Forgery         █████  (1)       │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. ZAKRES I METODYKA AUDYTU

### 4.1. Zakres audytu

#### 4.1.1. Audytowana aplikacja

- **Typ aplikacji:** RESTful API - Backend aplikacji quizowej
- **Technologia:** Java, Spring Boot, Angular, Typescript
- **Baza danych:** MySQL z Hibernate (JPA)
- **Autentykacja:** JWT (JSON Web Tokens)
- **Architektura:** Modularna (8 modułów funkcjonalnych)

#### 4.1.2. Audytowane Moduły

| Moduł(Kontroler) | Funkcjonalność | Liczba Endpointów |
|-------|----------------|-------------------|
| AuthenticationController | Rejestracja, logowanie, reset hasła | 3 |
| UserController | Zarządzanie profilami użytkowników | 1 |
| CategoryController | Zarządzanie kategoriami (Admin) | 4 |
| QuizController | Zarządzanie quizami | 6 |
| QuestionController | Zarządzanie pytaniami do quizów | 6 |

**Łącznie:** 20 endpointow API

### 4.2. Metodyka

#### 4.2.1. Typ Audytu: White Box

Audyt przeprowadzono z **pełnym dostępem do kodu źródłowego**, co pozwoliło na:

- Szczegółową analizę statyczną kodu
- Zrozumienie logiki biznesowej i przepływów danych
- Identyfikację podatności na poziomie implementacji
- Weryfikację mechanizmów zabezpieczeń

#### 4.2.2. Zastosowane Standardy
- **OWASP Top 10 2021** - Główna metodyka klasyfikacji podatności
- **CWE (Common Weakness Enumeration)** - Klasyfikacja podatności
- **CVSS** 4.0 - Ocena zagrożenia

#### 4.2.3. Użyte Narzędzia
// TODO
| Kategoria | Narzędzie | Wersja | Przeznaczenie |
|-----------|-----------|--------|---------------|
| **Analiza kodu** | Visual Studio Code | 1.103.2 | Przegląd kodu źródłowego |
| **Analiza statyczna** | ESLint + Security Plugin | 9.18.0 | Wykrywanie wzorców niebezpiecznego kodu |
| **Analiza zależności** | npm audit | 10.x | Skanowanie znanych podatności w pakietach |
| **Testowanie API** | Postman | 10.x | Manualne testowanie endpointów |
| **Testowanie SQL Injection** | sqlmap | 1.7.x | Automatyczne wykrywanie SQL Injection |
| **Analiza JWT** | jwt.io / jwt-tool | - | Analiza tokenów JWT |
| **Skanowanie portów** | nmap | 7.94 | Rekonesans infrastruktury |

### 4.3. Środowisko Testowe

#### 4.3.1. Sposób Uruchomienia Aplikacji

```bash
# Uruchomienie całego środowiska (Frontend, Backend, Baza Danych)
docker-compose up --build

# Aplikacja dostępna pod adresem
http://localhost:4200

# Dokumentacja API (Swagger)
http://localhost:3000/api
```

#### 4.3.2. Parametry Środowiska

- **System operacyjny:** Windows 11
- **Wirtualizacja:** Docker Desktop
- **Java:** 17
- **Spring Boot:** 3.1.2
- **Spring Security :** 3.1.0
- **Angular:** ^16.2.0
- **Angular Material:** ^16.2.4
- **RxJS:** ~7.8.0
- **Baza danych:** MySQL (plik: exam_portal.sql)

#### 4.3.3. Dane Testowe

Wykorzystano dane testowe dostarczone w pliku exam_portal.sql, zawierające użytkowników, kategorie, quizy i pytania w tym 2 konta użytkowników (admin, regularne).

### 4.4. Ograniczenia Audytu

#### 4.4.1. Ograniczenia Czasowe i Zakresowe
// TODO
| Obszar | Ograniczenie | Powód | Wpływ |
|--------|-------------|-------|-------|
| **Testy penetracyjne infrastruktury** | Niewykonane | Brak dostępu do środowiska produkcyjnego | Nie zidentyfikowano podatności infrastrukturalnych (firewall, load balancer, itp.) |
| **Testy obciążeniowe (DoS/DDoS)** | Niewykonane | Ograniczenia środowiska lokalnego | Nie oceniono odporności na ataki DoS |
| **Testowanie aplikacji front-end** | Niewykonane | Brak aplikacji klienckiej | Nie wykryto podatności XSS, CSRF po stronie front-endu |
| **Audyt konfiguracji Docker** | Częściowy | Kontener nie był uruchomiony w środowisku testowym | Nie oceniono bezpieczeństwa izolacji kontenerów |
| **Testy compliance (RODO, PCI-DSS)** | Poza zakresem | Audyt techniczny, nie prawny | Nie oceniono zgodności z regulacjami |

#### 4.4.2. Czego Nie Można Było Sprawdzić
// TODO
1. **Race conditions**
   - **Powód:** Ograniczone możliwości symulacji współbieżności
   - **Wpływ:** Nie zidentyfikowano podatności związanych z równoczesnym dostępem

2. **Błędy logiki biznesowej**
   - **Powód:** Brak pełnej dokumentacji wymagań biznesowych
   - **Wpływ:** Wykryto tylko oczywiste błędy logiki biznesowej

### 4.5. Klauzula Odpowiedzialności

Niniejszy raport przedstawia stan bezpieczeństwa aplikacji na dzień przeprowadzenia audytu. Nie stanowi gwarancji braku innych podatności. Audytorzy dołożyli należytej staranności zgodnie z przyjętą metodyką i dostępnym czasem.
