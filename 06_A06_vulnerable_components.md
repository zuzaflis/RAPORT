# A06:2021 - Vulnerable and Outdated Components

### 5.6. A06:2021 - Vulnerable and Outdated Components

#### 📚 Wyjaśnienie Zagadnienia

#### 📚 Wyjaśnienie Zagadnienia

**Vulnerable and Outdated Components** (Podatne i Nieaktualne Komponenty) dotyczy ryzyka związanego z łańcuchem dostaw oprogramowania (Supply Chain). Współczesne aplikacje, takie jak ta oparta na Spring Boot i Angularze, budowane są z setek gotowych bibliotek zewnętrznych. Jeśli którakolwiek z tych bibliotek zawiera lukę bezpieczeństwa, cała aplikacja staje się na nią podatna.

Problem ten jest oznaczany numerami **CVE** (Common Vulnerabilities and Exposures). Podczas audytu wykorzystujemy narzędzia **SCA** (Software Composition Analysis), aby zidentyfikować biblioteki, które nie otrzymały aktualizacji bezpieczeństwa i mogą zostać wykorzystane przez atakujących do przejęcia serwera (RCE) lub zablokowania usługi (DoS).

---

#### 🔍 PODATNOŚĆ #1: Przestarzałe zależności z znanymi CVE

**Identyfikator:** `VUL-A06-001`
**Poziom ryzyka:** 🔴 **KRYTYCZNY**
**CWE:** CWE-1390 (Use of Components with Known Vulnerabilities)

##### 📍 Lokalizacja

**Pliki:**
* `backend/pom.xml`
* `frontend/package.json`

##### 📝 Opis Podatności

Analiza zależności projektu (zarówno `pom.xml`, jak i `package.json`) wykazała użycie **dziesiątek** bibliotek, które posiadają publicznie znane podatności bezpieczeństwa (CVE/GHSA). Wiele z nich ma status **KRYTYCZNY** lub **WYSOKI**.

Atakujący może wykorzystać te powszechnie znane błędy do przeprowadzenia ataków, takich jak:
* **RCE (Remote Code Execution):** Przejęcie serwera przez błąd deserializacji (`snakeyaml`).
* **SSRF / CSRF:** Ataki na serwer i użytkowników przez podatne `axios`.
* **DoS (Denial of Service):** Zablokowanie aplikacji przez błędy w `tomcat` lub `body-parser`.
* **Arbitrary Code Execution:** Podatność w narzędziach budowania (`@babel/traverse`).

##### 💥 Weryfikacja (Wyniki Skanowania)

```bash
# Sprawdzenie podatności frontend
npm audit


# Wynik:
# 78 vulnerabilities (12 low, 46 moderate, 18 high, 2 critical)

# Sprawdzenie podatności backend
mvn org.owasp:dependency-check-maven:check

# Wynik:
# Dependencies Scanned: 72 (43 unique)
# Vulnerable Dependencies: 10
# Vulnerabilities Found: 39

```

---

**Backend (OWASP Dependency-Check):**
Skanowanie `pom.xml` wykazało **10 podatnych bibliotek z 39 podatnościami**. Najważniejsze z nich to:

| # | Biblioteka (Java) | Wersja | Poziom | CVE / Opis Zagrożenia |
|---|---|---|---|---|
| 1 | `snakeyaml` | 1.33 | 🔴 **CRITICAL** | `CVE-2022-1471` - Deserialization of Untrusted Data (możliwe RCE) |
| 2 | `tomcat-embed-core` | 10.1.11 | 🔴 **CRITICAL** | **27 podatności!** W tym błędy DoS, Request Smuggling. |
| 3 | `spring-security-core` | 6.1.2 | 🟠 **HIGH** | `CVE-2023-34035` - Denial of Service (DoS) |
| 4 | `mysql-connector-j` | 8.0.33 | 🟠 **HIGH** | Błąd deserializacji przy połączeniu z fałszywym serwerem. |

**Frontend (npm audit):**
Skanowanie `package.json` wykazało **78 podatności**, w tym:

| # | Biblioteka (npm) | Wersja | Poziom | GHSA / Opis Zagrożenia |
|---|---|---|---|---|
| 1 | `@babel/traverse` | <7.23.2 | 🔴 **CRITICAL** | `GHSA-67hx-6x53-jw92` - Arbitrary code execution. |
| 2 | `form-data` | 4.0.0 - 4.0.3 | 🔴 **CRITICAL** | `GHSA-fjxv-7rqg-78g4` - Użycie niebezpiecznej funkcji losowej. |
| 3 | `axios` | 1.0.0 - 1.11.0 | 🟠 **HIGH** | `GHSA-8hc4-vh64-cxmj` (SSRF), `GHSA-wf5p-g6vw-rhxx` (CSRF). |
| 4 | `body-parser` | <1.20.3 | 🟠 **HIGH** | `GHSA-qwcr-r2fm-qrc7` - Denial of Service (DoS). |
| 5 | `ws` | 8.0.0 - 8.17.0 | 🟠 **HIGH** | `GHSA-3h5v-q93c-6h6q` - Denial of Service (DoS). |


---

##### ⚠️ Wpływ Biznesowy
* **Ryzyko Kompromitacji:** Wykorzystanie znanej podatności (np. RCE w `snakeyaml`) może prowadzić do całkowitego przejęcia serwera.
* **Denial of Service (DoS):** Wiele podatności pozwala na zablokowanie aplikacji przez wysłanie specjalnie spreparowanego żądania.
* **Utrata Zaufania:** Używanie nieaktualnego, dziurawego oprogramowania świadczy o braku higieny bezpieczeństwa.

##### 🛡️ Rekomendacje Naprawy

1.  **Natychmiastowa Aktualizacja:** Zaktualizować wszystkie biblioteki z podatnościami `CRITICAL` i `HIGH` do najnowszych bezpiecznych wersji (`npm audit fix`, manualna aktualizacja `pom.xml`).
2.  **Automatyzacja w CI/CD:** Zintegrować `npm audit` i `OWASP Dependency-Check` z procesem CI/CD, aby automatycznie blokować buildy zawierające nowe krytyczne podatności.
3.  **Wdrożenie Snyk / Dependabot:** Używać narzędzi (np. Dependabot w GitHub), które automatycznie skanują repozytorium i tworzą Pull Requesty z poprawkami bezpieczeństwa.
---

#### 🔍 PODATNOŚĆ #2: Brak Software Bill of Materials (SBOM)

**Identyfikator:** `VUL-A06-002`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-1104 (Use of Unmaintained Third Party Components)

##### 📝 Opis Podatności

Aplikacja nie posiada udokumentowanej listy wszystkich używanych komponentów, co utrudnia:
- Szybką identyfikację podatności
- Reagowanie na nowe CVE
- Dostosowania się do wymogów prawnych

##### 🛡️ Rekomendacje Naprawy

1. **Generowanie i utrzymywanie SBOM**
   - Użyć narzędzia typu CycloneDX do wygenerowania Software Bill of Materials

---