# A05:2021 – Security Misconfiguration

### 5.5. A05:2021 – Security Misconfiguration

####  Wyjaśnienie Zagadnienia

Kategoria **Security Misconfiguration** (Błędy konfiguracji bezpieczeństwa) obejmuje podatności wynikające z niewłaściwych ustawień serwera, frameworków i komponentów aplikacji. Nie są to klasyczne „bugi” w kodzie, lecz **niebezpieczne lub zbyt liberalne konfiguracje**, np. brak odpowiednich nagłówków HTTP, wyłączone mechanizmy ochronne czy pozostawione ustawienia domyślne. 

W analizowanej aplikacji **Quiz-Web-App** zidentyfikowano **4 istotne błędy konfiguracyjne**, które obniżają poziom bezpieczeństwa systemu.

---

#### 🔍 PODATNOŚĆ #1: Zbyt liberalna polityka CORS (`@CrossOrigin` bez ograniczenia originów)

**Identyfikator:** `VUL-A05-001`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-942 – Permissive Cross-Origin Resource Sharing Policy

##### 📍 Lokalizacja

**Plik:**

* `backend/src/main/java/com/portal/demo/controller/UserController.java`

**Fragment:**

```java
@RestController
@RequestMapping("/api/v1/user")
@CrossOrigin // domyślnie: wszystkie domeny
public class UserController {
    // ...
}
```

##### 📝 Opis Podatności

W kontrolerze `UserController` użyto adnotacji `@CrossOrigin` **bez żadnych parametrów**.
W Springu taka konfiguracja oznacza domyślnie zezwolenie na **wszystkie originy (domeny)**, wszystkie nagłówki oraz metody zdefiniowane w `@RequestMapping`. 

W rezultacie:

* dowolna zewnętrzna strona (w tym potencjalnie złośliwa) może wykonywać żądania do API,
* przeglądarka nie zablokuje takich wywołań na poziomie CORS,
* jeśli endpoint zwraca dane wrażliwe, mogą zostać one odczytane z kontekstu przeglądarki ofiary.

#####  Proof of Concept

**Scenariusz:**

Atakujący hostuje własną stronę (`https://evil-frontend.com`), która w tle wysyła żądania AJAX do API aplikacji.

```javascript
// Kod na stronie atakującego
fetch("http://localhost:8080/api/v1/user/me", {
  credentials: "include"
})
  .then(r => r.json())
  .then(data => console.log("Dane ofiary:", data));
```

Ponieważ `@CrossOrigin` bez ograniczeń dopuszcza wszystkie originy, przeglądarka zezwoli na takie żądanie do backendu.

#####  Wpływ Biznesowy

* **Poufność:** wysoka – możliwość odczytu danych użytkownika z poziomu zewnętrznej strony.
* **Integralność:** potencjalnie wysoka, jeśli endpointy pozwalają na modyfikację danych.
* **Dostępność:** brak bezpośredniego wpływu, ale CORS nie ogranicza też floodowania API z innych domen.

##### 🛡️ Rekomendacje Naprawy

1. **Ograniczenie originów**

   W `UserController` należy jawnie wskazać zaufany frontend, np.:

   ```java
   @CrossOrigin(origins = "http://localhost:4200")
   ```

   W produkcji origin powinien wskazywać na właściwą domenę aplikacji.

2. **Konfiguracja globalna**

   Docelowo warto przenieść konfigurację CORS do klasy konfiguracyjnej (`WebMvcConfigurer` albo `CorsConfigurationSource` w Spring Security), aby mieć jedno, centralne miejsce zarządzania polityką CORS.

---

#### 🔍 PODATNOŚĆ #2: Wyłączona ochrona CSRF (`csrf().disable()`)

**Identyfikator:** `VUL-A05-002`
**Poziom ryzyka:** 🟡 **ŚREDNI**
**CWE:** CWE-352 – Cross-Site Request Forgery (CSRF)

##### 📍 Lokalizacja

**Plik:**

* `backend/src/main/java/com/portal/demo/config/SecurityConfig.java`

**Fragment:**

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/api/v1/auth/**").permitAll()
            .requestMatchers("/**").permitAll()
            .anyRequest().authenticated()
        )
        .csrf(csrf -> csrf.disable()) // Wyłączona ochrona CSRF
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .authenticationProvider(authenticationProvider)
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
}
```

##### 📝 Opis Podatności

W konfiguracji Spring Security globalnie wyłączono mechanizm **CSRF** (`csrf().disable()`).
W architekturze opartej na **JWT w nagłówku** i bez cookies może to być decyzja świadoma, ale:

* jeśli w przyszłości logowanie lub sesje zostaną przeniesione na cookies,
* lub powstaną endpointy korzystające z formularzy webowych,

– brak CSRF otwiera drogę do ataków polegających na **wykonywaniu akcji w imieniu zalogowanego użytkownika** bez jego wiedzy. 

#####  Proof of Concept (scenariusz przyszły)

Jeżeli autoryzacja zostałaby oparta o cookies, atakujący mógłby osadzić na swojej stronie formularz:

```html
<form action="https://quiz-app.local/api/v1/user/updateEmail" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
</form>

<script>
  // formularz wysyła się automatycznie po załadowaniu strony
  document.forms[0].submit();
</script>
```

Po wejściu zalogowanego użytkownika na stronę napastnika przeglądarka wyśle żądanie z jego cookies, zmieniając dane ofiary bez jej interakcji.

#####  Wpływ Biznesowy

* **Poufność:** średnia – CSRF dotyczy głównie wykonywania akcji, niekoniecznie podglądu danych.
* **Integralność:** wysoka – możliwość modyfikacji danych konta (np. e-mail, hasło, ustawienia) bez wiedzy użytkownika.
* **Dostępność:** niewielki wpływ bezpośredni, możliwa eskalacja przez zmiany konfiguracji.

##### 🛡️ Rekomendacje Naprawy

1. **Dokumentacja decyzji o `csrf().disable()`**

   Jeśli aplikacja **pozostanie stateless i bez cookies**, należy wyraźnie udokumentować, że CSRF jest wyłączony ze względu na architekturę JWT.

2. **Włączenie CSRF w przypadku użycia cookies**

   Jeśli pojawią się sesje/cookies, trzeba:

   * usunąć `csrf().disable()`,
   * skonfigurować token CSRF (np. w nagłówku `X-XSRF-TOKEN`),
   * wymuszać jego obecność przy modyfikujących żądaniach (POST/PUT/DELETE).

---

#### 🔍 PODATNOŚĆ #3: Brak nagłówków bezpieczeństwa HTTP (CSP, HSTS)

**Identyfikator:** `VUL-A05-003`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-693 – Protection Mechanism Failure

##### 📍 Lokalizacja

**Plik:**

* `backend/src/main/java/com/portal/demo/config/SecurityConfig.java`
  (brak konfiguracji nagłówków HTTP)

##### 📝 Opis Podatności

W konfiguracji Spring Security nie zdefiniowano żadnych dodatkowych **nagłówków bezpieczeństwa HTTP**, takich jak:

* `Content-Security-Policy` (CSP) – ogranicza źródła skryptów, stylów, ramek itd. i jest jednym z podstawowych mechanizmów ochrony przed XSS,
* `Strict-Transport-Security` (HSTS) – wymusza korzystanie z HTTPS, chroniąc przed atakami typu downgrade i częścią ataków typu man-in-the-middle.

Domyślna konfiguracja Spring Security dodaje kilka nagłówków (m.in. `X-Content-Type-Options`, `X-Frame-Options: DENY`), ale **CSP i HSTS nie są ustawiane automatycznie** i wymagają świadomego skonfigurowania. 

#####  Proof of Concept (symulacja odpowiedzi)

Przykładowa odpowiedź z serwera (bez ręcznej konfiguracji CSP/HSTS) może wyglądać następująco:

```http
HTTP/1.1 200 OK
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
# BRAK: Content-Security-Policy
# BRAK: Strict-Transport-Security
```

Brak CSP powoduje, że przeglądarka nie ma dodatkowych ograniczeń dotyczących ładowania skryptów (np. zewnętrznych CDN, domen atakującego).
Brak HSTS oznacza, że użytkownik może zostać „zmuszony” do połączenia po HTTP, jeżeli infrastruktura (proxy/serwer) nie wymusi HTTPS na poziomie sieci.

#####  Wpływ Biznesowy

* **Poufność:** wysoka – brak CSP ułatwia wykorzystanie ewentualnych podatności XSS.
* **Integralność:** średnia – możliwość wstrzyknięcia złośliwego JS, który modyfikuje zawartość strony.
* **Dostępność:** pośrednia – brak HSTS ułatwia część ataków MITM, które mogą doprowadzić do blokowania/uszkadzania ruchu.

##### 🛡️ Rekomendacje Naprawy

1. **Konfiguracja Content-Security-Policy**

   W `SecurityConfig` dodać restrykcyjną politykę CSP, np.:

   ```java
   http.headers(headers -> headers
       .contentSecurityPolicy(csp -> csp
           .policyDirectives("default-src 'self'")
       )
   );
   ```

2. **Włączenie HSTS w środowisku produkcyjnym**

   Po pełnym przejściu na HTTPS na serwerze / reverse proxy:

   ```java
   http.headers(headers -> headers
       .httpStrictTransportSecurity(hsts -> hsts
           .includeSubDomains(true)
           .preload(true)
       )
   );
   ```

3. **Regularny przegląd nagłówków HTTP**

   Okresowo weryfikować nagłówki (np. za pomocą OWASP ZAP / curl), aby mieć pewność, że konfiguracja odpowiada aktualnym zaleceniom bezpieczeństwa.

---

#### 🔍 PODATNOŚĆ #4: Ujawnianie szczegółów błędów (Stack Trace)

**Identyfikator:** `VUL-A05-004`
**Poziom ryzyka:** 🟡 **ŚREDNI**
**CWE:** CWE-209 – Information Exposure Through Error Messages

##### 📍 Lokalizacja

Domyślna obsługa wyjątków Spring Boot (brak własnego `@ControllerAdvice` / globalnego handlera błędów).

##### 📝 Opis Podatności

Spring Boot domyślnie zwraca ustandaryzowaną odpowiedź błędu (JSON/HTML) dla nieobsłużonych wyjątków.
W zależności od wersji i konfiguracji właściwości `server.error.include-stacktrace` (oraz użycia DevTools) **stack trace może zostać dołączony do odpowiedzi**, np. w polu `trace`.

Takie szczegółowe komunikaty ujawniają atakującemu m.in.:

* nazwy pakietów i klas (architekturę aplikacji),
* fragmenty zapytań SQL i nazw tabel,
* ścieżki systemowe i wersje bibliotek.

OWASP klasyfikuje nadmiernie szczegółowe komunikaty błędów jako typową formę **Security Misconfiguration**.

#####  Proof of Concept (przykładowa odpowiedź)

Przy nieostrożnej konfiguracji (np. `server.error.include-stacktrace=always`) odpowiedź może wyglądać następująco:

```json
{
  "timestamp": "2023-11-24T10:00:00.000+00:00",
  "status": 500,
  "error": "Internal Server Error",
  "trace": "java.lang.NullPointerException: ... at com.portal.demo.service.UserService.getUser(UserService.java:45) ...",
  "path": "/api/user/get"
}
```

Atakujący, wywołując celowo błędne żądania, może zbierać tego typu informacje i wykorzystywać je do dalszych ataków (np. precyzyjnego SQL Injection na konkretne tabele).

#####  Wpływ Biznesowy

* **Poufność:** średnia – wyciek informacji o wewnętrznej strukturze aplikacji.
* **Integralność:** pośrednia – ułatwia przygotowanie bardziej zaawansowanych ataków.
* **Dostępność:** niewielka – sama podatność nie wpływa na dostępność, ale może pomóc w przygotowaniu np. ataków DoS na konkretne miejsca.

##### 🛡️ Rekomendacje Naprawy

1. **Wyłączenie stack trace w odpowiedziach**

   W `application.properties`:

   ```properties
   server.error.include-stacktrace=never
   ```

   (lub odpowiednik dla używanej wersji Spring Boot).

2. **Globalny handler wyjątków**

   Stworzyć klasę z `@ControllerAdvice`, która:

   * mapuje wyjątki na uproszczone komunikaty dla użytkownika (np. „Wystąpił błąd, spróbuj ponownie później”),
   * pełne szczegóły zapisuje wyłącznie w logach serwera (logback/log4j).

3. **Rozdzielenie komunikatów dev/prod**

   * w środowisku deweloperskim można zachować bardziej szczegółowe logi,
   * w produkcji odpowiedzi API powinny być maksymalnie lakoniczne pod kątem informacji technicznych.

---

### ✔ Podsumowanie Oceny A05 – Security Misconfiguration

| Podatność                                                        | Ryzyko     |
| ---------------------------------------------------------------- | ---------- |
| Permissive CORS (`@CrossOrigin` zezwalający na wszystkie domeny) | 🟠 WYSOKIE |
| Brak nowoczesnych nagłówków bezpieczeństwa (CSP, HSTS)           | 🟠 WYSOKIE |
| Wyłączona ochrona CSRF (`csrf().disable()`)                      | 🟡 ŚREDNIE |
| Możliwe ujawnianie Stack Trace w odpowiedziach błędów            | 🟡 ŚREDNIE |

