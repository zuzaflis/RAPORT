
# A05:2021 – Security Misconfiguration

### 5.5. A05:2021 – Security Misconfiguration

#### 📚 Wyjaśnienie Zagadnienia

Kategoria **Security Misconfiguration** (błędy konfiguracji bezpieczeństwa) obejmuje sytuacje, w których aplikacja jest poprawnie napisana, ale jej **konfiguracja** jest zbyt liberalna lub nie uwzględnia podstawowych mechanizmów ochronnych. Dotyczy to m.in. ustawień CORS, CSRF, nagłówków HTTP czy domyślnych konfiguracji frameworków.

W aplikacji **Quiz-Web-App** zidentyfikowano **2 istotne problemy konfiguracyjne**, które mogą obniżać poziom bezpieczeństwa systemu.

---

#### 🔍 PODATNOŚĆ #1: Zbyt liberalna polityka CORS (`@CrossOrigin` bez ograniczenia originów)

**Identyfikator:** `VUL-A05-001`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-942 – Permissive Cross-Origin Resource Sharing Policy

##### 📍 Lokalizacja

**Plik:**

* `backend/src/main/java/com/portal/demo/controllers/UserController.java`

**Fragment:**

```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
@CrossOrigin   // domyślnie: wszystkie domeny
public class UserController {
    private final UserService userService;

    @GetMapping("/{username}")
    public Optional<User> getUser(@PathVariable("username") String username) {
        return this.userService.findUser(username);
    }
}
```

##### 📝 Opis podatności

Adnotacja `@CrossOrigin` została użyta **bez parametrów**.
Z dokumentacji Spring wynika, że w takim przypadku:

* **domyślnie dozwolone są wszystkie originy (domeny)**,
* domyślnie dozwolone są nagłówki i metody przypisane do danego endpointu.

Oznacza to, że:

* dowolna zewnętrzna strona internetowa może wykonywać żądania do endpointu `/api/v1/user/{username}`,
* jeśli kiedyś zostaną tu dodane dane wrażliwe (np. e-mail, role), mogą zostać odczytane z poziomu zewnętrznego frontendu.

##### 💥 Proof of Concept

**Scenariusz:**

Atakujący tworzy prostą stronę HTML pod adresem `https://evil-frontend.com`, która wysyła zapytanie do API:

```javascript
// Kod na stronie atakującego
fetch("http://localhost:8080/api/v1/user/admin1")
  .then(r => r.json())
  .then(data => console.log("Dane użytkownika:", data));
```

Ponieważ `@CrossOrigin` bez parametrów domyślnie zezwala na wszystkie domeny, przeglądarka **nie zablokuje** tego żądania ze względu na CORS, a odpowiedź z API trafi do skryptu działającego na stronie atakującego.

##### ⚠️ Wpływ Biznesowy

* **Poufność:** ryzyko wycieku danych użytkowników do zewnętrznych aplikacji.
* **Integralność:** jeśli w przyszłości dodane zostaną metody modyfikujące dane użytkownika (`POST/PUT/DELETE`), zewnętrzny frontend będzie mógł je wywoływać.
* **Dostępność:** pośrednio – otwarcie API na wszystkie domeny ułatwia masowe, zautomatyzowane wywołania z innych aplikacji.

##### 🛡️ Rekomendacje naprawy

1. **Ograniczenie originów w kontrolerze**

   Wskazanie zaufanego frontendu (w środowisku developerskim Angular na porcie 4200):

   ```java
   @CrossOrigin(origins = "http://localhost:4200")
   ```

   W środowisku produkcyjnym należy użyć docelowej domeny aplikacji.

2. **Konfiguracja globalna CORS**

   Docelowo konfigurację CORS warto przenieść do klasy konfiguracyjnej (np. przez `CorsConfigurationSource` lub `WebMvcConfigurer`), aby jednoznacznie kontrolować:

   * dozwolone domeny (`allowedOrigins`),
   * metody HTTP,
   * nagłówki,
   * możliwość wysyłania cookies/credentials.

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
        .csrf(csrf -> csrf.disable())   // wyłączona ochrona CSRF
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .authenticationProvider(authenticationProvider)
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
}
```

##### 📝 Opis podatności

W konfiguracji Spring Security globalnie wyłączono mechanizm **CSRF**:

```java
.csrf(csrf -> csrf.disable())
```

Obecna wersja aplikacji:

* działa jako **stateless API**,
* używa **JWT** w nagłówku `Authorization`,
* nie wykorzystuje mechanizmu sesji przeglądarkowej opartej o cookies.

W takim modelu wyłączenie CSRF jest decyzją często spotykaną. Jednak:

* jeśli w przyszłości zostanie wprowadzone logowanie oparte o cookies (sesje HTTP),
* lub pojawi się formularz HTML wysyłany bezpośrednio z przeglądarki,

– brak CSRF spowoduje, że przeglądarka będzie mogła **automatycznie wykonywać żądania w imieniu użytkownika** (np. po wejściu na złośliwą stronę).

##### 💥 Proof of Concept (scenariusz przyszły)

Przy założeniu, że kiedyś logowanie zostanie oparte o cookies sesyjne:

1. Użytkownik loguje się do aplikacji `https://quiz-app.local` – przeglądarka zapisuje ciasteczko sesyjne.

2. Następnie użytkownik odwiedza stronę atakującego, która zawiera ukryty formularz:

   ```html
   <form action="https://quiz-app.local/api/v1/user/updateEmail" method="POST">
     <input type="hidden" name="email" value="attacker@example.com">
   </form>

   <script>
     document.forms[0].submit();
   </script>
   ```

3. Przeglądarka wyśle żądanie **z ciasteczkiem ofiary**, a ponieważ CSRF jest wyłączone – serwer zaakceptuje zmianę e-maila bez wiedzy użytkownika.

##### ⚠️ Wpływ Biznesowy

* **Poufność:** pośrednio – atak CSRF może zostać wykorzystany do zmiany danych kontaktowych (np. e-mail), co następnie ułatwi przejęcie konta.
* **Integralność:** wysoka – możliwa modyfikacja danych użytkownika (ustawienia, hasło, e-mail) bez jego zgody.
* **Dostępność:** niska – sama podatność nie wpływa bezpośrednio na dostępność, ale umożliwia dalszą eskalację (np. zmiana konfiguracji konta admina).

##### 🛡️ Rekomendacje naprawy

1. **Utrzymanie stateless + dokumentacja decyzji**

   Jeśli aplikacja ma pozostać **czystym API z JWT w nagłówku** i bez cookies:

   * decyzja o `csrf().disable()` powinna być **świadomie udokumentowana** w dokumentacji technicznej jako element architektury.

2. **Włączenie CSRF przy użyciu cookies**

   Jeżeli w przyszłości pojawią się:

   * sesje oparte o cookies,
   * klasyczne formularze logowania z przeglądarki,

   należy:

   * usunąć `csrf().disable()`,
   * skonfigurować token CSRF (np. nagłówek `X-XSRF-TOKEN`),
   * wymuszać jego obecność dla żądań modyfikujących dane (`POST`, `PUT`, `DELETE`).

---

### ✔ Podsumowanie Oceny A05 – Security Misconfiguration

| Podatność                                                    | Ryzyko     |
| ------------------------------------------------------------ | ---------- |
| Zbyt liberalna polityka CORS (`@CrossOrigin` bez ograniczeń) | 🟠 WYSOKIE |
| Globalne wyłączenie ochrony CSRF (`csrf().disable()`)        | 🟡 ŚREDNIE |
