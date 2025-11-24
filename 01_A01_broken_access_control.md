# A01:2021 - Broken Access Control

### 5.1. A01:2021 - Broken Access Control

#### 📚 Wyjaśnienie Zagadnienia

**Broken Access Control** (Błędy Kontroli Dostępu) to sytuacja, w której mechanizmy autoryzacji zawodzą, pozwalając użytkownikom na działania wykraczające poza ich uprawnienia. Należy odróżnić to od uwierzytelniania (logowania) – tutaj użytkownik jest poprawnie zalogowany, ale system nie blokuje mu dostępu do zasobów innych osób lub administratorów.

W kontekście tego audytu skupiliśmy się na dwóch kluczowych wektorach:
* **Privilege Escalation (Podniesienie uprawnień):** Sytuacja, w której zwykły użytkownik uzyskuje dostęp do funkcji administracyjnych (np. `CategoryController`) z powodu błędnej konfiguracji `Spring Security`.
* **IDOR (Insecure Direct Object References):** Błąd polegający na bezpośrednim dostępie do obiektów w bazie (np. profili użytkowników) poprzez manipulację identyfikatorem w adresie URL, bez weryfikacji, czy dany zasób należy do pytającego.

---

#### 🔍 PODATNOŚĆ #1: Brak autoryzacji w panelu administratora

**Identyfikator:** `VUL-A01-001`
**Poziom ryzyka:** 🔴 **KRYTYCZNY**
**CWE:** CWE-306 (Missing Authentication for Critical Function)

##### 📍 Lokalizacja

**Plik:** `src/main/java/com/portal/demo/controller/CategoryController.java`
**Plik konfiguracyjny:** `src/main/java/com/portal/demo/config/SecurityConfig.java` (Prawdopodobne miejsce błędu konfiguracji)
**Endpointy:** 
- `GET /category/` 
- `POST /category/` 
- `PUT /category/` 
- `GET /category/{categoryId}`

##### 📝 Opis Podatności

Aplikacja eksponuje kluczowe endpointy administracyjne (cały CategoryController) bez wymaganego sprawdzania uprawnień. Adnotacja @PreAuthorize("hasRole('ADMIN')")  jest obecna w kodzie, jednak nie jest poprawnie egzekwowana przez konfigurację Spring Security.
W rezultacie każdy zalogowany użytkownik, niezależnie od swojej roli, może wykonywać operacje administracyjne:
- Pobieranie listy wszystkich kategorii.
- Dodawanie nowych kategorii.
- Modyfikowanie istniejących kategorii.

**Podatny kod:**

```java
@RestController
@RequestMapping("/category")
@PreAuthorize("hasRole('ADMIN')") // ❌ Ta adnotacja nie działa!
@RequiredArgsConstructor
@CrossOrigin(origins="http://localhost:4200", allowedHeaders="*", allowCredentials = "true")
public class CategoryController {
    
    private final CategoryService categoryService;

    // ❌ Dostęp do tego endpointu ma każdy zalogowany użytkownik
    @GetMapping("/")
    public ResponseEntity<?> getCategories() { 
        return ResponseEntity.ok(this.categoryService.getCategories());
    }

    // ❌ Dostęp do tego endpointu również nie jest zablokowany
    @PostMapping("/")
    public ResponseEntity<Category> addCategory(@RequestBody Category category) {
        // ...
    }
}
```

##### 💥 Proof of Concept

```bash
# Scenariusz: Atakujący (zwykły użytkownik "user") uzyskuje dostęp do endpointu GET /category/, który powinien być zarezerwowany dla roli "ADMIN".

# 1. Zdobycie tokenu zwykłego użytkownika Wysyłamy żądanie logowania dla użytkownika z rolą USER.
curl -X POST http://localhost:8080/api/v1/auth/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "username": "zwykly_user",
    "password": "user_pass123"
  }'

# Odpowiedź (skrócona):
# { "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ6d3lrbHlfdXNlci..." }

# 2. Nieautoryzowany dostęp do zasobu admina Używamy zdobytego tokenu, aby odpytać chroniony endpoint /category/.

# Atakujemy endpoint admina
curl -X GET http://localhost:8080/category/ \
  -H "Authorization: Bearer $TOKEN"

# 3. Wynik (Podatność potwierdzona) Zamiast oczekiwanego błędu 403 Forbidden, serwer zwraca 200 OK i pełną listę kategorii, potwierdzając, że kontrola dostępu nie zadziałała.

[
    {
        "title": "Sport",
        "description": "Quiz na temat kolarstwa",
        "cid": 602
    },
    {
        "title": "Podróże",
        "description": "...",
        "cid": 652
    },
    ...
]
```

##### ⚠️ Wpływ Biznesowy

- **Poufność:** 🟡 ŚREDNIA - Ujawnienie struktury kategorii.
 - **Integralność:** 🔴 KRYTYCZNA - Każdy użytkownik może modyfikować, dodawać i usuwać kategorie quizów, dewastując kluczową logikę biznesową aplikacji.
- **Dostępność:** 🟡 WYSOKA - Atakujący może usunąć wszystkie kategorie, uniemożliwiając korzystanie z aplikacji.

**Konsekwencje:**
- Całkowite przejęcie kontroli nad kategoriami quizów.

- Możliwość wstrzyknięcia złośliwych lub obraźliwych treści do kategorii.

- Paraliż aplikacji poprzez usunięcie wszystkich kategorii.

##### 🛡️ Rekomendacje Naprawy

1. **Natychmiastowa Weryfikacja Konfiguracji Spring Security:**

    - Upewnij się, że w głównej klasie konfiguracyjnej (SecurityConfig.java) włączona jest obsługa adnotacji @PreAuthorize. Wymaga to adnotacji @EnableMethodSecurity (w nowszych wersjach Spring Security) lub @EnableGlobalMethodSecurity(prePostEnabled = true) (w starszych).

    - Sprawdź, czy filtr JwtAuthenticationFilter jest poprawnie wpięty w łańuch filtrów przed filtrem autoryzacji.

2. **Poprawna Konfiguracja Ról:**

    - Zweryfikuj, czy role w bazie danych są przechowywane z prefiksem ROLE_ (np. ROLE_ADMIN), jeśli Spring Security tego wymaga. Jeśli nie, należy dostosować adnotację do hasAuthority('ADMIN') lub skonfigurować Springa, aby nie oczekiwał prefiksu.

3. **Testy Jednostkowe Bezpieczeństwa:**

    - Dodać testy jednostkowe (@WebMvcTest) z @MockUser (symulującym różne role), aby automatycznie weryfikować, czy endpointy admina poprawnie zwracają błąd 403 Forbidden dla zwykłych użytkowników.

---

#### 🔍 PODATNOŚĆ #2: IDOR - Nieautoryzowany dostęp do danych dowolnego użytkownika

**Identyfikator:** `VUL-A01-002`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

##### 📍 Lokalizacja

**Plik:**
* `src/main/java/com/portal/demo/controller/UserController.java`
**Endpoint:**
* `GET /api/v1/user/{username}`

##### 📝 Opis Podatności

Endpoint `GET /api/v1/user/{username}` pozwala na pobranie pełnych informacji profilowych dowolnego użytkownika na podstawie jego nazwy. Brakuje weryfikacji, czy zalogowany użytkownik żąda informacji o **samym sobie**.

Dowolny zalogowany użytkownik (Atakujący) może enumerować nazwy użytkowników i wykradać dane osobowe (imię, nazwisko, email, telefon) wszystkich innych użytkowników, w tym administratorów.

**Podatny kod:**

```java
// UserController.java
// ...
    // ❌ Endpoint nie weryfikuje, czy zalogowany użytkownik
    // ❌ to ten sam użytkownik, o którego pyta (np. "admin1")
    @GetMapping("/{username}")
    public User getUser(@PathVariable("username") String username) {
        return this.userService.getUser(username);
    }
// ...
```

##### 💥 Proof of Concept

Scenariusz: Atakujący (zwykły użytkownik "user") wykrada dane profilowe administratora ("admin1").

```bash
# 1. Zdobycie tokenu Użytkownika A Używamy tokenu userA (np. eyJhbGci...).

# 2. Żądanie dostępu do zasobu Użytkownika B (Admina) Używając tokenu userA, wysyłamy żądanie o dane profilowe użytkownika admin1
# Odpowiedź zawiera WSZYSTKICH użytkowników z hasłami:

# Atakujemy endpoint, pytając o dane "admin1"
curl -X GET http://localhost:8080/api/v1/user/admin1 \
  -H "Authorization: Bearer $TOKEN_USER_A"

# 3. Wynik (Podatność potwierdzona) Zamiast oczekiwanego błędu 403 Forbidden, serwer zwraca 200 OK i pełne dane profilowe administratora, w tym jego zahaszowane hasło, email i numer telefonu.

{
    "id": 402,
    "username": "admin1",
    "password": "$2a$10$/OK0xEZ5dX1wrhqDrIFbceyrbHDLQF9qRbQmmA1hV3T5gTeLvWyle",
    "firstName": "admin",
    "lastName": "admin",
    "email": "admin@mail.com",
    "phone": "13213",
    "profile": null,
    "role": "ADMIN",
    "results": [],
    "enabled": true,
    "authorities": [
        {
            "authority": "ADMIN"
        }
    ],
    "accountNonExpired": true,
    "accountNonLocked": true,
    "credentialsNonExpired": true
}
```

##### ⚠️ Wpływ Biznesowy

- **Poufność:** 🔴 KRYTYCZNA - Ujawnienie danych osobowych (PII) wszystkich użytkowników, w tym imion, nazwisk, e-maili i numerów telefonów. Ujawnienie zahaszowanych haseł ułatwia ataki offline (łamanie hashy).
- **Integralność:** 🟢 BRAK WPŁYWU
- **Dostępność:** 🟢 BRAK WPŁYWU

**Konsekwencje:**
- **Naruszenie zgodności z RODO, PCI-DSS**
- Utrata zaufania użytkowników.
- Ułatwienie ataków phishingowych i socjotechnicznych na użytkowników (dzięki pozyskaniu e-maili i telefonów).

##### 🛡️ Rekomendacje Naprawy

1. **Implementacja Weryfikacji Właściciela:**
    - W metodzie getUser w UserController należy pobrać obiekt Authentication (dane zalogowanego użytkownika).

    - Należy porównać nazwę zalogowanego użytkownika (authentication.getName()) z nazwą użytkownika z username w URL.

    - Zezwolić na dostęp tylko jeśli nazwy są identyczne LUB zalogowany użytkownik ma rolę ADMIN.

2. **Filtrowanie Danych (DTO):**
   - NIGDY nie zwracać w odpowiedzi API całego obiektu encji (User).

    - Stworzyć obiekt DTO (Data Transfer Object), np. UserProfileDto, który zawiera tylko bezpieczne dane (np. username, firstName) i pomija wrażliwe pola, takie jak password, role, email, phone.

---