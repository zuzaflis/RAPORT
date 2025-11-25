# A10:2021 – Server-Side Request Forgery (SSRF)

## 5.10. A10:2021 – Server-Side Request Forgery (SSRF)

### Wstęp do zagadnienia

Kategoria **A10:2021 – Server-Side Request Forgery (SSRF)** opisuje sytuacje, w których aplikacja po stronie serwera wykonuje żądania HTTP do adresów podanych przez użytkownika, bez odpowiedniej walidacji. Pozwala to atakującemu zmusić serwer do łączenia się z zasobami wewnętrznymi (np. `localhost`, sieć prywatna, metadane chmurowe), do których normalnie użytkownik nie miałby dostępu.

W aplikacjach typu CRUD (jak **Quiz-Web-App**) podatność SSRF pojawia się głównie wtedy, gdy dodane są funkcje typu „pobierz zasób z URL” (np. import danych z linku, pobieranie obrazka profilowego z podanego adresu).

Na podstawie analizy kodu stwierdzono, że **aplikacja w aktualnej wersji nie zawiera funkcjonalności narażonych na SSRF**. Poniższa sekcja ma charakter audytu potwierdzającego brak podatności.

---

### 🔍 PODATNOŚĆ: Brak funkcjonalności narażonych na SSRF

**Identyfikator:** `VUL-A10-001`
**Poziom ryzyka:** ✅ **NIE STWIERDZONO PODATNOŚCI**
**CWE (kontekst kategorii):** CWE-918 – Server-Side Request Forgery (SSRF)

#### 📍 Lokalizacja

**Zakres analizy kodu:**

* kontrolery: `QuizController`, `QuestionController`, `UserController`, `CategoryController`, `AdminController`, `AuthenticationController`,
* serwisy: `QuizService`, `QuestionService`, `UserService`, `CategoryService`,
* konfiguracja bezpieczeństwa i JWT: `SecurityConfig`, `JwtService`, `JwtAuthenticationFilter`, `ApplicationConfig`,
* encje i DTO: m.in. `Quiz`, `Question`, `User`, `Result`, `Category`, `QuizRequest`, `QuestionRequest`, `EvalRequest`, `RegisterRequest`, `AuthenticationRequest`.

#### 📝 Opis podatności

* **nie występują** klienci HTTP po stronie serwera (`RestTemplate`, `WebClient`, `HttpClient`, `OkHttp` itp.),
* nie ma bezpośredniego użycia `java.net.URL` / `HttpURLConnection`,
* brak jest funkcji, które pobierałyby zasoby z zewnętrznych adresów URL podanych przez użytkownika.

Logika aplikacji ogranicza się do:

* przyjmowania żądań HTTP z frontendu,
* wykonywania operacji CRUD na bazie danych (Spring Data JPA),
* generowania i weryfikacji tokenów JWT,
* walidacji dostępu (Spring Security).

Dane wejściowe w kontrolerach (DTO) zawierają m.in.:

* nazwy quizów, pytania, odpowiedzi, wyniki,
* dane użytkowników (login, hasło, podstawowe dane identyfikacyjne),

i **nie są nigdzie wykorzystywane do budowy URL-i, na które serwer wykonywałby żądania HTTP**.

---

#### 💥 Proof of Concept (negatywny – potwierdzenie braku SSRF)

**Cel weryfikacji:** sprawdzić, czy serwer wykonuje jakiekolwiek żądania HTTP do adresów pochodzących od użytkownika.

1. **Przegląd importów w kontrolerach i serwisach**

   W kodzie nie ma importów typowych klientów HTTP, takich jak:

   ```java
   import org.springframework.web.client.RestTemplate;
   import org.springframework.web.reactive.function.client.WebClient;
   import java.net.URL;
   import java.net.HttpURLConnection;
   ```

   Kontrolery delegują logikę do serwisów, a te korzystają z repozytoriów JPA (`UserRepository`, `QuizRepository`, `QuestionRepository` itd.).

2. **Analiza DTO i encji**

   Przykładowo, encja `Quiz` zawiera pola:

   ```java
   private Long qId;
   private String title;
   private String description;
   private String maxMarks;
   private String numberOfQuestions;
   private boolean active = false;
   ```

   a DTO `QuestionRequest`:

   ```java
   private Long quizId;
   private String content;
   private String image;
   private String option1;
   private String option2;
   // ...
   ```

   Żadne z tych pól nie jest używane jako adres URL, na który backend wysyłałby żądania HTTP.

3. **Brak funkcji „importu z URL”**

   W kodzie nie ma endpointów typu „import quizu z adresu URL”, „pobierz obraz z linku” ani „wywołaj webhook”, które mogłyby być punktem wejścia dla SSRF.

**Wniosek:** w aktualnej architekturze serwer **nie wykonuje żądań HTTP na podstawie danych wejściowych od użytkownika**, więc brak jest wektora ataku charakterystycznego dla SSRF.

---

#### ⚠️ Wpływ biznesowy (aktualny i potencjalny)

**Aktualny stan:**

* W obecnej wersji aplikacji **nie stwierdzono podatności SSRF**, ponieważ brak jest mechanizmów, które mogłyby zostać wykorzystane do tego typu ataku.

**Potencjalny wpływ w przyszłości (jeśli dodane zostaną funkcje oparte o URL):**

* **Poufność:**

  * w przypadku wprowadzenia funkcji pobierania danych z URL (np. import z linku) bez odpowiednich zabezpieczeń, serwer mógłby zostać wykorzystany do odpytywania zasobów wewnętrznych (bazy, paneli admina, metadanych chmurowych);
* **Integralność:**

  * błędnie zaprojektowana funkcja SSRF mogłaby umożliwiać modyfikację danych w systemach wewnętrznych, do których użytkownik normalnie nie ma dostępu;
* **Dostępność:**

  * masowe żądania SSRF do wewnętrznych serwisów mogłyby zostać użyte do ich przeciążenia (DoS).

---

#### 🛡️ Rekomendacje (prewencyjne)

Na wypadek rozbudowy aplikacji o funkcje korzystające z adresów URL (np. import z linku, pobieranie plików):

1. **Walidacja URL po stronie backendu**

   * akceptowanie wyłącznie bezpiecznych schematów (`https://`),
   * blokowanie schematów takich jak `file://`, `ftp://`, `gopher://` itp.

2. **Lista dozwolonych domen (allowlist)**

   * wykonywanie żądań HTTP tylko do zdefiniowanych, zaufanych domen,
   * brak możliwości wskazania dowolnego hosta/IP.

3. **Blokada adresów wewnętrznych**

   * odrzucanie prób połączeń do adresów takich jak `127.0.0.1`, `localhost`, `10.x.x.x`, `192.168.x.x`, adresów metadanych chmurowych itp.

4. **Ograniczenie ruchu wychodzącego z serwera**

   * konfiguracja firewalli / reguł sieciowych w modelu „deny by default” i zezwolenie tylko na niezbędne połączenia zewnętrzne.

---

### ✔ Podsumowanie Oceny A10 – Server-Side Request Forgery (SSRF)

| Obszar                                                | Wynik weryfikacji         |
| ----------------------------------------------------- | ------------------------- |
| Użycie klientów HTTP po stronie backendu              | ✅ Nie stwierdzono         |
| Parametry wejściowe typu URL używane do żądań serwera | ✅ Nie stwierdzono         |
| Import/pobieranie zasobów z zewnętrznych URL          | ✅ Nie stwierdzono         |
| Podatność A10:2021 – SSRF                             | ✅ W aktualnej wersji brak |

W aktualnym kształcie aplikacja **Quiz-Web-App** nie jest podatna na ataki z kategorii **A10:2021 – Server-Side Request Forgery (SSRF)**.
