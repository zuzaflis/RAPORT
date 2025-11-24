# A07:2021 - Identification and Authentication Failures

### 5.7. A07:2021 – Identification and Authentication Failures

#### 📚 Wyjaśnienie Zagadnienia

**Identification and Authentication Failures** (Błędy Identyfikacji i Uwierzytelniania) to kategoria grupująca słabości w procesie potwierdzania tożsamości użytkownika. Jest to pierwsza linia obrony aplikacji – jeśli zawiedzie, wszystkie inne zabezpieczenia mogą okazać się bezużyteczne.

W ramach tego audytu zidentyfikowaliśmy dwa krytyczne braki:
* **Słaba polityka haseł:** System pozwala na tworzenie trywialnych haseł (np. jednoliterowych), co czyni je podatnymi na ataki słownikowe. Mimo że hasła są hashowane w bazie, ich niska entropia (złożoność) sprawia, że są łatwe do złamania.
* **Brak MFA (Multi-Factor Authentication):** System opiera się wyłącznie na jednym składniku (wiedzy – haśle). Brak drugiego składnika (np. kodu jednorazowego) oznacza, że kompromitacja hasła administratora prowadzi do natychmiastowego i całkowitego przejęcia systemu.

#### 🔍 PODATNOŚĆ #1: Brak Polityki Silnych Haseł

**Identyfikator:** `VUL-A07-001`
**Poziom ryzyka:** 🔴 **KRYTYCZNY**
**CWE:** CWE-521: Weak Password Requirements

##### 📍 Lokalizacja

**Plik:**
* `src/main/java/com/portal/demo/controller/AuthenticationController.java`
* `src/main/java/com/portal/demo/service/AuthenticationService.java`

**Endpoint:**
* `POST /api/v1/auth/register`

##### 📝 Opis Podatności

Endpoint rejestracji (`/api/v1/auth/register`) nie implementuje żadnej polityki dotyczącej siły haseł. Aplikacja pozwala użytkownikom na tworzenie kont z ekstremalnie słabymi hasłami, takimi jak `"s"`, `"a"`, `"123"` lub `"user1"`.

Mimo że aplikacja poprawnie hashuje hasła w bazie danych (co jest dobre), pozwala na istnienie słabych hashy, które są trywialne do złamania za pomocą ataków słownikowych lub brute-force.

##### 💻 Kod Podatny

**Brak adnotacji @Valid:**
'backend/src/main/java/com/portal/demo/auth/AuthenticationController.java'
```java
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest registerRequest) // ⬅️ DODAJ @Valid
    {
```
**Brak walidacji w DTO:**
`backend/src/main/java/com/portal/demo/dto/RegisterRequest.java`

```java

@Data
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String username;
    private String password;
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private String profile;
    private Role role;

}
```

##### 💥 Weryfikacja (Proof of Concept)

**Scenariusz:** Atakujący tworzy konto z jednoznakowym hasłem.

```bash
**Krok 1: Wysłanie żądania rejestracji ze słabym hasłem**
Atakujący wysyła żądanie do endpointu rejestracji z hasłem `"s"`.

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "NIEpoprawnyUser",
    "password": "s",
    "firstName": "NIEPoprawny",
    "lastName": "User",
    "email": "NIEpoprawny@test.com",
    "phone": "123456789"
  }'

**Odpowiedź 200 OK(sukces!):**
```json
{
    "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwb3ByY..."
}
```


**Scenariusz 3: Weryfikacja w bazie danych**

```bash
# Sprawdzenie hasła w bazie MySQL
 "SELECT * FROM users WHERE email='NIEpoprawny@test.com';"
```

**Wynik:**
```
id	email	first_name	last_name	password	phone	profile	role	username
402	NIEpoprawny@test.com	NIEPoprawny	uSER	$2a$10$/OK0xEZ5dX1wrhqDrIFbceyrbHDLQF9qRbQmmA1hV3T5gTeLvWyle	123456789	NULL	NULL	NIEpoprawnyUser

```

Hasło przechowywane poprawnie.

##### ⚠️ Wpływ Biznesowy
- **Poufność:** 🟡 WYSOKA - Konta użytkowników są podatne na przejęcie przez ataki brute-force, które błyskawicznie złamią słabe hasła.
 - **Integralność:** 🔴 WYSOKA - Po przejęciu konta (w tym konta admina), atakujący może modyfikować dane.
- **Reputacja:** Utrata zaufania, gdy użytkownicy dowiedzą się, że ich konta nie są chronione podstawowymi zasadami bezpieczeństwa.

##### Konsekwencje:

- Masowe przejmowanie kont użytkowników.

- Użycie słabych, przejętych kont do dalszych ataków na system.

- Ataki typu "Credential Stuffing" stają się bardziej skuteczne.
##### 🛡️ Rekomendacje Naprawy

**1. Implementacja polityki silnych haseł**

**Wymagania minimalne:**
- Wprowadzić w logice serwisowej (AuthenticationService) lub na poziomie DTO (RegisterRequest) walidację haseł.

- Należy użyć adnotacji walidacyjnych (np. @Size, @Pattern) lub logiki sprawdzającej.

**2. Wymuszenie Polityki Silnych Haseł:**
- Minimalna długość: Wymusić co najmniej 12 znaków.

- Złożoność: Wymusić użycie co najmniej jednej małej litery, jednej wielkiej litery, jednej cyfry i jednego znaku specjalnego.

- Blokowanie słownika: Odrzucać hasła znajdujące się na listach popularnych haseł (np. "password123", "qwerty").

**3. Weryfikacja wycieków**
- Rozważyć wdrożenie Have I Been Pwned API do sprawdzenia czy użyte hasło nie znajduje się w innych wyciekach

---

##### 📚 Referencje

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [bcrypt NPM Package](https://www.npmjs.com/package/bcrypt)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)

---

#### 🔍 PODATNOŚĆ #2: Brak Multi-Factor Authentication (MFA)

**Identyfikator:** `VUL-A07-002`
**Poziom ryzyka:** 🔴 **KRYTYCZNY**
**CWE:** CWE-308: Use of Single-factor Authentication

##### 📍 Lokalizacja

**Pliki:**
* `src/main/java/com/portal/demo/controller/AuthenticationController.java`
* `src/main/java/com/portal/demo/service/AuthenticationService.java`
* Całkowity brak modułu/logiki MFA w aplikacji

##### 📝 Opis Podatności

Aplikacja nie oferuje ani nie wymusza żadnej formy uwierzytelniania wieloskładnikowego (MFA/2FA) dla użytkowników, a w szczególności dla kont z uprawnieniami **ADMINA**. Uwierzytelnianie opiera się wyłącznie na jednym czynniku (haśle).

W przypadku kompromitacji hasła administratora (np. poprzez phishing, słabe hasło z A07-001, lub wyciek hashy z A01-002), atakujący uzyskuje natychmiastowy i pełny dostęp do panelu administracyjnego bez żadnych dodatkowych barier.

**Brak mechanizmów:**
- TOTP (Time-based One-Time Password)
- Dodatkowej weryfikacji przez magic-link lub kod w wiadomości email
- WebAuth (YubiKey, FIDO2)

##### 💻 Kod Podatny

**backend/src/main/java/com/portal/demo/auth/AuthenticationService.java:52-68**
```java
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getUsername(),
                        authenticationRequest.getPassword()
                )
        );
        var user = userRepository.findByUsername(authenticationRequest.getUsername())
                .orElseThrow(()-> new UsernameNotFoundException("Username not found"));

    // ❌ Krok 2: NATYCHMIASTOWE generowanie tokenu
    // ❌ Brak weryfikacji drugiego czynnika (MFA)
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
```

##### 💥 Weryfikacja (Proof of Concept)

**Scenariusz 1: Logowanie do aplikacji (zarówno jako user, jak i admin).**

✅ **Natychmiastowy pełny dostęp do konta!**

1. Użytkownik wysyła żądanie POST /api/v1/auth/authenticate z poprawnym loginem i hasłem.

2. Serwer weryfikuje poświadczenia (jeden czynnik).

3. Serwer natychmiast zwraca 200 OK wraz z tokenem JWT.

4. W żadnym momencie procesu logowania aplikacja nie prosi o drugi czynnik (np. kod TOTP z aplikacji, kod SMS, email).

**Wpływ:** Każdy, kto zdobędzie hasło administratora, natychmiast staje się administratorem.

##### ⚠️ Wpływ Biznesowy
- **Account takeover** - przejęcie konta po kompromitacji hasła
- **Brak obrony przed credential stuffing** - skradzione dane logowania z innych serwisów działają
- **Naruszenie Zgodności:** Brak MFA dla kont administracyjnych jest często naruszeniem podstawowych standardów bezpieczeństwa (np. PCI-DSS).
- **Brak wykrywania podejrzanych logowań** - logowanie z nowego urządzenia/lokalizacji nie wymaga weryfikacji
- **Persistent access** - nawet zmiana hasła przez użytkownika nie unieważnia sesji atakującego
- **Privilege escalation** - przejęcie konta administratora daje pełną kontrolę nad systemem

##### 🛡️ Rekomendacje Naprawy

1. **Wymuszenie MFA dla Administratorów:** Natychmiast zaimplementować i wymusić włączenie MFA (np. TOTP przez Google Authenticator) dla wszystkich kont z rolą ADMIN.

2. **Opcjonalne MFA dla Użytkowników:** Dodać w profilu użytkownika możliwość włączenia MFA dla swojego konta, aby zwiększyć bezpieczeństwo.

3. **Modyfikacja Procesu Logowania:** Proces logowania musi zostać zmieniony:

    - Krok 1: Walidacja loginu i hasła.

    - Krok 2: Jeśli MFA jest włączone, zwróć 200 OK z informacją {"mfaRequired": true} (bez tokenu!).

    - Krok 3: Użytkownik wysyła kod MFA na nowy endpoint (np. /auth/verify-mfa).

    - Krok 4: Dopiero po poprawnej weryfikacji kodu MFA serwer wydaje finalny token JWT.

---

##### 📚 Referencje

- [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [CWE-308: Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [RFC 6238: TOTP Algorithm](https://tools.ietf.org/html/rfc6238)
- [speakeasy NPM Package](https://www.npmjs.com/package/speakeasy)
- [Microsoft: MFA blocks 99.9% of attacks](https://www.microsoft.com/en-us/security/blog/2019/08/20/one-simple-action-you-can-take-to-prevent-99-9-percent-of-account-attacks/)

---