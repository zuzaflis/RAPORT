# A09:2021 - Security Logging and Monitoring Failures

### 5.9. A09:2021 – Security Logging and Monitoring Failures

#### 📚 Wyjaśnienie Zagadnienia

Kategoria **Security Logging and Monitoring Failures** (Błędy Logowania i Monitorowania Bezpieczeństwa) obejmuje braki w rejestrowaniu zdarzeń, które uniemożliwiają wykrywanie ataków w czasie rzeczywistym oraz analizę incydentów po fakcie (forensics). Bez odpowiednich logów i monitoringu, naruszenie bezpieczeństwa może trwać miesiącami, a administratorzy nie będą świadomi, że dane są wykradane lub modyfikowane.

W analizowanym projekcie `Quiz-Web-App` zidentyfikowano **2 podatności**, które mają bezpośrednie odzwierciedlenie w kodzie źródłowym.


### 🔍 PODATNOŚĆ \#1: Brak systematycznego mechanizmu logowania (Insufficient Logging)

**Identyfikator:** `VUL-A09-001`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** CWE-778 – Insufficient Logging

#### 📍 Lokalizacja

  * **Główna klasa:** `backend/src/main/java/com/portal/demo/auth/AuthenticationController.java`
  * **Cały projekt:** Brak logowania w pozostałych serwisach i kontrolerach.

#### 📝 Opis Podatności

Większość modułów aplikacji (kontrolery `Quiz`, `Question`, `Category`) **nie używa żadnego logowania**. Choć w `AuthenticationController.java` zaimplementowano logger, rejestruje on jedynie fakt otrzymania żądania (`logger.info`).

Krytycznym błędem jest **brak logowania wyjątków** (np. `BadCredentialsException`) w procesie uwierzytelniania. Oznacza to, że nieudane próby logowania są odrzucane przez aplikację, ale nie generują żadnego śladu w logach systemowych, co czyni ataki słownikowe niewykrywalnymi.

#### 💥 Proof of Concept: Niewykrywalny Atak Brute Force

Atakujący może wykonać tysiące prób logowania, a administrator przeglądający logi nie zobaczy ani jednego błędu.

**Scenariusz (Bash Script):**

```bash
#!/bin/bash
# Próba zalogowania na konto admina błędnym hasłem 50 razy
for i in {1..50}; do
  curl -X POST http://localhost:8080/api/v1/auth/authenticate \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong_password"}'
done
```

**Wynik w logach serwera:Brak śladu ataku**


#### ⚠️ Wpływ Biznesowy

  * **Poufność:** 🟠 **WYSOKA** – Ataki na hasła użytkowników pozostają niezauważone.
  * **Integralność:** 🟠 **WYSOKA** – Brak możliwości śledzenia błędów aplikacji.

#### 🛡️ Rekomendacje Naprawy

1.  Wprowadzić **SLF4J + Logback** we wszystkich komponentach backendu.
2.  Dodać logowanie poziomu `ERROR` w blokach `catch` obsługujących uwierzytelnianie.
3.  Zaimplementować mechanizm **Rate Limiting** blokujący IP po serii nieudanych prób.



### 🔍 PODATNOŚĆ \#2: Brak audytu operacji modyfikujących dane (Audit Trail)

**Identyfikator:** `VUL-A09-002`
**Poziom ryzyka:** 🔴 **KRYTYCZNY**
**CWE:** CWE-1191 — Missing Sensitive Operation Audit

#### 📍 Lokalizacja

  * **Serwisy:** `QuizService.java`, `QuestionService.java`, `CategoryService.java`.

#### 📝 Opis Podatności

Aplikacja pozwala na modyfikację i usuwanie krytycznych danych biznesowych (pytania, quizy) za pomocą operacji **Hard Delete** (fizyczne usunięcie rekordu z bazy). Operacje te są wykonywane bez:

1.  Logowania zdarzenia.
2.  Zapisu w tabeli historycznej (kto, co, kiedy usunął).
3.  Wersjonowania danych.

#### 💥 Proof of Concept: "Insider Threat" 

Zwolniony pracownik posiadający wciąż aktywny token administratora usuwa całą bazę pytań.

**Kod Podatny (`QuestionService.java`):**

```java
public void deleteQuestion(Long quesId){
    Question question = questionRepository.findById(quesId).get();
    // Nie ma śladu, kto wywołał tę metodę.
    questionRepository.delete(question); 
}
```

**Analiza powłamaniowa:**
Administrator bazy danych widzi brakujące rekordy, ale **nie jest w stanie ustalić sprawcy**, ponieważ system nie przechowuje ID użytkownika przy operacjach usuwania.

#### ⚠️ Wpływ Biznesowy

  * **Integralność:** 🔴 **KRYTYCZNA** – Brak rozliczalności (non-repudiation) działań administratorów.
  * **Odtwarzalność:** 🟠 **WYSOKA** – Fizyczne usunięcie rekordu uniemożliwia przywrócenie danych po incydencie.

#### 🛡️ Rekomendacje Naprawy

1.  **Implementacja Soft Delete:** Zamiast fizycznego usuwania, oznaczać rekordy flagą `is_deleted = true`.
2.  **Rejestracja kontekstu:** Zapisywać ID użytkownika wykonującego operację w logach audytowych.
