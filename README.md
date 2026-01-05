# SecureFileShare

**Università degli Studi di Bari "Aldo Moro"**  
Corso di Laurea in Sicurezza Informatica  
Sicurezza nelle Applicazioni - A.A. 2025/2026

---

## Descrizione

Applicazione web Java per la condivisione sicura di file testuali.
Implementa le best practice di sicurezza trattate nel corso.

---

## Struttura Progetto

```
SecureFileShare/
├── sql/                            # Schema database
├── src/main/java/app
│   ├── controller/                 # Servlet
│   ├── dao/                        # Accesso database
│   ├── filter/                     # Filtri sicurezza
│   ├── security/                   # Crittografia, Vault, validazione
│   ├── config/                     # Configurazione applicazione
│   └── model/                      # Entità
├── src/main/webapp/
│   ├── WEB-INF/                    # web.xml, pagine errore
│   ├── META-INF/                   # Manifest
│   ├── css/                        # Stili
│   ├── js/                         # JavaScript
│   └── *.jsp                       # Pagine
├── vault/                          # Configurazione e init Vault
├── docker-compose.yml              # Configurazione Docker
├── .env.example                    # Template variabili d'ambiente
├── pom.xml                         # Dipendenze Maven
├── SecureFileShare.war             # Applicazione compilata
├── setup.bat                       # Script installazione (Windows)
└── setup.sh                        # Script installazione (macOS/Linux)
```

---

## Prerequisiti

| Software | Versione | Note |
|----------|----------|------|
| Java JDK | 17+ | `JAVA_HOME` deve essere impostato |
| Apache Tomcat | 11.0+ | `CATALINA_HOME` deve essere impostato |
| Docker Desktop | - | Deve essere **avviato** |
| Maven | 3.8+ | Solo se si vuole ricompilare |

---

## Sicurezza Implementata

| Categoria | Implementazione |
|-----------|-----------------|
| **Trasporto** | HTTPS obbligatorio, HSTS, redirect automatico |
| **Password** | PBKDF2-HMAC-SHA256, 310.000 iterazioni, salt 16 byte |
| **File** | AES-256-GCM, IV random, chiave in Vault |
| **Email** | Cifrate AES-256-GCM + hash SHA-256 per ricerca |
| **XSS** | Output encoding (JSTL), CSP con nonce dinamico |
| **SQL Injection** | PreparedStatement su tutte le query |
| **Session** | Rigenerazione ID al login, timeout 30 min |
| **Cookie** | HttpOnly, Secure, SameSite=Strict |
| **Segreti** | HashiCorp Vault |
| **Upload** | Validazione MIME con Apache Tika, whitelist tipi |
| **Concorrenza** | ReadWriteLock per accesso file thread-safe |

---

## Installazione

### 1. Estrai il progetto

Estrai `SecureFileShare.zip` in una cartella a scelta.

### 2. Configura le credenziali (.env)

**⚠️ OBBLIGATORIO: Tutte le configurazioni sono in `.env`**

```bash
# Copia il template
cp .env.example .env

# Modifica con le tue credenziali
nano .env   # oppure il tuo editor preferito
```

**Variabili principali in `.env`:**

| Variabile | Descrizione |
|-----------|-------------|
| `MYSQL_ROOT_PASSWORD` | Password root MySQL |
| `MYSQL_USER` | Username app per MySQL |
| `MYSQL_PASSWORD` | Password app per MySQL |
| `VAULT_TOKEN` | Token Vault (generato automaticamente, vedi step 4) |
| `AES_ENCRYPTION_KEY` | Chiave AES-256 (opzionale, generata automaticamente) |
| `SESSION_TIMEOUT` | Timeout sessione in secondi (default: 900) |
| `COOKIE_SECURE` | Cookie solo HTTPS (default: true) |
| `COOKIE_HTTPONLY` | Cookie non accessibile da JS (default: true) |
| `COOKIE_SAMESITE` | Protezione CSRF (default: Strict) |

> ℹ️ Vedi `.env.example` per la lista completa delle variabili.

**Genera password sicure:**
```bash
openssl rand -base64 32
```

### 3. Avvia Docker (Vault + MySQL)

```bash
docker-compose up -d
```

Questo avvia:
- **Vault** in server mode
- **MySQL** con lo schema dell'applicazione
- **vault-init** che automaticamente:
  - Inizializza Vault (primo avvio)
  - Esegue unseal
  - Configura tutti i segreti da `.env`

### 4. Recupera il VAULT_TOKEN

Il token viene salvato automaticamente in un file:

```bash
cat vault/generated-token.txt
```

Copia questo token nel file `.env`:
```
VAULT_TOKEN=hvs.xxxxxxxxxxxxx
```

> ℹ️ Ai riavvii successivi, vault-init esegue solo unseal (le chiavi sono persistite nel volume).

### 5. Configura Tomcat per leggere le variabili d'ambiente

L'applicazione legge **tutte** le configurazioni da variabili d'ambiente.
Configura Tomcat per passarle:

**macOS / Linux** (`$CATALINA_HOME/bin/setenv.sh`):
```bash
#!/bin/bash
# Vault
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="$(cat /path/to/SecureFileShare/vault/generated-token.txt)"

# Upload
export UPLOAD_DIRECTORY="uploads"
export UPLOAD_MAX_SIZE="1048576"

# Validazione
export PASSWORD_MIN_LENGTH="12"
export PASSWORD_MAX_LENGTH="128"
export EMAIL_MAX_LENGTH="254"

# File whitelist
export FILE_ALLOWED_EXTENSIONS=".txt"
export FILE_ALLOWED_MIMETYPES="text/plain"
export FILE_BUFFER_SIZE="8192"

# Sessione e Cookie
export SESSION_TIMEOUT="900"
export COOKIE_SECURE="true"
export COOKIE_HTTPONLY="true"
export COOKIE_SAMESITE="Strict"

# HSTS
export HSTS_ENABLED="true"
export HSTS_MAX_AGE="31536000"
export HSTS_INCLUDE_SUBDOMAINS="true"

# Sicurezza password
export PBKDF2_ITERATIONS="310000"
export SALT_LENGTH="16"
export KEY_LENGTH="256"
export NONCE_LENGTH="16"
```

**Windows** (`%CATALINA_HOME%\bin\setenv.bat`):
```cmd
@echo off
rem Vault
set VAULT_ADDR=http://localhost:8200
set /p VAULT_TOKEN=<vault\generated-token.txt

rem Upload
set UPLOAD_DIRECTORY=uploads
set UPLOAD_MAX_SIZE=1048576

rem Validazione
set PASSWORD_MIN_LENGTH=12
set PASSWORD_MAX_LENGTH=128
set EMAIL_MAX_LENGTH=254

rem File whitelist
set FILE_ALLOWED_EXTENSIONS=.txt
set FILE_ALLOWED_MIMETYPES=text/plain
set FILE_BUFFER_SIZE=8192

rem Sessione e Cookie
set SESSION_TIMEOUT=900
set COOKIE_SECURE=true
set COOKIE_HTTPONLY=true
set COOKIE_SAMESITE=Strict

rem HSTS
set HSTS_ENABLED=true
set HSTS_MAX_AGE=31536000
set HSTS_INCLUDE_SUBDOMAINS=true

rem Sicurezza password
set PBKDF2_ITERATIONS=310000
set SALT_LENGTH=16
set KEY_LENGTH=256
set NONCE_LENGTH=16
```

> ⚠️ Crea il file `setenv.sh` / `setenv.bat` se non esiste. Su Linux/macOS rendi eseguibile con `chmod +x setenv.sh`.

### 6. Esegui setup

**Windows:**
```cmd
setup.bat
```

**macOS / Linux:**
```bash
chmod +x setup.sh
./setup.sh
```

Lo script automaticamente:
- Genera il certificato HTTPS
- Configura Tomcat
- Deploya il WAR
- Avvia Tomcat
- Apre il browser

### 7. Accedi all'applicazione

```
https://localhost:8443/SecureFileShare
```

> ⚠️ Il browser mostrerà un avviso sul certificato (è autofirmato).  
> Clicca **"Avanzate"** → **"Procedi comunque"**.

---

## Arresto

Per fermare l'applicazione:

**Windows:**
```cmd
"%CATALINA_HOME%\bin\shutdown.bat"
docker-compose down
```

**macOS / Linux:**
```bash
$CATALINA_HOME/bin/shutdown.sh
docker-compose down
```

---

## Risoluzione Problemi

### Verifica variabili d'ambiente

**Windows:**
```cmd
echo %JAVA_HOME%
echo %CATALINA_HOME%
```

**macOS / Linux:**
```bash
echo $JAVA_HOME
echo $CATALINA_HOME
```

Se non impostate:

**Windows:**
```cmd
set JAVA_HOME=C:\Program Files\Java\jdk-17
set CATALINA_HOME=C:\apache-tomcat-11.0.0
```

**macOS:**
```bash
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home
export CATALINA_HOME=/opt/tomcat
```

**Linux:**
```bash
export JAVA_HOME=/usr/lib/jvm/java-17
export CATALINA_HOME=/opt/tomcat
```

### "Docker non trovato"
- Avvia Docker Desktop
- Attendi che sia completamente avviato (icona nella tray)
- Riprova

### "Porta 8443 già in uso"
```cmd
netstat -ano | findstr 8443
taskkill /PID <numero_pid> /F
```

### "WAR non trovato"
Assicurati che `SecureFileShare.war` sia nella stessa cartella di `setup.bat`.

### "Errore connessione database"
```cmd
docker-compose ps
docker-compose logs mysql
```

### "Errore Vault"
```cmd
docker-compose logs vault
```

---

## Configurazione Manuale Completa

Se `setup.bat`/`setup.sh` non funziona:

### 1. Genera keystore
**Windows:**
```cmd
"%JAVA_HOME%\bin\keytool" -genkeypair ^
    -alias tomcat ^
    -keyalg RSA ^
    -keysize 2048 ^
    -validity 365 ^
    -keystore "%CATALINA_HOME%\conf\keystore.jks" ^
    -storepass changeit ^
    -keypass changeit ^
    -dname "CN=localhost, OU=SecureFileShare, O=UniBa, L=Bari, ST=Puglia, C=IT" ^
    -ext "SAN=dns:localhost,ip:127.0.0.1"
```

**macOS / Linux:**
```bash
$JAVA_HOME/bin/keytool -genkeypair \
    -alias tomcat \
    -keyalg RSA \
    -keysize 2048 \
    -validity 365 \
    -keystore $CATALINA_HOME/conf/keystore.jks \
    -storepass changeit \
    -keypass changeit \
    -dname "CN=localhost, OU=SecureFileShare, O=UniBa, L=Bari, ST=Puglia, C=IT" \
    -ext "SAN=dns:localhost,ip:127.0.0.1"
```

**Posizione Keystore**
```
Windows:  %CATALINA_HOME%\conf\keystore.jks
macOS/Linux: $CATALINA_HOME/conf/keystore.jks
```

### 2. Configura server.xml
Aggiungi in `%CATALINA_HOME%\conf\server.xml` prima di `</Service>`:

```xml
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true">
    <SSLHostConfig>
        <Certificate certificateKeystoreFile="conf/keystore.jks"
                     certificateKeystorePassword="changeit"
                     certificateKeyAlias="tomcat" type="RSA" />
    </SSLHostConfig>
</Connector>
```

### 3. Avvia Docker
```bash
docker-compose up -d
```

### 4. Deploya WAR

**Windows:**
```cmd
copy SecureFileShare.war "%CATALINA_HOME%\webapps\"
```

**macOS / Linux:**
```bash
cp SecureFileShare.war $CATALINA_HOME/webapps/
```

### 5. Avvia Tomcat

**Windows:**
```cmd
"%CATALINA_HOME%\bin\startup.bat"
```

**macOS / Linux:**
```bash
$CATALINA_HOME/bin/startup.sh
```

---

## Tecnologie Utilizzate

- Java 17, Servlet 6.0, JSP, JSTL
- Apache Tomcat 11
- MySQL 8.0
- HashiCorp Vault
- Apache Tika (validazione file)
- zxcvbn (validazione password client-side)
- Docker Compose

---

## Autore

Marco Ferrara   
m.ferrara62@studenti.uniba.it   
864819
