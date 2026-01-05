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
├── .env.example                    # Template configurazione (da copiare in .env)
├── .env                            # Configurazione (da creare)
├── docker-compose.yml              # Configurazione Docker
├── SecureFileShare.war             # Applicazione compilata
├── sql/                            # Schema database
├── vault/                          # Configurazione Vault
├── pom.xml                         # Dipendenze Maven
└── src/                            # Codice sorgente
```

---

## Prerequisiti

| Software | Versione | Note |
|----------|----------|------|
| Java JDK | 17+ | |
| Apache Tomcat | 11.0+ | |
| Docker Desktop | - | Deve essere **avviato** |
| Maven | 3.8+ | Solo per ricompilare |

---

## Sicurezza Implementata

| Categoria | Implementazione |
|-----------|-----------------|
| **Trasporto** | HTTPS obbligatorio, HSTS |
| **Password** | PBKDF2-HMAC-SHA256, 310.000 iterazioni |
| **File** | AES-256-GCM, chiave in Vault |
| **Email** | Cifrate AES-256-GCM + hash SHA-256 |
| **XSS** | Output encoding JSTL, CSP con nonce, sanitizzazione server-side |
| **SQL Injection** | PreparedStatement |
| **Session** | Rigenerazione ID, timeout configurabile |
| **Cookie** | HttpOnly, Secure, SameSite=Strict |
| **Segreti** | HashiCorp Vault |
| **Upload** | Validazione MIME con Apache Tika |
| **Concorrenza** | ReadWriteLock thread-safe |

---

## Installazione

### 1. Estrai e configura

```bash
# Estrai il progetto
unzip SecureFileShare.zip
cd SecureFileShare

# Crea il file di configurazione
cp .env.example .env

# Modifica le configurazioni
nano .env
```

**Modifica obbligatoria nel `.env`:**

```bash
# Percorsi Java e Tomcat (adatta al tuo sistema)
JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
CATALINA_HOME=/opt/tomcat11

# Password sicure (genera con: openssl rand -base64 32)
MYSQL_ROOT_PASSWORD=genera_password_sicura_1
MYSQL_PASSWORD=genera_password_sicura_2
```

### 2. Avvia Docker

```bash
docker-compose up -d
```

Attendi qualche secondo, poi recupera il token Vault:

```bash
cat vault/generated-token.txt
```

Aggiungi il token al `.env`:

```bash
VAULT_TOKEN=hvs.xxxxxxxxxxxxxx
```

### 3. Configura HTTPS in Tomcat

**Genera certificato (sviluppo):**

```bash
source .env

keytool -genkey -alias tomcat -keyalg RSA -keysize 2048 \
    -keystore "$CATALINA_HOME/conf/keystore.jks" \
    -validity 365 -storepass changeit -keypass changeit \
    -dname "CN=localhost, OU=Dev, O=SecureFileShare, L=Bari, C=IT"
```

**Configura connector HTTPS:**

Modifica `$CATALINA_HOME/conf/server.xml`, aggiungi dopo il connector HTTP (porta 8080):

```xml
<Connector port="8443" 
           protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" 
           SSLEnabled="true"
           scheme="https" 
           secure="true">
    <SSLHostConfig>
        <Certificate certificateKeystoreFile="conf/keystore.jks"
                     certificateKeystorePassword="changeit"
                     type="RSA" />
    </SSLHostConfig>
</Connector>
```

### 4. Deploy

```bash
source .env

# Copia il WAR
cp SecureFileShare.war "$CATALINA_HOME/webapps/"

# Avvia Tomcat (estrae il WAR)
"$CATALINA_HOME/bin/startup.sh"

# Attendi qualche secondo, poi copia il .env nella webapp
cp .env "$CATALINA_HOME/webapps/SecureFileShare/"
```

### 5. Accedi

Apri: **https://localhost:8443/SecureFileShare**

> ⚠️ Accetta l'avviso del certificato self-signed.

---

## Configurazione IDE (Eclipse)

1. Configura Tomcat in Eclipse
2. Copia il `.env` nella working directory del progetto
3. Oppure imposta `ENV_FILE_PATH=/percorso/al/.env` nelle Run Configurations → Environment

---

## Risoluzione Problemi

### File .env non trovato

L'applicazione cerca il `.env` in:
1. `ENV_FILE_PATH` (variabile d'ambiente)
2. `$CATALINA_HOME/webapps/SecureFileShare/.env`
3. `$CATALINA_HOME/.env`
4. Directory corrente

Controlla i log: `tail -f $CATALINA_HOME/logs/catalina.out | grep EnvLoader`

### VAULT_TOKEN non trovato

```bash
docker-compose logs vault-init
cat vault/generated-token.txt
```

### Connessione database fallita

```bash
docker-compose ps                    # Verifica MySQL attivo
docker-compose logs mysql            # Controlla errori
```

---

## Comandi Utili

```bash
source .env                                    # Carica variabili

# Docker
docker-compose ps                              # Stato container
docker-compose logs -f                         # Log
docker-compose down -v                         # Reset completo

# Tomcat
"$CATALINA_HOME/bin/startup.sh"               # Avvia
"$CATALINA_HOME/bin/shutdown.sh"              # Ferma
tail -f "$CATALINA_HOME/logs/catalina.out"    # Log

# Database
docker exec -it securefileshare-mysql mysql -u root -p
```

---

## Compilazione (Opzionale)

```bash
source .env
export JAVA_HOME
mvn clean package
# Output: target/SecureFileShare.war
```

---

## Licenza

Progetto per il corso di Sicurezza nelle Applicazioni  
Università degli Studi di Bari "Aldo Moro" - A.A. 2025/2026
