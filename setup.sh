#!/bin/bash
# ============================================
# SecureFileShare - Setup Automatico
# ============================================
# Università degli Studi di Bari "Aldo Moro"
# Sicurezza nelle Applicazioni 2025/2026
# ============================================
#
# Questo script configura e avvia l'applicazione:
# 1. Genera certificato HTTPS (se non presente)
# 2. Configura Tomcat per HTTPS (se necessario)
# 3. Avvia Vault e MySQL (Docker)
# 4. Deploya il WAR in Tomcat
# 5. Avvia Tomcat
#
# ============================================

set -e

echo ""
echo "============================================"
echo "  SecureFileShare - Setup Automatico"
echo "============================================"
echo ""

# ============================================
# VERIFICA PREREQUISITI
# ============================================

echo "[1/5] Verifica prerequisiti..."

# Verifica JAVA_HOME
if [ -z "$JAVA_HOME" ]; then
    echo ""
    echo "[ERRORE] JAVA_HOME non impostato!"
    echo ""
    echo "Imposta la variabile d'ambiente JAVA_HOME."
    echo "Esempio: export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home"
    echo ""
    exit 1
fi
echo "      JAVA_HOME: $JAVA_HOME"

# Verifica CATALINA_HOME
if [ -z "$CATALINA_HOME" ]; then
    echo ""
    echo "[ERRORE] CATALINA_HOME non impostato!"
    echo ""
    echo "Imposta la variabile d'ambiente CATALINA_HOME."
    echo "Esempio: export CATALINA_HOME=/opt/tomcat"
    echo ""
    exit 1
fi
echo "      CATALINA_HOME: $CATALINA_HOME"

# Verifica Docker
if ! command -v docker &> /dev/null; then
    echo ""
    echo "[ERRORE] Docker non trovato!"
    echo ""
    echo "Installa Docker e riprova."
    echo ""
    exit 1
fi

if ! docker info &> /dev/null; then
    echo ""
    echo "[ERRORE] Docker non avviato!"
    echo ""
    echo "Avvia Docker Desktop e riprova."
    echo ""
    exit 1
fi
echo "      Docker: OK"

echo ""

# ============================================
# FERMA TOMCAT SE IN ESECUZIONE
# ============================================

echo "[2/5] Arresto Tomcat..."
"$CATALINA_HOME/bin/shutdown.sh" &> /dev/null || true
sleep 2
echo "      Tomcat arrestato"
echo ""

# ============================================
# CONFIGURA HTTPS
# ============================================

echo "[3/5] Configurazione HTTPS..."

KEYSTORE_FILE="$CATALINA_HOME/conf/keystore.jks"
SERVER_XML="$CATALINA_HOME/conf/server.xml"

# Genera certificato se non esiste
if [ -f "$KEYSTORE_FILE" ]; then
    echo "      Certificato esistente trovato"
else
    echo "      Generazione certificato SSL..."
    "$JAVA_HOME/bin/keytool" -genkeypair \
        -alias tomcat \
        -keyalg RSA \
        -keysize 2048 \
        -validity 365 \
        -keystore "$KEYSTORE_FILE" \
        -storepass changeit \
        -keypass changeit \
        -dname "CN=localhost, OU=SecureFileShare, O=UniBa, L=Bari, ST=Puglia, C=IT" \
        -ext "SAN=dns:localhost,ip:127.0.0.1" \
        &> /dev/null

    if [ $? -ne 0 ]; then
        echo "[ERRORE] Generazione certificato fallita!"
        exit 1
    fi
    echo "      Certificato generato"
fi

# Configura server.xml - Sovrascrive sempre con configurazione funzionante
echo "      Configurazione server.xml..."

# Backup del file originale (solo la prima volta)
if [ ! -f "$SERVER_XML.original" ]; then
    cp "$SERVER_XML" "$SERVER_XML.original"
fi

# Scrivi server.xml completo con HTTPS configurato
cat > "$SERVER_XML" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Server port="8005" shutdown="SHUTDOWN">
  <Listener className="org.apache.catalina.startup.VersionLoggerListener" />
  <Listener className="org.apache.catalina.core.AprLifecycleListener" />
  <Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />
  <Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener" />
  <Listener className="org.apache.catalina.core.ThreadLocalLeakPreventionListener" />

  <GlobalNamingResources>
    <Resource name="UserDatabase" auth="Container"
              type="org.apache.catalina.UserDatabase"
              description="User database that can be updated and saved"
              factory="org.apache.catalina.users.MemoryUserDatabaseFactory"
              pathname="conf/tomcat-users.xml" />
  </GlobalNamingResources>

  <Service name="Catalina">

    <!-- HTTP Connector -->
    <Connector port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443" />

    <!-- HTTPS Connector - SecureFileShare -->
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true">
        <SSLHostConfig>
            <Certificate certificateKeystoreFile="conf/keystore.jks"
                         certificateKeystorePassword="changeit"
                         certificateKeyAlias="tomcat" type="RSA" />
        </SSLHostConfig>
    </Connector>

    <Engine name="Catalina" defaultHost="localhost">

      <Realm className="org.apache.catalina.realm.LockOutRealm">
        <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
               resourceName="UserDatabase"/>
      </Realm>

      <Host name="localhost" appBase="webapps"
            unpackWARs="true" autoDeploy="true">

        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />

      </Host>
    </Engine>
  </Service>
</Server>
EOF

echo "      HTTPS configurato su porta 8443"

echo ""

# ============================================
# AVVIA DOCKER
# ============================================

echo "[4/5] Avvio servizi Docker..."

docker-compose down &> /dev/null || true
docker-compose up -d

if [ $? -ne 0 ]; then
    echo "[ERRORE] Avvio Docker fallito!"
    exit 1
fi

echo "      Attendo inizializzazione (15 sec)..."
sleep 15
echo "      Vault e MySQL avviati"

echo ""

# ============================================
# DEPLOY WAR
# ============================================

echo "[5/5] Deploy applicazione..."

# Cerca WAR nella cartella corrente o in target
WAR_FILE=""
if [ -f "SecureFileShare.war" ]; then
    WAR_FILE="SecureFileShare.war"
elif [ -f "target/SecureFileShare.war" ]; then
    WAR_FILE="target/SecureFileShare.war"
fi

if [ -z "$WAR_FILE" ]; then
    echo "[ERRORE] File WAR non trovato!"
    echo "         Assicurati che SecureFileShare.war sia presente."
    exit 1
fi

# Rimuovi vecchio deploy
rm -rf "$CATALINA_HOME/webapps/SecureFileShare" 2>/dev/null || true
rm -f "$CATALINA_HOME/webapps/SecureFileShare.war" 2>/dev/null || true

# Copia WAR
cp "$WAR_FILE" "$CATALINA_HOME/webapps/SecureFileShare.war"

if [ $? -ne 0 ]; then
    echo "[ERRORE] Deploy fallito!"
    exit 1
fi

echo "      WAR deployato: $WAR_FILE"

# Avvia Tomcat
echo "      Avvio Tomcat..."
"$CATALINA_HOME/bin/startup.sh" &> /dev/null

echo "      Attendo avvio (10 sec)..."
sleep 10

# ============================================
# COMPLETATO
# ============================================

echo ""
echo "============================================"
echo "  SETUP COMPLETATO!"
echo "============================================"
echo ""
echo "  Applicazione disponibile su:"
echo ""
echo "  https://localhost:8443/SecureFileShare"
echo ""
echo "  NOTA: Il browser mostrera' un avviso"
echo "  sul certificato. Clicca 'Avanzate' e"
echo "  poi 'Procedi comunque'."
echo ""
echo "============================================"
echo ""

# Apri browser
sleep 2
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    open "https://localhost:8443/SecureFileShare"
elif command -v xdg-open &> /dev/null; then
    # Linux
    xdg-open "https://localhost:8443/SecureFileShare"
fi
