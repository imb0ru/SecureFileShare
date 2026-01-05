@echo off
REM ============================================
REM SecureFileShare - Setup Automatico
REM ============================================
REM Università degli Studi di Bari "Aldo Moro"
REM Sicurezza nelle Applicazioni 2025/2026
REM ============================================
REM
REM Questo script configura e avvia l'applicazione:
REM 1. Genera certificato HTTPS (se non presente)
REM 2. Configura Tomcat per HTTPS (se necessario)
REM 3. Avvia Vault e MySQL (Docker)
REM 4. Deploya il WAR in Tomcat
REM 5. Avvia Tomcat
REM
REM ============================================

setlocal enabledelayedexpansion

echo.
echo ============================================
echo   SecureFileShare - Setup Automatico
echo ============================================
echo.

REM ============================================
REM VERIFICA PREREQUISITI
REM ============================================

echo [1/5] Verifica prerequisiti...

REM Verifica JAVA_HOME
if "%JAVA_HOME%"=="" (
    echo.
    echo [ERRORE] JAVA_HOME non impostato!
    echo.
    echo Imposta la variabile d'ambiente JAVA_HOME.
    echo Esempio: set JAVA_HOME=C:\Program Files\Java\jdk-17
    echo.
    goto :error
)
echo       JAVA_HOME: %JAVA_HOME%

REM Verifica CATALINA_HOME
if "%CATALINA_HOME%"=="" (
    echo.
    echo [ERRORE] CATALINA_HOME non impostato!
    echo.
    echo Imposta la variabile d'ambiente CATALINA_HOME.
    echo Esempio: set CATALINA_HOME=C:\apache-tomcat-11.0.0
    echo.
    goto :error
)
echo       CATALINA_HOME: %CATALINA_HOME%

REM Verifica Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERRORE] Docker non trovato o non avviato!
    echo.
    echo Avvia Docker Desktop e riprova.
    echo.
    goto :error
)
echo       Docker: OK

echo.

REM ============================================
REM FERMA TOMCAT SE IN ESECUZIONE
REM ============================================

echo [2/5] Arresto Tomcat...
call "%CATALINA_HOME%\bin\shutdown.bat" >nul 2>&1
timeout /t 2 /nobreak >nul
echo       Tomcat arrestato
echo.

REM ============================================
REM CONFIGURA HTTPS
REM ============================================

echo [3/5] Configurazione HTTPS...

set KEYSTORE_FILE=%CATALINA_HOME%\conf\keystore.jks
set SERVER_XML=%CATALINA_HOME%\conf\server.xml

REM Genera certificato se non esiste
if exist "%KEYSTORE_FILE%" (
    echo       Certificato esistente trovato
) else (
    echo       Generazione certificato SSL...
    "%JAVA_HOME%\bin\keytool" -genkeypair ^
        -alias tomcat ^
        -keyalg RSA ^
        -keysize 2048 ^
        -validity 365 ^
        -keystore "%KEYSTORE_FILE%" ^
        -storepass changeit ^
        -keypass changeit ^
        -dname "CN=localhost, OU=SecureFileShare, O=UniBa, L=Bari, ST=Puglia, C=IT" ^
        -ext "SAN=dns:localhost,ip:127.0.0.1" ^
        >nul 2>&1

    if errorlevel 1 (
        echo [ERRORE] Generazione certificato fallita!
        goto :error
    )
    echo       Certificato generato
)

REM Configura server.xml - Sovrascrive sempre con configurazione funzionante
echo       Configurazione server.xml...

REM Backup del file originale (solo la prima volta)
if not exist "%SERVER_XML%.original" (
    copy "%SERVER_XML%" "%SERVER_XML%.original" >nul
)

REM Scrivi server.xml - ogni riga contiene un elemento XML completo
echo ^<?xml version="1.0" encoding="UTF-8"?^> > "%SERVER_XML%"
echo ^<Server port="8005" shutdown="SHUTDOWN"^> >> "%SERVER_XML%"
echo   ^<Listener className="org.apache.catalina.startup.VersionLoggerListener" /^> >> "%SERVER_XML%"
echo   ^<Listener className="org.apache.catalina.core.AprLifecycleListener" /^> >> "%SERVER_XML%"
echo   ^<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" /^> >> "%SERVER_XML%"
echo   ^<Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener" /^> >> "%SERVER_XML%"
echo   ^<Listener className="org.apache.catalina.core.ThreadLocalLeakPreventionListener" /^> >> "%SERVER_XML%"
echo   ^<GlobalNamingResources^> >> "%SERVER_XML%"
echo     ^<Resource name="UserDatabase" auth="Container" type="org.apache.catalina.UserDatabase" factory="org.apache.catalina.users.MemoryUserDatabaseFactory" pathname="conf/tomcat-users.xml" /^> >> "%SERVER_XML%"
echo   ^</GlobalNamingResources^> >> "%SERVER_XML%"
echo   ^<Service name="Catalina"^> >> "%SERVER_XML%"
echo     ^<Connector port="8080" protocol="HTTP/1.1" connectionTimeout="20000" redirectPort="8443" /^> >> "%SERVER_XML%"
echo     ^<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" maxThreads="150" SSLEnabled="true" scheme="https" secure="true"^> >> "%SERVER_XML%"
echo       ^<SSLHostConfig^> >> "%SERVER_XML%"
echo         ^<Certificate certificateKeystoreFile="conf/keystore.jks" certificateKeystorePassword="changeit" certificateKeyAlias="tomcat" type="RSA" /^> >> "%SERVER_XML%"
echo       ^</SSLHostConfig^> >> "%SERVER_XML%"
echo     ^</Connector^> >> "%SERVER_XML%"
echo     ^<Engine name="Catalina" defaultHost="localhost"^> >> "%SERVER_XML%"
echo       ^<Realm className="org.apache.catalina.realm.LockOutRealm"^> >> "%SERVER_XML%"
echo         ^<Realm className="org.apache.catalina.realm.UserDatabaseRealm" resourceName="UserDatabase" /^> >> "%SERVER_XML%"
echo       ^</Realm^> >> "%SERVER_XML%"
echo       ^<Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true"^> >> "%SERVER_XML%"
echo         ^<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs" prefix="localhost_access_log" suffix=".txt" pattern="%%h %%l %%u %%t %%r %%s %%b" /^> >> "%SERVER_XML%"
echo       ^</Host^> >> "%SERVER_XML%"
echo     ^</Engine^> >> "%SERVER_XML%"
echo   ^</Service^> >> "%SERVER_XML%"
echo ^</Server^> >> "%SERVER_XML%"

echo       HTTPS configurato su porta 8443

:dopo_https

echo.

REM ============================================
REM AVVIA DOCKER
REM ============================================

echo [4/5] Avvio servizi Docker...

docker-compose down >nul 2>&1
docker-compose up -d

if errorlevel 1 (
    echo [ERRORE] Avvio Docker fallito!
    goto :error
)

echo       Attendo inizializzazione (15 sec)...
timeout /t 15 /nobreak >nul
echo       Vault e MySQL avviati

echo.

REM ============================================
REM DEPLOY WAR
REM ============================================

echo [5/5] Deploy applicazione...

REM Cerca WAR nella cartella corrente o in target
set WAR_FILE=
if exist "SecureFileShare.war" (
    set WAR_FILE=SecureFileShare.war
) else if exist "target\SecureFileShare.war" (
    set WAR_FILE=target\SecureFileShare.war
)

if "%WAR_FILE%"=="" (
    echo [ERRORE] File WAR non trovato!
    echo          Assicurati che SecureFileShare.war sia presente.
    goto :error
)

REM Rimuovi vecchio deploy
if exist "%CATALINA_HOME%\webapps\SecureFileShare" (
    rmdir /s /q "%CATALINA_HOME%\webapps\SecureFileShare" >nul 2>&1
)
if exist "%CATALINA_HOME%\webapps\SecureFileShare.war" (
    del /f "%CATALINA_HOME%\webapps\SecureFileShare.war" >nul 2>&1
)

REM Copia WAR
copy /y "%WAR_FILE%" "%CATALINA_HOME%\webapps\SecureFileShare.war" >nul

if errorlevel 1 (
    echo [ERRORE] Deploy fallito!
    goto :error
)

echo       WAR deployato: %WAR_FILE%

REM Avvia Tomcat
echo       Avvio Tomcat...
start "" "%CATALINA_HOME%\bin\startup.bat"

echo       Attendo avvio (10 sec)...
timeout /t 10 /nobreak >nul

REM ============================================
REM COMPLETATO
REM ============================================

echo.
echo ============================================
echo   SETUP COMPLETATO!
echo ============================================
echo.
echo   Applicazione disponibile su:
echo.
echo   https://localhost:8443/SecureFileShare
echo.
echo   NOTA: Il browser mostrera' un avviso
echo   sul certificato. Clicca "Avanzate" e
echo   poi "Procedi comunque".
echo.
echo ============================================
echo.

REM Apri browser
timeout /t 2 /nobreak >nul
start "" "https://localhost:8443/SecureFileShare"

goto :end

:error
echo.
echo ============================================
echo   SETUP FALLITO
echo ============================================
echo.
echo Verifica i prerequisiti e riprova.
echo Consulta README.md per maggiori dettagli.
echo.
pause
exit /b 1

:end
pause
