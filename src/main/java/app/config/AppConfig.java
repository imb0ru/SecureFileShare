package app.config;

import app.security.VaultClient;

/**
 * Gestisce le configurazioni dell'applicazione.
 *
 * TUTTE le configurazioni vengono lette da:
 * - File .env (caricato automaticamente da EnvLoader)
 * - Variabili d'ambiente di sistema (hanno priorità sul .env)
 * - HashiCorp Vault (per credenziali DB e chiavi crittografiche)
 *
 * NON esistono fallback o valori di default hardcoded.
 * Se una configurazione manca, l'applicazione non parte.
 * 
 * ORDINE DI RICERCA FILE .env:
 * 1. Path in ENV_FILE_PATH (variabile d'ambiente)
 * 2. Directory corrente (user.dir)
 * 3. ~/.securefileshare/.env
 * 4. $CATALINA_HOME/.env
 * 5. $CATALINA_HOME/webapps/SecureFileShare/.env
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public final class AppConfig {

    private static volatile AppConfig instance;
    private final VaultClient vaultClient;
    private final EnvLoader envLoader;

    /**
     * Costruttore privato per il pattern Singleton.
     */
    private AppConfig() {
        // Carica variabili dal file .env
        this.envLoader = EnvLoader.getInstance();
        envLoader.printDebugInfo();
        
        // Connessione a Vault (OBBLIGATORIA)
        VaultClient tempClient = null;
        try {
            tempClient = VaultClient.getInstance();
            if (!tempClient.isConnected()) {
                throw new IllegalStateException("Vault connesso ma non risponde ai segreti");
            }
        } catch (Exception e) {
            System.err.println("[AppConfig] ╔═══════════════════════════════════════════════════════╗");
            System.err.println("[AppConfig] ║  ERRORE: VAULT NON DISPONIBILE                        ║");
            System.err.println("[AppConfig] ╠═══════════════════════════════════════════════════════╣");
            System.err.println("[AppConfig] ║  L'applicazione richiede Vault per avviarsi.          ║");
            System.err.println("[AppConfig] ║                                                       ║");
            System.err.println("[AppConfig] ║  1. Copia .env.example in .env                        ║");
            System.err.println("[AppConfig] ║  2. Configura VAULT_ADDR e VAULT_TOKEN nel .env       ║");
            System.err.println("[AppConfig] ║  3. Avvia: docker-compose up -d                       ║");
            System.err.println("[AppConfig] ║  4. Recupera token: cat vault/generated-token.txt     ║");
            System.err.println("[AppConfig] ║  5. Inserisci il token nel .env                       ║");
            System.err.println("[AppConfig] ╚═══════════════════════════════════════════════════════╝");
            throw new IllegalStateException("Vault non disponibile: " + e.getMessage(), e);
        }
        this.vaultClient = tempClient;

        // Verifica variabili obbligatorie
        verifyRequiredEnvVars();

        printConfiguration();
    }

    /**
     * Verifica che tutte le variabili d'ambiente obbligatorie siano impostate.
     */
    private void verifyRequiredEnvVars() {
        String[] required = {
                "UPLOAD_DIRECTORY", "UPLOAD_MAX_SIZE",
                "PASSWORD_MIN_LENGTH", "PASSWORD_MAX_LENGTH", "EMAIL_MAX_LENGTH",
                "FILE_ALLOWED_EXTENSIONS", "FILE_ALLOWED_MIMETYPES", "FILE_BUFFER_SIZE",
                "SESSION_TIMEOUT", "COOKIE_SECURE", "COOKIE_HTTPONLY", "COOKIE_SAMESITE",
                "HSTS_ENABLED", "HSTS_MAX_AGE", "HSTS_INCLUDE_SUBDOMAINS",
                "PBKDF2_ITERATIONS", "SALT_LENGTH", "KEY_LENGTH", "NONCE_LENGTH"
        };

        StringBuilder missing = new StringBuilder();
        for (String var : required) {
            if (envLoader.get(var) == null) {
                missing.append("\n  - ").append(var);
            }
        }

        if (!missing.isEmpty()) {
            String envPath = envLoader.getLoadedFilePath();
            throw new IllegalStateException(
                    "Variabili d'ambiente mancanti:" + missing +
                    "\n\nFile .env caricato: " + (envPath != null ? envPath : "NESSUNO") +
                    "\n\nAssicurati che tutte le variabili siano definite nel file .env"
            );
        }
    }

    /**
     * Ottiene l'istanza singleton in modo thread-safe.
     */
    public static AppConfig getInstance() {
        if (instance == null) {
            synchronized (AppConfig.class) {
                if (instance == null) {
                    instance = new AppConfig();
                }
            }
        }
        return instance;
    }

    /**
     * @return true se Vault è disponibile e connesso
     */
    public boolean isVaultAvailable() {
        return vaultClient != null && vaultClient.isConnected();
    }
    
    /**
     * @return il percorso del file .env caricato
     */
    public String getEnvFilePath() {
        return envLoader.getLoadedFilePath();
    }

    // ========== Database (da Vault) ==========

    public String getDbUrl() {
        return vaultClient.getDatabaseUrl();
    }

    public String getDbUser() {
        return vaultClient.getDatabaseUsername();
    }

    public char[] getDbPassword() {
        return vaultClient.getDatabasePassword().toCharArray();
    }

    // ========== Upload (da .env) ==========

    public String getUploadDirectory() {
        String configuredPath = envLoader.require("UPLOAD_DIRECTORY");
        java.io.File file = new java.io.File(configuredPath);

        // Path assoluto
        if (file.isAbsolute()) {
            ensureDirectoryExists(file);
            return file.getAbsolutePath();
        }

        // Path relativo → {user.home}/SecureFileShare/{path}
        String userHome = System.getProperty("user.home");
        file = new java.io.File(userHome, "SecureFileShare/" + configuredPath);
        
        ensureDirectoryExists(file);
        return file.getAbsolutePath();
    }

    private void ensureDirectoryExists(java.io.File dir) {
        if (dir.exists()) {
            if (!dir.isDirectory()) {
                throw new IllegalStateException(
                        "UPLOAD_DIRECTORY non è una directory: " + dir.getAbsolutePath()
                );
            }
            return;
        }

        boolean created = dir.mkdirs();
        if (!created) {
            throw new IllegalStateException(
                    "Impossibile creare la directory di upload: " + dir.getAbsolutePath()
            );
        }

        System.out.println("[AppConfig] Creata directory: " + dir.getAbsolutePath());
    }


    public long getMaxFileSize() {
        return envLoader.requireLong("UPLOAD_MAX_SIZE");
    }

    // ========== Sessione (da .env) ==========

    public int getSessionTimeout() {
        return envLoader.requireInt("SESSION_TIMEOUT");
    }

    // ========== Cookie (da .env) ==========

    public boolean isCookieSecure() {
        return envLoader.requireBoolean("COOKIE_SECURE");
    }

    public boolean isCookieHttpOnly() {
        return envLoader.requireBoolean("COOKIE_HTTPONLY");
    }

    public String getCookieSameSite() {
        return envLoader.require("COOKIE_SAMESITE");
    }

    // ========== HSTS (da .env) ==========

    public boolean isHstsEnabled() {
        return envLoader.requireBoolean("HSTS_ENABLED");
    }

    public int getHstsMaxAge() {
        return envLoader.requireInt("HSTS_MAX_AGE");
    }

    public boolean isHstsIncludeSubDomains() {
        return envLoader.requireBoolean("HSTS_INCLUDE_SUBDOMAINS");
    }

    // ========== Sicurezza Password (da .env) ==========

    public int getPbkdf2Iterations() {
        return envLoader.requireInt("PBKDF2_ITERATIONS");
    }

    public int getSaltLength() {
        return envLoader.requireInt("SALT_LENGTH");
    }

    public int getKeyLength() {
        return envLoader.requireInt("KEY_LENGTH");
    }

    // ========== Validazione Input (da .env) ==========

    public int getPasswordMinLength() {
        return envLoader.requireInt("PASSWORD_MIN_LENGTH");
    }

    public int getPasswordMaxLength() {
        return envLoader.requireInt("PASSWORD_MAX_LENGTH");
    }

    public int getEmailMaxLength() {
        return envLoader.requireInt("EMAIL_MAX_LENGTH");
    }

    // ========== File Upload Whitelist (da .env) ==========

    public java.util.Set<String> getAllowedExtensions() {
        String extensions = envLoader.require("FILE_ALLOWED_EXTENSIONS");
        java.util.Set<String> result = new java.util.HashSet<>();
        for (String ext : extensions.split(",")) {
            String trimmed = ext.trim().toLowerCase();
            if (!trimmed.isEmpty()) {
                if (!trimmed.startsWith(".")) {
                    trimmed = "." + trimmed;
                }
                result.add(trimmed);
            }
        }
        return result;
    }

    public java.util.Set<String> getAllowedMimeTypes() {
        String mimeTypes = envLoader.require("FILE_ALLOWED_MIMETYPES");
        java.util.Set<String> result = new java.util.HashSet<>();
        for (String mime : mimeTypes.split(",")) {
            String trimmed = mime.trim().toLowerCase();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }

    public int getFileBufferSize() {
        return envLoader.requireInt("FILE_BUFFER_SIZE");
    }

    // ========== CSP Nonce (da .env) ==========

    public int getNonceLength() {
        return envLoader.requireInt("NONCE_LENGTH");
    }

    /**
     * Stampa la configurazione corrente (senza dati sensibili).
     */
    public void printConfiguration() {
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║         SecureFileShare - Configurazione                 ║");
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        System.out.println("║ 📄 .env:          " + padRight(envLoader.isEnvFileLoaded() ? "✓ Caricato" : "✗ Non trovato", 39) + "║");
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        System.out.println("║ 🔐 Vault:         " + padRight("CONNESSO", 39) + "║");
        System.out.println("║    Indirizzo:     " + padRight(vaultClient.getVaultAddress(), 39) + "║");
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        System.out.println("║ 🗄️  Database:                                             ║");
        System.out.println("║    URL:           " + padRight(truncate(getDbUrl(), 39), 39) + "║");
        System.out.println("║    User:          " + padRight(getDbUser(), 39) + "║");
        System.out.println("║    Password:      " + padRight("[PROTETTA]", 39) + "║");
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        System.out.println("║ 🔒 Sicurezza:                                             ║");
        System.out.println("║    Cookie Secure:    " + padRight(isCookieSecure() ? "✓" : "✗", 36) + "║");
        System.out.println("║    Cookie HttpOnly:  " + padRight(isCookieHttpOnly() ? "✓" : "✗", 36) + "║");
        System.out.println("║    Cookie SameSite:  " + padRight(getCookieSameSite(), 36) + "║");
        System.out.println("║    HSTS:             " + padRight(isHstsEnabled() ? "✓ (max-age: " + getHstsMaxAge() + ")" : "✗", 36) + "║");
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        System.out.println("║ 📁 Upload:                                                ║");
        System.out.println("║    Directory:     " + padRight(truncate(getUploadDirectory(), 39), 39) + "║");
        System.out.println("║    Max Size:      " + padRight(getMaxFileSize() + " bytes", 39) + "║");
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        System.out.println("║ 🔑 Crittografia:                                          ║");
        System.out.println("║    PBKDF2 Iter:   " + padRight(String.valueOf(getPbkdf2Iterations()), 39) + "║");
        System.out.println("║    Session:       " + padRight(getSessionTimeout() + "s", 39) + "║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
    }

    private String padRight(String s, int n) {
        if (s == null) s = "null";
        return String.format("%-" + n + "s", s);
    }

    private String truncate(String s, int maxLen) {
        if (s == null) return "null";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }
}
