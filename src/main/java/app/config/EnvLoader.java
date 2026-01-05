package app.config;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Carica le variabili d'ambiente dal file .env.
 * 
 * Ordine di ricerca del file .env:
 * 1. Path specificato nella variabile d'ambiente ENV_FILE_PATH
 * 2. $CATALINA_HOME/webapps/SecureFileShare/.env (directory webapp)
 * 3. $CATALINA_HOME/.env (home Tomcat)
 * 4. Directory corrente di lavoro
 * 
 * Priorità valori:
 * 1. Variabile d'ambiente di sistema (se esiste)
 * 2. Valore dal file .env
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public final class EnvLoader {
    
    private static volatile EnvLoader instance;
    private final Map<String, String> envVariables;
    private final String loadedFromPath;
    
    /**
     * Costruttore privato (Singleton).
     */
    private EnvLoader() {
        this.envVariables = new HashMap<>();
        this.loadedFromPath = loadEnvFile();
    }
    
    /**
     * Ottiene l'istanza singleton.
     */
    public static EnvLoader getInstance() {
        if (instance == null) {
            synchronized (EnvLoader.class) {
                if (instance == null) {
                    instance = new EnvLoader();
                }
            }
        }
        return instance;
    }
    
    /**
     * Cerca e carica il file .env.
     * 
     * @return il percorso del file caricato, o null se non trovato
     */
    private String loadEnvFile() {
        String catalinaHome = System.getenv("CATALINA_HOME");
        
        // Lista di possibili percorsi per il file .env
        String[] possiblePaths = {
            // 1. Path esplicito da variabile d'ambiente
            System.getenv("ENV_FILE_PATH"),
            
            // 2. Directory webapp (dopo deploy)
            catalinaHome != null 
                ? catalinaHome + File.separator + "webapps" + File.separator + "SecureFileShare" + File.separator + ".env" 
                : null,
                
            // 3. Home Tomcat
            catalinaHome != null 
                ? catalinaHome + File.separator + ".env" 
                : null,
                
            // 4. Directory corrente
            System.getProperty("user.dir") + File.separator + ".env"
        };
        
        for (String path : possiblePaths) {
            if (path == null || path.isEmpty()) {
                continue;
            }
            
            File envFile = new File(path);
            if (envFile.exists() && envFile.isFile() && envFile.canRead()) {
                try {
                    loadFromFile(envFile);
                    System.out.println("[EnvLoader] ✓ Caricato .env da: " + envFile.getAbsolutePath());
                    return envFile.getAbsolutePath();
                } catch (IOException e) {
                    System.err.println("[EnvLoader] Errore lettura " + path + ": " + e.getMessage());
                }
            }
        }
        
        // Se non trovato, stampa dove ha cercato
        System.err.println("[EnvLoader] ⚠ File .env non trovato!");
        System.err.println("[EnvLoader] Percorsi cercati:");
        for (String path : possiblePaths) {
            if (path != null) {
                System.err.println("[EnvLoader]   - " + path);
            }
        }
        System.err.println("[EnvLoader] Copia il file .env nella directory dell'applicazione.");
        
        return null;
    }
    
    /**
     * Carica le variabili da un file .env.
     * 
     * Formato supportato:
     * - KEY=value
     * - KEY="value with spaces"
     * - KEY='value with spaces'
     * - # commenti
     * - Linee vuote ignorate
     * 
     * @param file il file .env da caricare
     * @throws IOException se la lettura fallisce
     */
    private void loadFromFile(File file) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            int lineNumber = 0;
            
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                
                // Ignora linee vuote e commenti
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                // Trova il primo '='
                int equalsIndex = line.indexOf('=');
                if (equalsIndex <= 0) {
                    continue;
                }
                
                String key = line.substring(0, equalsIndex).trim();
                String value = line.substring(equalsIndex + 1).trim();
                
                // Rimuovi virgolette se presenti
                if ((value.startsWith("\"") && value.endsWith("\"")) ||
                    (value.startsWith("'") && value.endsWith("'"))) {
                    value = value.substring(1, value.length() - 1);
                }
                
                // Valida il nome della variabile
                if (isValidEnvName(key)) {
                    envVariables.put(key, value);
                }
            }
        }
    }
    
    /**
     * Verifica che il nome della variabile sia valido.
     */
    private boolean isValidEnvName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        char first = name.charAt(0);
        if (!Character.isLetter(first) && first != '_') {
            return false;
        }
        for (int i = 1; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_') {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Ottiene una variabile d'ambiente.
     * Priorità: System.getenv() > file .env
     */
    public String get(String name) {
        String systemValue = System.getenv(name);
        if (systemValue != null && !systemValue.isEmpty()) {
            return systemValue;
        }
        return envVariables.get(name);
    }
    
    /**
     * Ottiene una variabile d'ambiente obbligatoria.
     */
    public String require(String name) {
        String value = get(name);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalStateException(
                "Variabile richiesta non trovata: " + name + "\n" +
                "File .env: " + (loadedFromPath != null ? loadedFromPath : "NON TROVATO")
            );
        }
        return value.trim();
    }
    
    /**
     * Ottiene una variabile come intero.
     */
    public int requireInt(String name) {
        String value = require(name);
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Variabile " + name + " non è un intero: " + value);
        }
    }
    
    /**
     * Ottiene una variabile come long.
     */
    public long requireLong(String name) {
        String value = require(name);
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Variabile " + name + " non è un numero: " + value);
        }
    }
    
    /**
     * Ottiene una variabile come boolean.
     */
    public boolean requireBoolean(String name) {
        String value = require(name).toLowerCase();
        return "true".equals(value) || "1".equals(value) || "yes".equals(value);
    }
    
    /**
     * @return il percorso del file .env caricato, o null
     */
    public String getLoadedFilePath() {
        return loadedFromPath;
    }
    
    /**
     * @return true se un file .env è stato caricato
     */
    public boolean isEnvFileLoaded() {
        return loadedFromPath != null;
    }
    
    /**
     * Stampa informazioni di debug.
     */
    public void printDebugInfo() {
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║              EnvLoader - Configurazione                  ║");
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        if (loadedFromPath != null) {
            System.out.println("║ 📄 .env: ✓ Caricato                                      ║");
            System.out.println("║    " + padRight(truncate(loadedFromPath, 54), 54) + "║");
        } else {
            System.out.println("║ 📄 .env: ✗ NON TROVATO                                   ║");
        }
        System.out.println("║ 📊 Variabili caricate: " + padRight(String.valueOf(envVariables.size()), 33) + "║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
    }
    
    private String padRight(String s, int n) {
        if (s == null) s = "null";
        return String.format("%-" + n + "s", s);
    }
    
    private String truncate(String s, int maxLen) {
        if (s == null) return "null";
        if (s.length() <= maxLen) return s;
        return "..." + s.substring(s.length() - maxLen + 3);
    }
}
