package app.security;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Client per comunicazione con HashiCorp Vault.
 * 
 * Gestisce la connessione a Vault e il recupero dei segreti sensibili.
 * 
 * Segreti gestiti (SOLO dati sensibili):
 * - secret/securefileshare/database: credenziali DB (url, username, password)
 * - secret/securefileshare/encryption: chiave AES (aes_key, algorithm, key_size)
 * 
 * Le altre configurazioni sono gestite da variabili d'ambiente (.env).
 * 
 * NON esistono fallback: se Vault non è disponibile o mancano segreti,
 * l'applicazione non parte.
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public final class VaultClient {
    
    // Singleton instance
    private static volatile VaultClient instance;
    
    // Vault connection
    private final Vault vault;
    private final String vaultAddress;
    
    // Cache dei segreti
    private final Map<String, Map<String, String>> secretsCache;
    
    // Paths dei segreti in Vault
    private static final String SECRET_PATH_DATABASE = "secret/data/securefileshare/database";
    private static final String SECRET_PATH_ENCRYPTION = "secret/data/securefileshare/encryption";
    
    /**
     * Costruttore privato (Singleton).
     * 
     * @throws VaultException se VAULT_ADDR o VAULT_TOKEN non sono configurati
     */
    private VaultClient() throws VaultException {
        // VAULT_ADDR obbligatorio
        this.vaultAddress = System.getenv("VAULT_ADDR");
        if (vaultAddress == null || vaultAddress.isEmpty()) {
            throw new VaultException("VAULT_ADDR non configurato! " +
                    "Imposta la variabile d'ambiente VAULT_ADDR (es. http://localhost:8200)");
        }
        
        // VAULT_TOKEN obbligatorio
        String vaultToken = System.getenv("VAULT_TOKEN");
        if (vaultToken == null || vaultToken.isEmpty()) {
            throw new VaultException("VAULT_TOKEN non configurato! " +
                    "Recupera il token con: cat vault/generated-token.txt");
        }
        
        VaultConfig config = new VaultConfig()
                .address(vaultAddress)
                .token(vaultToken)
                .engineVersion(2) // KV v2
                .build();
        
        this.vault = Vault.create(config);
        this.secretsCache = new ConcurrentHashMap<>();
        
        System.out.println("[VaultClient] Connesso a Vault: " + vaultAddress);
    }
    
    /**
     * Ottiene l'istanza singleton del client.
     */
    public static VaultClient getInstance() {
        if (instance == null) {
            synchronized (VaultClient.class) {
                if (instance == null) {
                    try {
                        instance = new VaultClient();
                    } catch (VaultException e) {
                        throw new RuntimeException("Impossibile connettersi a Vault: " + e.getMessage(), e);
                    }
                }
            }
        }
        return instance;
    }

    /**
     * Recupera un segreto da Vault (con caching).
     *
     * @param path il path del segreto
     * @return mappa chiave-valore del segreto
     * @throws VaultException se il segreto non esiste
     */
    private Map<String, String> getSecret(String path) throws VaultException {

        // Cache
        Map<String, String> cached = secretsCache.get(path);
        if (cached != null) {
            return cached;
        }

        LogicalResponse response = vault.logical().read(path);
        if (response == null || response.getData() == null) {
            throw new VaultException("Segreto non trovato: " + path);
        }

        Object dataObj = response.getData().get("data");
        if (!(dataObj instanceof Map)) {
            throw new VaultException("Formato segreto non valido (KV v2 atteso): " + path);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> rawData = (Map<String, Object>) dataObj;

        if (rawData.isEmpty()) {
            throw new VaultException("Segreto vuoto: " + path);
        }

        // Conversione sicura Object → String
        Map<String, String> data = new ConcurrentHashMap<>();
        for (Map.Entry<String, Object> entry : rawData.entrySet()) {
            if (entry.getValue() == null) {
                continue;
            }
            data.put(entry.getKey(), entry.getValue().toString());
        }

        secretsCache.put(path, data);
        return data;
    }

    
    /**
     * Recupera un valore obbligatorio da un segreto.
     */
    private String requireSecretValue(String path, String key) {
        try {
            Map<String, String> secret = getSecret(path);
            String value = secret.get(key);
            if (value == null || value.isEmpty()) {
                throw new RuntimeException("Chiave '" + key + "' mancante in " + path);
            }
            return value;
        } catch (VaultException e) {
            throw new RuntimeException("Errore lettura da Vault: " + e.getMessage(), e);
        }
    }
    
    /**
     * Invalida la cache dei segreti.
     */
    public void invalidateCache() {
        secretsCache.clear();
        System.out.println("[VaultClient] Cache invalidata");
    }
    
    // ========== DATABASE CREDENTIALS ==========
    
    /**
     * @return URL di connessione al database
     */
    public String getDatabaseUrl() {
        return requireSecretValue(SECRET_PATH_DATABASE, "url");
    }
    
    /**
     * @return Username database
     */
    public String getDatabaseUsername() {
        return requireSecretValue(SECRET_PATH_DATABASE, "username");
    }
    
    /**
     * @return Password database
     */
    public String getDatabasePassword() {
        return requireSecretValue(SECRET_PATH_DATABASE, "password");
    }
    
    // ========== ENCRYPTION KEYS ==========
    
    /**
     * @return Chiave AES-256 in Base64
     */
    public String getAesKey() {
        return requireSecretValue(SECRET_PATH_ENCRYPTION, "aes_key");
    }
    
    /**
     * @return Algoritmo di cifratura
     */
    public String getEncryptionAlgorithm() {
        return requireSecretValue(SECRET_PATH_ENCRYPTION, "algorithm");
    }
    
    /**
     * @return Dimensione chiave in bit
     */
    public int getKeySize() {
        String size = requireSecretValue(SECRET_PATH_ENCRYPTION, "key_size");
        return Integer.parseInt(size);
    }
    
    // ========== STATUS ==========
    
    /**
     * Verifica la connessione a Vault.
     * 
     * @return true se Vault è raggiungibile e i segreti sono accessibili
     */
    public boolean isConnected() {
        try {
            getSecret(SECRET_PATH_DATABASE);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * @return Indirizzo Vault configurato
     */
    public String getVaultAddress() {
        return vaultAddress;
    }
}
