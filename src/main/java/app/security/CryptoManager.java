package app.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Gestisce la cifratura e decifratura dei dati sensibili.
 * 
 * Utilizza AES-256-GCM (Galois/Counter Mode) che fornisce:
 * - Confidenzialità: i dati sono cifrati
 * - Integrità: il tag di autenticazione rileva modifiche
 * - Autenticità: garantisce che i dati provengano dalla fonte corretta
 * 
 * Formato dati cifrati: [IV (12 bytes)][Ciphertext + Auth Tag]
 * 
 * La chiave AES viene recuperata da Vault, non è mai hardcoded.
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public final class CryptoManager {
    
    // Singleton instance
    private static volatile CryptoManager instance;
    
    // Costanti AES-GCM
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;      // 96 bit (raccomandato per GCM)
    private static final int GCM_TAG_LENGTH = 128;    // 128 bit authentication tag
    
    // Chiave AES
    private final SecretKey secretKey;
    
    // Generatore sicuro di IV
    private final SecureRandom secureRandom;
    
    /**
     * Costruttore privato (Singleton).
     * Recupera la chiave AES da Vault.
     */
    private CryptoManager() {
        VaultClient vault = VaultClient.getInstance();
        String base64Key = vault.getAesKey();
        
        if (base64Key == null || base64Key.isEmpty()) {
            throw new RuntimeException("Chiave AES non trovata in Vault. Eseguire init-vault.sh");
        }
        
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        this.secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
        this.secureRandom = new SecureRandom();
        
        System.out.println("[CryptoManager] Inizializzato con chiave AES-256 da Vault");
    }
    
    /**
     * Ottiene l'istanza singleton.
     */
    public static CryptoManager getInstance() {
        if (instance == null) {
            synchronized (CryptoManager.class) {
                if (instance == null) {
                    instance = new CryptoManager();
                }
            }
        }
        return instance;
    }
    
    /**
     * Cifra una stringa.
     * 
     * @param plaintext il testo in chiaro
     * @return il testo cifrato in Base64
     * @throws CryptoException se la cifratura fallisce
     */
    public String encrypt(String plaintext) throws CryptoException {
        if (plaintext == null || plaintext.isEmpty()) {
            return plaintext;
        }
        
        try {
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes = encryptBytes(plaintextBytes);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new CryptoException("Errore durante la cifratura", e);
        }
    }
    
    /**
     * Decifra una stringa.
     * 
     * @param ciphertext il testo cifrato in Base64
     * @return il testo in chiaro
     * @throws CryptoException se la decifratura fallisce
     */
    public String decrypt(String ciphertext) throws CryptoException {
        if (ciphertext == null || ciphertext.isEmpty()) {
            return ciphertext;
        }
        
        try {
            byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
            byte[] decryptedBytes = decryptBytes(ciphertextBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("Errore durante la decifratura", e);
        }
    }
    
    /**
     * Cifra un array di byte.
     * Formato output: [IV (12 bytes)][Ciphertext + Auth Tag]
     * 
     * @param plaintext i dati in chiaro
     * @return i dati cifrati con IV preposto
     * @throws CryptoException se la cifratura fallisce
     */
    public byte[] encryptBytes(byte[] plaintext) throws CryptoException {
        try {
            // Genera IV casuale
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            
            // Configura cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            
            // Cifra
            byte[] ciphertext = cipher.doFinal(plaintext);
            
            // Concatena IV + ciphertext
            ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
            buffer.put(iv);
            buffer.put(ciphertext);
            
            return buffer.array();
        } catch (Exception e) {
            throw new CryptoException("Errore durante la cifratura bytes", e);
        }
    }
    
    /**
     * Decifra un array di byte.
     * Formato input: [IV (12 bytes)][Ciphertext + Auth Tag]
     * 
     * @param ciphertext i dati cifrati con IV preposto
     * @return i dati in chiaro
     * @throws CryptoException se la decifratura fallisce
     */
    public byte[] decryptBytes(byte[] ciphertext) throws CryptoException {
        try {
            // Estrai IV
            ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
            byte[] iv = new byte[GCM_IV_LENGTH];
            buffer.get(iv);
            
            // Estrai ciphertext
            byte[] encryptedData = new byte[buffer.remaining()];
            buffer.get(encryptedData);
            
            // Configura cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            
            // Decifra e verifica tag
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new CryptoException("Errore durante la decifratura bytes", e);
        }
    }
    
    /**
     * Cifra un file (contenuto in byte).
     * 
     * @param fileContent il contenuto del file
     * @return il contenuto cifrato
     * @throws CryptoException se la cifratura fallisce
     */
    public byte[] encryptFile(byte[] fileContent) throws CryptoException {
        return encryptBytes(fileContent);
    }
    
    /**
     * Decifra un file (contenuto in byte).
     * 
     * @param encryptedContent il contenuto cifrato
     * @return il contenuto in chiaro
     * @throws CryptoException se la decifratura fallisce
     */
    public byte[] decryptFile(byte[] encryptedContent) throws CryptoException {
        return decryptBytes(encryptedContent);
    }
    
    /**
     * Verifica che la cifratura funzioni correttamente.
     * Utile per test di integrazione.
     * 
     * @return true se il test passa
     */
    public boolean selfTest() {
        try {
            String testData = "Test di cifratura AES-256-GCM";
            String encrypted = encrypt(testData);
            String decrypted = decrypt(encrypted);
            return testData.equals(decrypted);
        } catch (CryptoException e) {
            System.err.println("[CryptoManager] Self-test fallito: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Eccezione per errori di cifratura/decifratura.
     */
    public static class CryptoException extends Exception {
        private static final long serialVersionUID = 1L;
        
        public CryptoException(String message) {
            super(message);
        }
        
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
