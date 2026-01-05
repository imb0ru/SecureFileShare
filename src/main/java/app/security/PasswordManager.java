package app.security;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import app.config.AppConfig;

/**
 * Gestisce l'hashing sicuro delle password utilizzando PBKDF2 con HMAC-SHA256.
 * 
 * I parametri di sicurezza sono configurabili tramite variabili d'ambiente:
 * - PBKDF2_ITERATIONS: numero di iterazioni (default: 310000)
 * - SALT_LENGTH: lunghezza del salt in byte (default: 16)
 * - KEY_LENGTH: lunghezza della chiave in bit (default: 256)
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public final class PasswordManager {
    
    // Algoritmo PBKDF2
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    
    // Costruttore privato per impedire l'istanziazione
    private PasswordManager() {
        throw new AssertionError("Classe non istanziabile");
    }
    
    /**
     * Ottiene il numero di iterazioni dalla configurazione.
     */
    private static int getIterations() {
        return AppConfig.getInstance().getPbkdf2Iterations();
    }
    
    /**
     * Ottiene la lunghezza del salt dalla configurazione.
     */
    private static int getSaltLength() {
        return AppConfig.getInstance().getSaltLength();
    }
    
    /**
     * Ottiene la lunghezza della chiave dalla configurazione.
     */
    private static int getKeyLength() {
        return AppConfig.getInstance().getKeyLength();
    }
    
    /**
     * Genera un salt crittograficamente sicuro.
     * 
     * @return array di byte contenente il salt
     */
    public static byte[] generateSalt() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[getSaltLength()];
        secureRandom.nextBytes(salt);
        return salt;
    }
    
    /**
     * Esegue l'hash della password con PBKDF2.
     * 
     * @param password la password in chiaro (come array di char per sicurezza)
     * @param salt il salt univoco dell'utente
     * @return l'hash della password
     * @throws NoSuchAlgorithmException se l'algoritmo non è disponibile
     * @throws InvalidKeySpecException se la specifica della chiave non è valida
     */
    public static byte[] hashPassword(char[] password, byte[] salt) 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("La password non può essere nulla o vuota");
        }
        if (salt == null || salt.length < getSaltLength()) {
            throw new IllegalArgumentException("Il salt non è valido");
        }
        
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(password, salt, getIterations(), getKeyLength());
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } finally {
            // Pulizia della specifica per rimuovere dati sensibili dalla memoria
            if (spec != null) {
                spec.clearPassword();
            }
        }
    }
    
    /**
     * Verifica se una password corrisponde all'hash memorizzato.
     * 
     * @param password la password da verificare
     * @param salt il salt dell'utente
     * @param storedHash l'hash memorizzato nel database
     * @return true se la password corrisponde, false altrimenti
     */
    public static boolean verifyPassword(char[] password, byte[] salt, byte[] storedHash) {
        if (password == null || salt == null || storedHash == null) {
            return false;
        }
        
        try {
            byte[] computedHash = hashPassword(password, salt);
            // Confronto costante nel tempo per prevenire timing attacks
            boolean result = constantTimeEquals(computedHash, storedHash);
            // Pulizia dell'hash calcolato
            Arrays.fill(computedHash, (byte) 0);
            return result;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // Log dell'errore senza esporre dettagli
            System.err.println("Errore durante la verifica della password");
            return false;
        }
    }
    
    /**
     * Confronto costante nel tempo per prevenire timing attacks.
     * 
     * @param a primo array
     * @param b secondo array
     * @return true se gli array sono uguali
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
    
    /**
     * Codifica un array di byte in stringa Base64.
     * 
     * @param bytes l'array da codificare
     * @return la stringa Base64
     */
    public static String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
    
    /**
     * Decodifica una stringa Base64 in array di byte.
     * 
     * @param encoded la stringa Base64
     * @return l'array di byte decodificato
     */
    public static byte[] decodeBase64(String encoded) {
        return Base64.getDecoder().decode(encoded);
    }
    
    /**
     * Pulisce in modo sicuro un array di caratteri.
     * 
     * @param chars l'array da pulire
     */
    public static void clearCharArray(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }
    
    /**
     * Pulisce in modo sicuro un array di byte.
     * 
     * @param bytes l'array da pulire
     */
    public static void clearByteArray(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
