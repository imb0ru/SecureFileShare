package app.model;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Rappresenta un utente dell'applicazione.
 * 
 * Implementa i principi di programmazione difensiva:
 * - Campi privati con getter/setter controllati
 * - Validazione degli input nei setter
 * - Oggetto immutabile dove possibile
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public class User implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private int id;
    private String email;
    private byte[] passwordHash;
    private byte[] salt;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;
    private boolean active;
    
    // Costruttore vuoto necessario per alcuni framework
    public User() {
        this.active = true;
    }
    
    /**
     * Costruttore completo.
     * 
     * @param id l'ID dell'utente
     * @param email l'email dell'utente
     * @param passwordHash l'hash della password
     * @param salt il salt usato per l'hash
     */
    public User(int id, String email, byte[] passwordHash, byte[] salt) {
        this.id = id;
        setEmail(email);
        setPasswordHash(passwordHash);
        setSalt(salt);
        this.createdAt = LocalDateTime.now();
        this.active = true;
    }
    
    // Getter e Setter con validazione
    
    public int getId() {
        return id;
    }
    
    public void setId(int id) {
        if (id < 0) {
            throw new IllegalArgumentException("L'ID non può essere negativo");
        }
        this.id = id;
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("L'email non può essere vuota");
        }
        this.email = email.toLowerCase().trim();
    }
    
    public byte[] getPasswordHash() {
        // Restituisce una copia per evitare modifiche esterne
        return passwordHash != null ? passwordHash.clone() : null;
    }
    
    public void setPasswordHash(byte[] passwordHash) {
        if (passwordHash == null || passwordHash.length == 0) {
            throw new IllegalArgumentException("L'hash della password non può essere vuoto");
        }
        // Memorizza una copia per evitare modifiche esterne
        this.passwordHash = passwordHash.clone();
    }
    
    public byte[] getSalt() {
        // Restituisce una copia per evitare modifiche esterne
        return salt != null ? salt.clone() : null;
    }
    
    public void setSalt(byte[] salt) {
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Il salt non può essere vuoto");
        }
        // Memorizza una copia per evitare modifiche esterne
        this.salt = salt.clone();
    }
    
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
    
    public LocalDateTime getLastLogin() {
        return lastLogin;
    }
    
    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }
    
    public boolean isActive() {
        return active;
    }
    
    public void setActive(boolean active) {
        this.active = active;
    }
    
    /**
     * Pulisce i dati sensibili dalla memoria.
     * Da chiamare quando l'oggetto non è più necessario.
     */
    public void clearSensitiveData() {
        if (passwordHash != null) {
            java.util.Arrays.fill(passwordHash, (byte) 0);
        }
        if (salt != null) {
            java.util.Arrays.fill(salt, (byte) 0);
        }
    }
    
    @Override
    public String toString() {
        // Non includere dati sensibili nel toString
        return "User{id=" + id + ", email='" + email + "', active=" + active + "}";
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return id == user.id;
    }
    
    @Override
    public int hashCode() {
        return Integer.hashCode(id);
    }
}
