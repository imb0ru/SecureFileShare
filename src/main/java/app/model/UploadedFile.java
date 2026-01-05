package app.model;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Rappresenta un file caricato da un utente.
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public class UploadedFile implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private int id;
    private int userId;
    private String originalFilename;
    private String storedFilename;
    private String mimeType;
    private long fileSize;
    private LocalDateTime uploadedAt;
    private String userEmail; // Per visualizzazione
    
    // Costruttore vuoto
    public UploadedFile() {
    }
    
    /**
     * Costruttore completo.
     */
    public UploadedFile(int id, int userId, String originalFilename, 
            String storedFilename, String mimeType, long fileSize) {
        this.id = id;
        this.userId = userId;
        setOriginalFilename(originalFilename);
        setStoredFilename(storedFilename);
        this.mimeType = mimeType;
        this.fileSize = fileSize;
        this.uploadedAt = LocalDateTime.now();
    }
    
    // Getter e Setter
    
    public int getId() {
        return id;
    }
    
    public void setId(int id) {
        this.id = id;
    }
    
    public int getUserId() {
        return userId;
    }
    
    public void setUserId(int userId) {
        this.userId = userId;
    }
    
    public String getOriginalFilename() {
        return originalFilename;
    }
    
    public void setOriginalFilename(String originalFilename) {
        // Sanitizza il nome file per prevenire path traversal
        if (originalFilename != null) {
            this.originalFilename = originalFilename.replaceAll("[^a-zA-Z0-9._-]", "_");
        }
    }
    
    public String getStoredFilename() {
        return storedFilename;
    }
    
    public void setStoredFilename(String storedFilename) {
        this.storedFilename = storedFilename;
    }
    
    public String getMimeType() {
        return mimeType;
    }
    
    public void setMimeType(String mimeType) {
        this.mimeType = mimeType;
    }
    
    public long getFileSize() {
        return fileSize;
    }
    
    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }
    
    public LocalDateTime getUploadedAt() {
        return uploadedAt;
    }
    
    public void setUploadedAt(LocalDateTime uploadedAt) {
        this.uploadedAt = uploadedAt;
    }
    
    public String getUserEmail() {
        return userEmail;
    }
    
    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }
    
    /**
     * Alias per getUserEmail() - usato nella dashboard per mostrare l'autore.
     * @return l'email del proprietario del file
     */
    public String getOwnerEmail() {
        return userEmail;
    }
    
    /**
     * Formatta la dimensione del file in modo leggibile.
     * 
     * @return la dimensione formattata
     */
    public String getFormattedFileSize() {
        if (fileSize < 1024) {
            return fileSize + " B";
        } else if (fileSize < 1024 * 1024) {
            return String.format("%.2f KB", fileSize / 1024.0);
        } else {
            return String.format("%.2f MB", fileSize / (1024.0 * 1024.0));
        }
    }
    
    @Override
    public String toString() {
        return "UploadedFile{id=" + id + ", originalFilename='" + originalFilename + 
               "', userId=" + userId + "}";
    }
}
