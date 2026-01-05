package app.security;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import app.config.AppConfig;

/**
 * Gestisce il caricamento e l'accesso ai file in modo thread-safe.
 * 
 * Questa classe implementa la gestione concorrente dell'accesso ai file,
 * come richiesto dalla specifica del progetto:
 * 
 * MECCANISMI DI CONCORRENZA UTILIZZATI:
 * 
 * 1. ReentrantReadWriteLock (directoryLock):
 *    - Protegge l'accesso alla directory di upload
 *    - Permette letture multiple simultanee (readLock)
 *    - Garantisce accesso esclusivo per scritture (writeLock)
 *    - Previene race condition durante creazione directory
 * 
 * 2. ConcurrentHashMap (fileLocks):
 *    - Mappa thread-safe per lock sui singoli file
 *    - Ogni file ha il proprio ReentrantReadWriteLock
 *    - Permette operazioni parallele su file diversi
 *    - Previene sovrascritture non intenzionali dello stesso file
 * 
 * 3. ExecutorService (thread pool):
 *    - Gestisce l'elaborazione concorrente dei file
 *    - Limita il numero di thread attivi (basato su CPU disponibili)
 *    - Permette upload asincroni con Future
 * 
 * 4. synchronized (statsLock):
 *    - Protegge il contatore atomico delle statistiche
 *    - Garantisce incrementi thread-safe
 * 
 * SEZIONI CRITICHE PROTETTE:
 * - Creazione directory utente
 * - Scrittura file su filesystem
 * - Lettura file da filesystem
 * - Eliminazione file
 * - Aggiornamento statistiche
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public class ConcurrentFileManager {
    
    // Lock per la directory di upload
    private final ReentrantReadWriteLock directoryLock = new ReentrantReadWriteLock();
    private final Lock readLock = directoryLock.readLock();
    private final Lock writeLock = directoryLock.writeLock();
    
    // Mappa thread-safe per i lock sui singoli file
    // Protetta dalla sua stessa struttura thread-safe (ConcurrentHashMap)
    private final ConcurrentHashMap<String, ReentrantReadWriteLock> fileLocks = 
            new ConcurrentHashMap<>();
    
    // Thread pool per operazioni I/O
    private final ExecutorService executorService;
    
    // Directory di upload
    private final String uploadDirectory;
    
    // Contatore atomico per statistiche - protetto da statsLock
    private int totalUploads = 0;
    private final Object statsLock = new Object();
    
    /**
     * Ottiene la dimensione del buffer per I/O da configurazione.
     */
    private int getBufferSize() {
        return AppConfig.getInstance().getFileBufferSize();
    }
    
    /**
     * Costruttore con directory di upload specificata.
     * 
     * @param uploadDirectory la directory di destinazione per i file
     */
    public ConcurrentFileManager(String uploadDirectory) {
        this.uploadDirectory = uploadDirectory;
        this.executorService = Executors.newFixedThreadPool(
            Math.max(2, Runtime.getRuntime().availableProcessors())
        );
        
        // Crea la directory se non esiste
        initializeDirectory();
    }
    
    /**
     * Inizializza la directory di upload in modo thread-safe.
     */
    private void initializeDirectory() {
        writeLock.lock();
        try {
            File dir = new File(uploadDirectory);
            if (!dir.exists()) {
                boolean created = dir.mkdirs();
                if (!created) {
                    throw new RuntimeException("Impossibile creare la directory di upload");
                }
            }
        } finally {
            writeLock.unlock();
        }
    }
    
    /**
     * Salva un file in modo thread-safe CON CIFRATURA AES-256-GCM.
     * 
     * Il file viene cifrato prima di essere salvato su disco.
     * La chiave AES è recuperata da Vault.
     * 
     * @param inputStream lo stream del file da salvare
     * @param filename il nome del file (già sanitizzato)
     * @param userId l'ID dell'utente proprietario
     * @return il path del file salvato
     * @throws IOException se si verifica un errore di I/O
     */
    public String saveFileThreadSafe(InputStream inputStream, String filename, int userId) 
            throws IOException {
        
        // Ottieni o crea il lock per questo file
        ReentrantReadWriteLock fileLock = fileLocks.computeIfAbsent(
            filename, k -> new ReentrantReadWriteLock()
        );
        
        // Acquisisci il write lock per questo file
        fileLock.writeLock().lock();
        
        try {
            // Acquisisci anche il read lock della directory
            readLock.lock();
            try {
                String userDirectory = uploadDirectory + File.separator + userId;
                
                // Crea la directory dell'utente se non esiste
                File userDir = new File(userDirectory);
                if (!userDir.exists()) {
                    // Per creare la directory, serve il write lock
                    readLock.unlock();
                    writeLock.lock();
                    try {
                        if (!userDir.exists()) {
                            userDir.mkdirs();
                        }
                    } finally {
                        writeLock.unlock();
                        readLock.lock();
                    }
                }
                
                // Leggi tutto il contenuto in memoria per la cifratura
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                byte[] buffer = new byte[getBufferSize()];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                byte[] plainContent = baos.toByteArray();
                
                // CIFRA il contenuto con AES-256-GCM
                byte[] encryptedContent;
                try {
                    CryptoManager crypto = CryptoManager.getInstance();
                    encryptedContent = crypto.encryptFile(plainContent);
                    System.out.println("[ConcurrentFileManager] File cifrato: " + filename + 
                            " (" + plainContent.length + " -> " + encryptedContent.length + " bytes)");
                } catch (CryptoManager.CryptoException e) {
                    throw new IOException("Errore cifratura file: " + e.getMessage(), e);
                }
                
                // Salva il file CIFRATO (con estensione .enc)
                File destFile = new File(userDir, filename + ".enc");
                
                try (FileOutputStream fos = new FileOutputStream(destFile)) {
                    fos.write(encryptedContent);
                    fos.flush();
                }
                
                // Aggiorna statistiche
                incrementUploadCount();
                
                return destFile.getAbsolutePath();
                
            } finally {
                readLock.unlock();
            }
        } finally {
            fileLock.writeLock().unlock();
            // Rimuovi il lock se non ci sono più riferimenti
            fileLocks.remove(filename, fileLock);
        }
    }
    
    /**
     * Legge un file in modo thread-safe CON DECIFRATURA AES-256-GCM.
     * 
     * Il file viene decifrato dopo essere letto da disco.
     * 
     * @param filename il nome del file
     * @param userId l'ID dell'utente proprietario
     * @return il contenuto del file DECIFRATO come byte array
     * @throws IOException se si verifica un errore di I/O
     */
    public byte[] readFileThreadSafe(String filename, int userId) throws IOException {
        
        ReentrantReadWriteLock fileLock = fileLocks.computeIfAbsent(
            filename, k -> new ReentrantReadWriteLock()
        );
        
        // Acquisisci il read lock per questo file
        fileLock.readLock().lock();
        
        try {
            readLock.lock();
            try {
                // I file sono salvati con estensione .enc
                String filePath = uploadDirectory + File.separator + userId + 
                                  File.separator + filename + ".enc";
                Path path = Paths.get(filePath);
                
                if (!Files.exists(path)) {
                    throw new IOException("File non trovato");
                }
                
                // Leggi il contenuto CIFRATO
                byte[] encryptedContent = Files.readAllBytes(path);
                
                // DECIFRA il contenuto
                try {
                    CryptoManager crypto = CryptoManager.getInstance();
                    byte[] decryptedContent = crypto.decryptFile(encryptedContent);
                    System.out.println("[ConcurrentFileManager] File decifrato: " + filename + 
                            " (" + encryptedContent.length + " -> " + decryptedContent.length + " bytes)");
                    return decryptedContent;
                } catch (CryptoManager.CryptoException e) {
                    throw new IOException("Errore decifratura file: " + e.getMessage(), e);
                }
                
            } finally {
                readLock.unlock();
            }
        } finally {
            fileLock.readLock().unlock();
        }
    }
    
    /**
     * Elimina un file in modo thread-safe.
     * 
     * @param filename il nome del file
     * @param userId l'ID dell'utente proprietario
     * @return true se il file è stato eliminato
     */
    public boolean deleteFileThreadSafe(String filename, int userId) {
        
        ReentrantReadWriteLock fileLock = fileLocks.computeIfAbsent(
            filename, k -> new ReentrantReadWriteLock()
        );
        
        fileLock.writeLock().lock();
        
        try {
            writeLock.lock();
            try {
                // I file sono salvati con estensione .enc
                String filePath = uploadDirectory + File.separator + userId + 
                                  File.separator + filename + ".enc";
                File file = new File(filePath);
                
                if (file.exists()) {
                    boolean deleted = file.delete();
                    if (deleted) {
                        System.out.println("[ConcurrentFileManager] File eliminato: " + filename);
                    }
                    return deleted;
                }
                return false;
                
            } finally {
                writeLock.unlock();
            }
        } finally {
            fileLock.writeLock().unlock();
            fileLocks.remove(filename);
        }
    }
    
    /**
     * Salva un file in modo asincrono.
     * 
     * @param inputStream lo stream del file
     * @param filename il nome del file
     * @param userId l'ID dell'utente
     * @return un Future con il percorso del file salvato
     */
    public Future<String> saveFileAsync(InputStream inputStream, String filename, int userId) {
        return executorService.submit(() -> saveFileThreadSafe(inputStream, filename, userId));
    }
    
    /**
     * Verifica se un file esiste in modo thread-safe.
     * 
     * @param filename il nome del file
     * @param userId l'ID dell'utente
     * @return true se il file esiste
     */
    public boolean fileExists(String filename, int userId) {
        readLock.lock();
        try {
            // I file sono salvati con estensione .enc
            String filePath = uploadDirectory + File.separator + userId + 
                              File.separator + filename + ".enc";
            return new File(filePath).exists();
        } finally {
            readLock.unlock();
        }
    }
    
    /**
     * Lista i file di un utente in modo thread-safe.
     * Rimuove l'estensione .enc dai nomi restituiti.
     * 
     * @param userId l'ID dell'utente
     * @return array di nomi file (senza .enc)
     */
    public String[] listUserFiles(int userId) {
        readLock.lock();
        try {
            String userDirectory = uploadDirectory + File.separator + userId;
            File userDir = new File(userDirectory);
            
            if (!userDir.exists() || !userDir.isDirectory()) {
                return new String[0];
            }
            
            String[] encryptedFiles = userDir.list();
            if (encryptedFiles == null) {
                return new String[0];
            }
            
            // Rimuovi l'estensione .enc dai nomi
            return java.util.Arrays.stream(encryptedFiles)
                    .filter(f -> f.endsWith(".enc"))
                    .map(f -> f.substring(0, f.length() - 4)) // rimuove ".enc"
                    .toArray(String[]::new);
            
        } finally {
            readLock.unlock();
        }
    }
    
    /**
     * Ottiene il contenuto di un file come stringa (per file di testo).
     * 
     * @param filename il nome del file
     * @param userId l'ID dell'utente
     * @return il contenuto del file
     * @throws IOException se si verifica un errore
     */
    public String readFileContentAsString(String filename, int userId) throws IOException {
        byte[] content = readFileThreadSafe(filename, userId);
        return new String(content, java.nio.charset.StandardCharsets.UTF_8);
    }
    
    /**
     * Incrementa il contatore di upload in modo thread-safe.
     */
    private void incrementUploadCount() {
        synchronized (statsLock) {
            totalUploads++;
        }
    }
    
    /**
     * Ottiene il numero totale di upload.
     * 
     * @return il numero di upload
     */
    public int getTotalUploads() {
        synchronized (statsLock) {
            return totalUploads;
        }
    }
    
    /**
     * Arresta il thread pool in modo ordinato.
     */
    public void shutdown() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Ottiene la directory di upload.
     * 
     * @return il percorso della directory
     */
    public String getUploadDirectory() {
        return uploadDirectory;
    }
}
