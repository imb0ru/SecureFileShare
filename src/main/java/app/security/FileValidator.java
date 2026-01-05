package app.security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import org.apache.tika.Tika;
import org.apache.tika.exception.TikaException;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.sax.BodyContentHandler;

import app.config.AppConfig;

/**
 * Gestisce la validazione sicura dei file caricati.
 * 
 * Implementa le seguenti misure di sicurezza:
 * - Validazione del tipo MIME reale con Apache Tika (non basata su estensione)
 * - Whitelist dei tipi di file consentiti (configurabile)
 * - Analisi del contenuto per rilevare codice malevolo
 * - Generazione di nomi file sicuri (UUID)
 * - Prevenzione TOCTOU attraverso validazione atomica
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public final class FileValidator {
    
    // Istanza Tika per il rilevamento del tipo MIME
    private static final Tika tika = new Tika();
    
    // Pattern per rilevare contenuti potenzialmente malevoli
    private static final Pattern SCRIPT_TAG_PATTERN = Pattern.compile(
        "<script[^>]*>", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern EVENT_HANDLER_PATTERN = Pattern.compile(
        "\\bon[a-z]+\\s*=", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern JAVASCRIPT_URI_PATTERN = Pattern.compile(
        "javascript:", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern EVAL_PATTERN = Pattern.compile(
        "\\beval\\s*\\(", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern PHP_TAG_PATTERN = Pattern.compile(
        "<\\?php|<\\?=", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern HTML_TAG_PATTERN = Pattern.compile(
        "<[a-zA-Z][^>]*>", Pattern.CASE_INSENSITIVE
    );
    
    // Costruttore privato
    private FileValidator() {
        throw new AssertionError("Classe non istanziabile");
    }
    
    // ========== Getter per configurazioni ==========
    
    private static Set<String> getAllowedMimeTypes() {
        return AppConfig.getInstance().getAllowedMimeTypes();
    }
    
    private static Set<String> getAllowedExtensions() {
        return AppConfig.getInstance().getAllowedExtensions();
    }
    
    private static long getMaxFileSize() {
        return AppConfig.getInstance().getMaxFileSize();
    }
    
    /**
     * Risultato della validazione del file.
     */
    public static class FileValidationResult {
        private final boolean valid;
        private final String message;
        private final String detectedMimeType;
        private final String safeFilename;
        
        public FileValidationResult(boolean valid, String message, 
                String detectedMimeType, String safeFilename) {
            this.valid = valid;
            this.message = message;
            this.detectedMimeType = detectedMimeType;
            this.safeFilename = safeFilename;
        }
        
        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
        public String getDetectedMimeType() { return detectedMimeType; }
        public String getSafeFilename() { return safeFilename; }
    }
    
    /**
     * Valida un file caricato verificando tipo MIME, estensione e contenuto.
     * 
     * @param inputStream lo stream del file
     * @param originalFilename il nome originale del file
     * @param fileSize la dimensione del file in byte
     * @return il risultato della validazione
     * @throws IOException se si verifica un errore di I/O
     */
    public static FileValidationResult validateFile(InputStream inputStream, 
            String originalFilename, long fileSize) throws IOException {
        
        // Verifica dimensione
        if (fileSize > getMaxFileSize()) {
            return new FileValidationResult(false, 
                "Il file supera la dimensione massima consentita di 1 MB", 
                null, null);
        }
        
        if (fileSize == 0) {
            return new FileValidationResult(false, 
                "Il file è vuoto", null, null);
        }
        
        // Verifica estensione
        String extension = getFileExtension(originalFilename);
        if (!getAllowedExtensions().contains(extension.toLowerCase())) {
            return new FileValidationResult(false, 
                "Estensione file non consentita. Sono ammessi solo file .txt", 
                null, null);
        }
        
        // Rileva il tipo MIME reale con Tika
        String detectedMimeType;
        try {
            detectedMimeType = tika.detect(inputStream);
        } catch (Exception e) {
            return new FileValidationResult(false, 
                "Il file non può essere elaborato. Assicurati che sia un file di testo valido.", 
                null, null);
        }
        
        // Verifica che il MIME type rilevato sia consentito
        if (!getAllowedMimeTypes().contains(detectedMimeType)) {
            return new FileValidationResult(false, 
                "Il file non sembra essere un documento di testo. Sono ammessi solo file .txt", 
                detectedMimeType, null);
        }
        
        // Genera un nome file sicuro
        String safeFilename = generateSafeFilename(extension);
        
        return new FileValidationResult(true, 
            "File valido", detectedMimeType, safeFilename);
    }
    
    /**
     * Analizza il contenuto del file per rilevare codice potenzialmente malevolo.
     * 
     * @param inputStream lo stream del file
     * @return risultato dell'analisi
     * @throws IOException se si verifica un errore di I/O
     */
    public static ContentAnalysisResult analyzeContent(InputStream inputStream) 
            throws IOException {
        
        StringBuilder contentBuilder = new StringBuilder();
        byte[] buffer = new byte[1024];
        int bytesRead;
        int totalBytes = 0;
        
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            contentBuilder.append(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
            totalBytes += bytesRead;
            
            // Limita la lettura per prevenire DoS
            if (totalBytes > getMaxFileSize()) {
                break;
            }
        }
        
        String content = contentBuilder.toString();
        
        // Verifica la presenza di codice malevolo
        StringBuilder warnings = new StringBuilder();
        boolean hasMaliciousContent = false;
        
        if (SCRIPT_TAG_PATTERN.matcher(content).find()) {
            warnings.append("codice eseguibile, ");
            hasMaliciousContent = true;
        }
        
        if (EVENT_HANDLER_PATTERN.matcher(content).find()) {
            warnings.append("codice interattivo, ");
            hasMaliciousContent = true;
        }
        
        if (JAVASCRIPT_URI_PATTERN.matcher(content).find()) {
            warnings.append("link non sicuri, ");
            hasMaliciousContent = true;
        }
        
        if (EVAL_PATTERN.matcher(content).find()) {
            warnings.append("comandi eseguibili, ");
            hasMaliciousContent = true;
        }
        
        if (PHP_TAG_PATTERN.matcher(content).find()) {
            warnings.append("codice server, ");
            hasMaliciousContent = true;
        }
        
        // Per file di testo puro, anche i tag HTML sono sospetti
        if (HTML_TAG_PATTERN.matcher(content).find()) {
            warnings.append("formattazione HTML, ");
            hasMaliciousContent = true;
        }
        
        if (hasMaliciousContent) {
            // Rimuovi ultima virgola e spazio
            String warningText = warnings.toString().replaceAll(", $", "");
            return new ContentAnalysisResult(false, 
                "Il file contiene elementi non consentiti: " + warningText + 
                ". Carica solo testo semplice senza codice o formattazione.");
        }
        
        return new ContentAnalysisResult(true, "Contenuto sicuro");
    }
    
    /**
     * Risultato dell'analisi del contenuto.
     */
    public static class ContentAnalysisResult {
        private final boolean safe;
        private final String message;
        
        public ContentAnalysisResult(boolean safe, String message) {
            this.safe = safe;
            this.message = message;
        }
        
        public boolean isSafe() { return safe; }
        public String getMessage() { return message; }
    }
    
    /**
     * Estrae l'estensione dal nome del file.
     * 
     * @param filename il nome del file
     * @return l'estensione (incluso il punto) o stringa vuota
     */
    public static String getFileExtension(String filename) {
        if (filename == null || filename.isEmpty()) {
            return "";
        }
        int lastDotIndex = filename.lastIndexOf('.');
        if (lastDotIndex == -1 || lastDotIndex == filename.length() - 1) {
            return "";
        }
        return filename.substring(lastDotIndex).toLowerCase();
    }
    
    /**
     * Genera un nome file sicuro basato su UUID.
     * 
     * @param extension l'estensione da mantenere
     * @return il nome file sicuro
     */
    public static String generateSafeFilename(String extension) {
        return UUID.randomUUID().toString() + extension;
    }
    
    /**
     * Verifica se un'estensione è consentita.
     * 
     * @param extension l'estensione da verificare
     * @return true se consentita
     */
    public static boolean isExtensionAllowed(String extension) {
        return getAllowedExtensions().contains(extension.toLowerCase());
    }
    
    /**
     * Verifica se un tipo MIME è consentito.
     * 
     * @param mimeType il tipo MIME da verificare
     * @return true se consentito
     */
    public static boolean isMimeTypeAllowed(String mimeType) {
        return getAllowedMimeTypes().contains(mimeType);
    }
    
    /**
     * Estrae i metadati dal file usando Apache Tika.
     * 
     * @param inputStream lo stream del file
     * @return i metadati estratti
     * @throws IOException se si verifica un errore di I/O
     * @throws TikaException se si verifica un errore di parsing
     */
    public static Metadata extractMetadata(InputStream inputStream) 
            throws IOException, TikaException {
        
        AutoDetectParser parser = new AutoDetectParser();
        BodyContentHandler handler = new BodyContentHandler();
        Metadata metadata = new Metadata();
        
        try {
            parser.parse(inputStream, handler, metadata);
        } catch (Exception e) {
            // Gestisce errori di parsing senza esporre dettagli
            throw new IOException("Errore durante l'estrazione dei metadati");
        }
        
        return metadata;
    }
}
