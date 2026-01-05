package app.security;

import java.util.regex.Pattern;

import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;

import app.config.AppConfig;

/**
 * Gestisce la validazione e sanitizzazione degli input utente.
 * 
 * Implementa le seguenti misure di sicurezza:
 * - Validazione email con regex robusta
 * - Validazione password con policy di sicurezza (configurabile)
 * - Valutazione forza password con zxcvbn (libreria Dropbox)
 * - Sanitizzazione output per prevenzione XSS
 * - Whitelisting per i tipi di input consentiti
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public final class InputValidator {
    
    // Pattern per validazione email (RFC 5322 semplificato)
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );
    
    // Istanza zxcvbn per valutazione forza password (thread-safe)
    private static final Zxcvbn zxcvbn = new Zxcvbn();
    
    // Soglia minima di forza password (0-4, dove 2 = "discreta")
    private static final int MIN_PASSWORD_STRENGTH = 2;
    
    // Costruttore privato
    private InputValidator() {
        throw new AssertionError("Classe non istanziabile");
    }
    
    // ========== Getter per configurazioni ==========
    
    private static int getMinPasswordLength() {
        return AppConfig.getInstance().getPasswordMinLength();
    }
    
    private static int getMaxPasswordLength() {
        return AppConfig.getInstance().getPasswordMaxLength();
    }
    
    private static int getMaxEmailLength() {
        return AppConfig.getInstance().getEmailMaxLength();
    }
    
    /**
     * Valida un indirizzo email.
     * 
     * @param email l'email da validare
     * @return true se l'email è valida
     */
    public static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }
        if (email.length() > getMaxEmailLength()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email).matches();
    }
    
    /**
     * Valida una password secondo la policy di sicurezza.
     * 
     * Combina controlli strutturali (requisiti base) con valutazione
     * della forza tramite zxcvbn che rileva:
     * - Password comuni (dizionari, leak noti)
     * - Pattern deboli (sequenze, ripetizioni, date, nomi)
     * - Keyboard patterns (qwerty, etc.)
     * 
     * Policy requisiti base:
     * - Lunghezza minima configurabile (default 12)
     * - Almeno una lettera maiuscola
     * - Almeno una lettera minuscola
     * - Almeno un numero
     * - Almeno un carattere speciale
     * 
     * @param password la password da validare
     * @return risultato della validazione con eventuale messaggio di errore
     */
    public static ValidationResult validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            return new ValidationResult(false, "La password non può essere vuota", 0);
        }
        
        if (password.length() < getMinPasswordLength()) {
            return new ValidationResult(false, 
                "La password deve contenere almeno " + getMinPasswordLength() + " caratteri", 0);
        }
        
        if (password.length() > getMaxPasswordLength()) {
            return new ValidationResult(false, 
                "La password non può superare " + getMaxPasswordLength() + " caratteri", 0);
        }
        
        // Verifica requisiti strutturali
        if (!password.matches(".*[A-Z].*")) {
            return new ValidationResult(false, 
                "La password deve contenere almeno una lettera maiuscola", 0);
        }
        
        if (!password.matches(".*[a-z].*")) {
            return new ValidationResult(false, 
                "La password deve contenere almeno una lettera minuscola", 0);
        }
        
        if (!password.matches(".*[0-9].*")) {
            return new ValidationResult(false, 
                "La password deve contenere almeno un numero", 0);
        }
        
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            return new ValidationResult(false, 
                "La password deve contenere almeno un carattere speciale", 0);
        }
        
        // Valutazione forza con zxcvbn
        Strength strength = zxcvbn.measure(password);
        int score = strength.getScore(); // 0-4
        
        // Se la password è troppo debole secondo zxcvbn
        if (score < MIN_PASSWORD_STRENGTH) {
            // Ottieni il feedback da zxcvbn
            String warning = strength.getFeedback().getWarning();
            String suggestion = "";
            if (strength.getFeedback().getSuggestions() != null && 
                !strength.getFeedback().getSuggestions().isEmpty()) {
                suggestion = strength.getFeedback().getSuggestions().get(0);
            }
            
            // Costruisci messaggio di errore
            StringBuilder message = new StringBuilder("La password è troppo debole");
            if (warning != null && !warning.isEmpty()) {
                message.append(": ").append(translateWarning(warning));
            } else if (!suggestion.isEmpty()) {
                message.append(". ").append(translateSuggestion(suggestion));
            }
            
            return new ValidationResult(false, message.toString(), score);
        }
        
        return new ValidationResult(true, "Password valida", score);
    }
    
    /**
     * Valuta la forza di una password senza validare i requisiti.
     * Utile per il feedback in tempo reale nel frontend.
     * 
     * @param password la password da valutare
     * @return risultato con score (0-4) e livello (WEAK/FAIR/GOOD/STRONG)
     */
    public static PasswordStrength getPasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return new PasswordStrength(0, StrengthLevel.WEAK, "Inserisci una password");
        }
        
        Strength strength = zxcvbn.measure(password);
        int score = strength.getScore();
        
        StrengthLevel level;
        String message;
        
        switch (score) {
            case 0:
                level = StrengthLevel.WEAK;
                message = "Molto debole - facilmente indovinabile";
                break;
            case 1:
                level = StrengthLevel.WEAK;
                message = "Debole - vulnerabile ad attacchi";
                break;
            case 2:
                level = StrengthLevel.FAIR;
                message = "Discreta - potrebbe essere più sicura";
                break;
            case 3:
                level = StrengthLevel.GOOD;
                message = "Buona - resistente alla maggior parte degli attacchi";
                break;
            case 4:
                level = StrengthLevel.STRONG;
                message = "Ottima - molto difficile da violare";
                break;
            default:
                level = StrengthLevel.WEAK;
                message = "Non valutabile";
        }
        
        // Aggiungi warning se presente
        String warning = strength.getFeedback().getWarning();
        if (warning != null && !warning.isEmpty()) {
            message = translateWarning(warning);
        }
        
        return new PasswordStrength(score, level, message);
    }
    
    /**
     * Traduce i warning di zxcvbn in italiano.
     */
    private static String translateWarning(String warning) {
        if (warning == null) return "";
        
        // Traduzioni dei warning più comuni di zxcvbn
        if (warning.contains("common password")) {
            return "Questa è una password molto comune";
        }
        if (warning.contains("similar to a commonly used password")) {
            return "Troppo simile a password comuni";
        }
        if (warning.contains("short keyboard patterns")) {
            return "Contiene pattern da tastiera prevedibili";
        }
        if (warning.contains("straight rows of keys")) {
            return "Contiene sequenze di tasti consecutive";
        }
        if (warning.contains("repeats like")) {
            return "Contiene troppe ripetizioni";
        }
        if (warning.contains("sequences like")) {
            return "Contiene sequenze prevedibili";
        }
        if (warning.contains("recent year")) {
            return "Evita di usare anni recenti";
        }
        if (warning.contains("dates")) {
            return "Le date sono facili da indovinare";
        }
        if (warning.contains("top 10") || warning.contains("top 100")) {
            return "Questa password è tra le più usate al mondo";
        }
        if (warning.contains("word by itself")) {
            return "Una singola parola è facile da indovinare";
        }
        if (warning.contains("names and surnames")) {
            return "Nomi e cognomi sono facili da indovinare";
        }
        if (warning.contains("common names")) {
            return "I nomi comuni sono facili da indovinare";
        }
        
        return warning; // Ritorna l'originale se non trovato
    }
    
    /**
     * Traduce i suggerimenti di zxcvbn in italiano.
     */
    private static String translateSuggestion(String suggestion) {
        if (suggestion == null) return "";
        
        if (suggestion.contains("Add another word or two")) {
            return "Aggiungi altre parole";
        }
        if (suggestion.contains("Use a longer keyboard pattern")) {
            return "Usa un pattern più lungo";
        }
        if (suggestion.contains("Avoid repeated words")) {
            return "Evita parole ripetute";
        }
        if (suggestion.contains("Avoid sequences")) {
            return "Evita sequenze prevedibili";
        }
        if (suggestion.contains("Avoid recent years")) {
            return "Evita anni recenti";
        }
        if (suggestion.contains("Avoid dates")) {
            return "Evita date significative";
        }
        if (suggestion.contains("Capitalization")) {
            return "Le maiuscole all'inizio non aggiungono molta sicurezza";
        }
        if (suggestion.contains("All-uppercase")) {
            return "Il tutto maiuscolo non è molto più sicuro";
        }
        if (suggestion.contains("Reversed words")) {
            return "Le parole al contrario non sono molto sicure";
        }
        if (suggestion.contains("Predictable substitutions")) {
            return "Sostituzioni come @ per 'a' sono prevedibili";
        }
        
        return suggestion;
    }
    
    /**
     * Sanitizza l'output per prevenire XSS (HTML encoding).
     * 
     * @param input la stringa da sanitizzare
     * @return la stringa con caratteri HTML encodati
     */
    public static String sanitizeForHtml(String input) {
        if (input == null) {
            return "";
        }
        
        StringBuilder sanitized = new StringBuilder(input.length());
        for (char c : input.toCharArray()) {
            switch (c) {
                case '<':
                    sanitized.append("&lt;");
                    break;
                case '>':
                    sanitized.append("&gt;");
                    break;
                case '&':
                    sanitized.append("&amp;");
                    break;
                case '"':
                    sanitized.append("&quot;");
                    break;
                case '\'':
                    sanitized.append("&#x27;");
                    break;
                case '/':
                    sanitized.append("&#x2F;");
                    break;
                default:
                    sanitized.append(c);
            }
        }
        return sanitized.toString();
    }
    
    /**
     * Verifica che il nome file contenga solo caratteri sicuri.
     * 
     * @param filename il nome del file
     * @return true se il nome è sicuro
     */
    public static boolean isValidFilename(String filename) {
        if (filename == null || filename.isEmpty()) {
            return false;
        }
        
        // Previene path traversal
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            return false;
        }
        
        // Solo caratteri alfanumerici, trattini, underscore e punto
        return filename.matches("^[a-zA-Z0-9._-]+$");
    }
    
    /**
     * Pulisce un filename rimuovendo caratteri potenzialmente pericolosi.
     * 
     * @param filename il nome del file
     * @return il nome del file sanitizzato
     */
    public static String sanitizeFilename(String filename) {
        if (filename == null) {
            return "";
        }
        // Rimuove path traversal e caratteri speciali
        return filename.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
    
    // ========== Classi interne ==========
    
    /**
     * Risultato della validazione password.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String message;
        private final int strengthScore;
        
        public ValidationResult(boolean valid, String message, int strengthScore) {
            this.valid = valid;
            this.message = message;
            this.strengthScore = strengthScore;
        }
        
        public boolean isValid() {
            return valid;
        }
        
        public String getMessage() {
            return message;
        }
        
        public int getStrengthScore() {
            return strengthScore;
        }
    }
    
    /**
     * Livelli di forza password.
     */
    public enum StrengthLevel {
        WEAK,       // Score 0-1
        FAIR,       // Score 2
        GOOD,       // Score 3
        STRONG      // Score 4
    }
    
    /**
     * Risultato valutazione forza password.
     */
    public static class PasswordStrength {
        private final int score;
        private final StrengthLevel level;
        private final String message;
        
        public PasswordStrength(int score, StrengthLevel level, String message) {
            this.score = score;
            this.level = level;
            this.message = message;
        }
        
        public int getScore() {
            return score;
        }
        
        public StrengthLevel getLevel() {
            return level;
        }
        
        public String getMessage() {
            return message;
        }
        
        public String getLevelName() {
            switch (level) {
                case WEAK: return "Debole";
                case FAIR: return "Discreta";
                case GOOD: return "Buona";
                case STRONG: return "Ottima";
                default: return "Sconosciuto";
            }
        }
        
        public String getLevelColor() {
            switch (level) {
                case WEAK: return "#dc3545";    // Rosso
                case FAIR: return "#ffc107";    // Giallo
                case GOOD: return "#28a745";    // Verde
                case STRONG: return "#20c997";  // Verde acqua
                default: return "#6c757d";      // Grigio
            }
        }
    }
}
