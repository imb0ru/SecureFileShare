package app.security;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import app.config.AppConfig;

/**
 * Gestisce le sessioni HTTP in modo sicuro.
 * 
 * Implementa le seguenti misure di sicurezza:
 * - Rigenerazione session ID dopo autenticazione (prevenzione session fixation)
 * - Impostazione cookie con attributi di sicurezza (HttpOnly, Secure, SameSite)
 * - Timeout di sessione configurabile
 * - Invalidazione completa della sessione al logout
 * 
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public final class SessionManager {
    
    // Nome dell'attributo per l'utente autenticato
    public static final String USER_ATTRIBUTE = "authenticatedUser";
    public static final String USER_ID_ATTRIBUTE = "userId";
    public static final String LOGIN_TIME_ATTRIBUTE = "loginTime";
    
    // Costruttore privato
    private SessionManager() {
        throw new AssertionError("Classe non istanziabile");
    }
    
    /**
     * Crea una nuova sessione sicura dopo l'autenticazione.
     * Implementa la rigenerazione dell'ID di sessione per prevenire session fixation.
     * 
     * @param request la richiesta HTTP
     * @param response la risposta HTTP
     * @param userEmail l'email dell'utente autenticato
     * @param userId l'ID dell'utente
     * @return la nuova sessione
     */
    public static HttpSession createSecureSession(HttpServletRequest request, 
            HttpServletResponse response, String userEmail, int userId) {
        
        // Salva gli attributi della vecchia sessione che vogliamo preservare
        HttpSession oldSession = request.getSession(false);
        Map<String, Object> preservedAttributes = new HashMap<>();
        
        if (oldSession != null) {
            // Preserva solo attributi non sensibili se necessario
            Enumeration<String> attributeNames = oldSession.getAttributeNames();
            while (attributeNames.hasMoreElements()) {
                String name = attributeNames.nextElement();
                // Non preservare attributi di autenticazione precedenti
                if (!name.equals(USER_ATTRIBUTE) && !name.equals(USER_ID_ATTRIBUTE) 
                        && !name.equals(LOGIN_TIME_ATTRIBUTE)) {
                    preservedAttributes.put(name, oldSession.getAttribute(name));
                }
            }
            // Invalida la vecchia sessione
            oldSession.invalidate();
        }
        
        // Crea una nuova sessione con nuovo ID
        HttpSession newSession = request.getSession(true);
        
        // Ripristina gli attributi preservati
        for (Map.Entry<String, Object> entry : preservedAttributes.entrySet()) {
            newSession.setAttribute(entry.getKey(), entry.getValue());
        }
        
        // Imposta gli attributi dell'utente autenticato
        newSession.setAttribute(USER_ATTRIBUTE, userEmail);
        newSession.setAttribute(USER_ID_ATTRIBUTE, userId);
        newSession.setAttribute(LOGIN_TIME_ATTRIBUTE, System.currentTimeMillis());
        
        // Imposta il timeout di sessione da configurazione
        newSession.setMaxInactiveInterval(AppConfig.getInstance().getSessionTimeout());
        
        return newSession;
    }
    
    /**
     * Verifica se l'utente è autenticato nella sessione corrente.
     * 
     * @param request la richiesta HTTP
     * @return true se l'utente è autenticato
     */
    public static boolean isAuthenticated(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return false;
        }
        
        Object user = session.getAttribute(USER_ATTRIBUTE);
        Object loginTime = session.getAttribute(LOGIN_TIME_ATTRIBUTE);
        
        return user != null && loginTime != null;
    }
    
    /**
     * Ottiene l'email dell'utente autenticato.
     * 
     * @param request la richiesta HTTP
     * @return l'email dell'utente o null se non autenticato
     */
    public static String getAuthenticatedUser(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (String) session.getAttribute(USER_ATTRIBUTE);
    }
    
    /**
     * Ottiene l'ID dell'utente autenticato.
     * 
     * @param request la richiesta HTTP
     * @return l'ID dell'utente o -1 se non autenticato
     */
    public static int getAuthenticatedUserId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return -1;
        }
        Object userId = session.getAttribute(USER_ID_ATTRIBUTE);
        return userId != null ? (Integer) userId : -1;
    }
    
    /**
     * Effettua il logout invalidando completamente la sessione.
     * 
     * @param request la richiesta HTTP
     * @param response la risposta HTTP
     */
    public static void logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        
        if (session != null) {
            // Rimuovi tutti gli attributi
            Enumeration<String> attributeNames = session.getAttributeNames();
            while (attributeNames.hasMoreElements()) {
                session.removeAttribute(attributeNames.nextElement());
            }
            
            // Invalida la sessione
            session.invalidate();
        }
        
        // Invalida il cookie di sessione
        invalidateSessionCookie(request, response);
    }
    
    /**
     * Invalida il cookie di sessione impostando una data di scadenza passata.
     * 
     * @param request la richiesta HTTP
     * @param response la risposta HTTP
     */
    private static void invalidateSessionCookie(HttpServletRequest request, 
            HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            AppConfig config = AppConfig.getInstance();
            for (Cookie cookie : cookies) {
                if ("JSESSIONID".equals(cookie.getName())) {
                    Cookie invalidCookie = new Cookie("JSESSIONID", "");
                    invalidCookie.setMaxAge(0); // Scadenza immediata
                    invalidCookie.setPath(request.getContextPath());
                    invalidCookie.setHttpOnly(config.isCookieHttpOnly());
                    invalidCookie.setSecure(config.isCookieSecure());
                    response.addCookie(invalidCookie);
                    break;
                }
            }
        }
    }
    
    /**
     * Rigenera l'ID di sessione mantenendo gli attributi.
     * Da usare per operazioni sensibili.
     * 
     * @param request la richiesta HTTP
     * @return la sessione con nuovo ID
     */
    public static HttpSession regenerateSessionId(HttpServletRequest request) {
        HttpSession oldSession = request.getSession(false);
        if (oldSession == null) {
            return request.getSession(true);
        }
        
        // Copia gli attributi
        Map<String, Object> attributes = new HashMap<>();
        Enumeration<String> names = oldSession.getAttributeNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            attributes.put(name, oldSession.getAttribute(name));
        }
        
        // Invalida e ricrea
        oldSession.invalidate();
        HttpSession newSession = request.getSession(true);
        
        // Ripristina gli attributi
        for (Map.Entry<String, Object> entry : attributes.entrySet()) {
            newSession.setAttribute(entry.getKey(), entry.getValue());
        }
        
        return newSession;
    }
    
    /**
     * Verifica se la sessione è scaduta.
     * 
     * @param request la richiesta HTTP
     * @return true se la sessione è scaduta o non esiste
     */
    public static boolean isSessionExpired(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false);
            if (session == null) {
                return true;
            }
            // Prova ad accedere alla sessione - lancerà IllegalStateException se invalidata
            session.getAttribute(USER_ATTRIBUTE);
            return false;
        } catch (IllegalStateException e) {
            return true;
        }
    }
}
