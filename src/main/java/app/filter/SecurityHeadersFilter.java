package app.filter;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import app.config.AppConfig;

/**
 * Filtro per impostare gli header di sicurezza HTTP.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Content-Security-Policy con NONCE per script inline (prevenzione XSS)
 * - X-Content-Type-Options per prevenire MIME sniffing
 * - X-Frame-Options per prevenire clickjacking
 * - X-XSS-Protection per browser legacy
 * - Referrer-Policy per la privacy
 * - Cache-Control per dati sensibili
 * - HSTS configurabile per forzare HTTPS in produzione
 *
 * NONCE CSP:
 * Un nonce (number used once) è un token casuale generato per ogni richiesta.
 * Solo gli script con l'attributo nonce corrispondente vengono eseguiti.
 * Questo è più sicuro di 'unsafe-inline' perché un attaccante non può
 * indovinare il nonce casuale.
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebFilter(urlPatterns = "/*")
public class SecurityHeadersFilter implements Filter {

    /**
     * Nome dell'attributo request per il nonce CSP.
     * Le JSP possono accedere a questo valore per gli script inline.
     */
    public static final String CSP_NONCE_ATTRIBUTE = "cspNonce";

    private static final SecureRandom secureRandom = new SecureRandom();

    private AppConfig config;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        config = AppConfig.getInstance();
        System.out.println("[SecurityHeadersFilter] Inizializzato - HSTS SEMPRE ATTIVO");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Genera nonce casuale per questa richiesta
        String nonce = generateNonce();

        // Rendi il nonce disponibile alle JSP
        httpRequest.setAttribute(CSP_NONCE_ATTRIBUTE, nonce);

        // Content-Security-Policy con nonce per script inline
        // Il nonce permette solo gli script che lo includono, bloccando XSS injection
        // cdnjs.cloudflare.com è consentito per la libreria zxcvbn (valutazione password)
        httpResponse.setHeader("Content-Security-Policy",
                "default-src 'self'; " +
                        "script-src 'self' 'nonce-" + nonce + "' https://cdnjs.cloudflare.com; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:; " +
                        "font-src 'self'; " +
                        "frame-ancestors 'none'; " +
                        "form-action 'self'; " +
                        "base-uri 'self'"
        );

        // X-Content-Type-Options - previene MIME sniffing
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");

        // X-Frame-Options - previene clickjacking
        httpResponse.setHeader("X-Frame-Options", "DENY");

        // X-XSS-Protection - protezione XSS per browser legacy
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");

        // Referrer-Policy - controlla le informazioni inviate nel Referer
        httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // Cache-Control - previene caching di dati sensibili
        httpResponse.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        httpResponse.setHeader("Pragma", "no-cache");
        httpResponse.setDateHeader("Expires", 0);

        // HSTS - HTTP Strict Transport Security
        // Forza HTTPS per tutte le connessioni future
        // Configurabile da variabili d'ambiente (HSTS_ENABLED, HSTS_MAX_AGE, etc.)
        if (config.isHstsEnabled()) {
            StringBuilder hstsValue = new StringBuilder();
            hstsValue.append("max-age=").append(config.getHstsMaxAge());
            if (config.isHstsIncludeSubDomains()) {
                hstsValue.append("; includeSubDomains");
            }
            httpResponse.setHeader("Strict-Transport-Security", hstsValue.toString());
        }

        // Permissions-Policy - limita le funzionalità del browser
        httpResponse.setHeader("Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=()"
        );

        chain.doFilter(request, response);
    }

    /**
     * Genera un nonce crittograficamente sicuro.
     *
     * @return nonce codificato in Base64
     */
    private String generateNonce() {
        byte[] nonceBytes = new byte[config.getNonceLength()];
        secureRandom.nextBytes(nonceBytes);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }

    @Override
    public void destroy() {
        // Nessuna pulizia necessaria
    }
}
