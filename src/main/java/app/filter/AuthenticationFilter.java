package app.filter;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import app.security.SessionManager;

/**
 * Filtro per verificare l'autenticazione sulle risorse protette.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Verifica sessione valida prima di accedere a risorse protette
 * - Redirect al login per utenti non autenticati
 * - Protezione contro accesso non autorizzato
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebFilter(urlPatterns = {"/dashboard/*", "/upload/*", "/files/*", "/content/*"})
public class AuthenticationFilter implements Filter {

    // Pagine escluse dall'autenticazione
    private static final String[] EXCLUDED_PATHS = {
            "/login", "/register", "/index.jsp", "/css/", "/js/", "/images/"
    };

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Inizializzazione se necessaria
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String requestURI = httpRequest.getRequestURI();
        String contextPath = httpRequest.getContextPath();
        String path = requestURI.substring(contextPath.length());

        // Verifica se il path è escluso dall'autenticazione
        if (isExcludedPath(path)) {
            chain.doFilter(request, response);
            return;
        }

        // Verifica autenticazione
        HttpSession session = httpRequest.getSession(false);

        if (session == null || !SessionManager.isAuthenticated(httpRequest)) {
            // Controlla se c'era una sessione precedente (cookie JSESSIONID presente)
            boolean hadSession = hasSessionCookie(httpRequest);

            if (hadSession) {
                // Cookie presente ma sessione non valida = sessione scaduta
                httpResponse.sendRedirect(contextPath + "/login?error=session_expired");
            } else {
                // Nessun cookie = utente non ha mai fatto login
                httpResponse.sendRedirect(contextPath + "/login?error=session_required");
            }
            return;
        }

        // Utente autenticato, prosegui con la richiesta
        chain.doFilter(request, response);
    }

    /**
     * Verifica se esiste un cookie di sessione JSESSIONID.
     */
    private boolean hasSessionCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("JSESSIONID".equals(cookie.getName())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Verifica se un path è escluso dall'autenticazione.
     */
    private boolean isExcludedPath(String path) {
        for (String excluded : EXCLUDED_PATHS) {
            if (path.startsWith(excluded) || path.equals("/")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void destroy() {
        // Pulizia se necessaria
    }
}
