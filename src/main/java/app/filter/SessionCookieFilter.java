package app.filter;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import app.config.AppConfig;

/**
 * Filtro per configurare gli attributi di sicurezza del cookie di sessione.
 *
 * Aggiunge gli attributi SameSite e Secure ai cookie JSESSIONID.
 * La configurazione viene letta da variabili d'ambiente:
 * - COOKIE_SECURE: true/false
 * - COOKIE_SAMESITE: Strict/Lax/None
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebFilter(filterName = "SessionCookieFilter", urlPatterns = "/*")
public class SessionCookieFilter implements Filter {

    private boolean secureCookie;
    private String sameSitePolicy;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        AppConfig config = AppConfig.getInstance();
        this.secureCookie = config.isCookieSecure();
        this.sameSitePolicy = config.getCookieSameSite();

        System.out.println("[SessionCookieFilter] Secure=" + secureCookie + ", SameSite=" + sameSitePolicy);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (response instanceof HttpServletResponse) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;

            // Wrapper per intercettare i cookie e aggiungere attributi di sicurezza
            SameSiteCookieResponseWrapper wrappedResponse =
                    new SameSiteCookieResponseWrapper(httpResponse, secureCookie, sameSitePolicy);

            chain.doFilter(request, wrappedResponse);
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {
        // Nessuna pulizia necessaria
    }

    /**
     * Wrapper della risposta HTTP che aggiunge attributi di sicurezza ai cookie.
     */
    private static class SameSiteCookieResponseWrapper extends HttpServletResponseWrapper {

        private final boolean secureCookie;
        private final String sameSitePolicy;

        public SameSiteCookieResponseWrapper(HttpServletResponse response,
                                             boolean secureCookie, String sameSitePolicy) {
            super(response);
            this.secureCookie = secureCookie;
            this.sameSitePolicy = sameSitePolicy;
        }

        @Override
        public void addHeader(String name, String value) {
            if ("Set-Cookie".equalsIgnoreCase(name) && value != null) {
                value = addSecurityAttributes(value);
            }
            super.addHeader(name, value);
        }

        @Override
        public void setHeader(String name, String value) {
            if ("Set-Cookie".equalsIgnoreCase(name) && value != null) {
                value = addSecurityAttributes(value);
            }
            super.setHeader(name, value);
        }

        /**
         * Aggiunge gli attributi di sicurezza al cookie.
         */
        private String addSecurityAttributes(String cookieValue) {
            // Solo per cookie JSESSIONID
            if (!cookieValue.contains("JSESSIONID")) {
                return cookieValue;
            }

            StringBuilder sb = new StringBuilder(cookieValue);

            // Aggiungi SameSite se non presente
            if (!cookieValue.contains("SameSite")) {
                sb.append("; SameSite=").append(sameSitePolicy);
            }

            // Aggiungi Secure se configurato e non presente
            if (secureCookie && !cookieValue.contains("Secure")) {
                sb.append("; Secure");
            }

            return sb.toString();
        }
    }
}
