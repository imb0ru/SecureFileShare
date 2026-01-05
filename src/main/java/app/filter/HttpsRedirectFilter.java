package app.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Filtro per forzare l'utilizzo di HTTPS.
 *
 * Tutte le richieste HTTP vengono reindirizzate automaticamente a HTTPS.
 * Questo garantisce che tutte le comunicazioni siano cifrate.
 *
 * NOTA: In produzione, questo redirect dovrebbe essere gestito
 * a livello di reverse proxy (nginx, Apache) per migliori prestazioni.
 * Questo filtro è un fallback di sicurezza.
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebFilter(urlPatterns = "/*", filterName = "HttpsRedirectFilter")
public class HttpsRedirectFilter implements Filter {

    // Porta HTTPS standard (può essere configurata)
    private static final int HTTPS_PORT = 8443;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("[HttpsRedirectFilter] Inizializzato - HTTPS obbligatorio");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Verifica se la richiesta è già HTTPS
        if (isSecure(httpRequest)) {
            // Già HTTPS, prosegui
            chain.doFilter(request, response);
            return;
        }

        // Costruisci URL HTTPS
        String httpsUrl = buildHttpsUrl(httpRequest);

        // Redirect permanente a HTTPS (301)
        httpResponse.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
        httpResponse.setHeader("Location", httpsUrl);

        System.out.println("[HttpsRedirectFilter] Redirect HTTP → HTTPS: " + httpsUrl);
    }

    /**
     * Verifica se la richiesta è sicura (HTTPS).
     * Considera anche header da reverse proxy.
     */
    private boolean isSecure(HttpServletRequest request) {
        // Controllo diretto
        if (request.isSecure()) {
            return true;
        }

        // Header da reverse proxy (nginx, Apache, load balancer)
        String forwardedProto = request.getHeader("X-Forwarded-Proto");
        if ("https".equalsIgnoreCase(forwardedProto)) {
            return true;
        }

        // Header alternativo
        String forwardedSsl = request.getHeader("X-Forwarded-Ssl");
        if ("on".equalsIgnoreCase(forwardedSsl)) {
            return true;
        }

        return false;
    }

    /**
     * Costruisce l'URL HTTPS equivalente.
     */
    private String buildHttpsUrl(HttpServletRequest request) {
        StringBuilder url = new StringBuilder();
        url.append("https://");
        url.append(request.getServerName());

        // Aggiungi porta se non standard
        if (HTTPS_PORT != 443) {
            url.append(":").append(HTTPS_PORT);
        }

        url.append(request.getRequestURI());

        // Mantieni query string
        String queryString = request.getQueryString();
        if (queryString != null && !queryString.isEmpty()) {
            url.append("?").append(queryString);
        }

        return url.toString();
    }

    @Override
    public void destroy() {
        // Cleanup se necessario
    }
}
