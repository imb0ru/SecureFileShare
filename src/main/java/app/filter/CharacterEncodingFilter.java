package app.filter;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;

/**
 * Filtro per impostare l'encoding UTF-8 su tutte le richieste e risposte.
 * Garantisce la corretta gestione dei caratteri speciali e accentati.
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebFilter(filterName = "CharacterEncodingFilter", urlPatterns = "/*")
public class CharacterEncodingFilter implements Filter {

    private static final String ENCODING = "UTF-8";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Nessuna inizializzazione necessaria
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // Imposta encoding sulla richiesta
        if (request.getCharacterEncoding() == null) {
            request.setCharacterEncoding(ENCODING);
        }

        // Imposta encoding sulla risposta
        response.setCharacterEncoding(ENCODING);

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Nessuna risorsa da rilasciare
    }
}
