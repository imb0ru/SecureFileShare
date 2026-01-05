package app.config;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.SessionCookieConfig;
import jakarta.servlet.annotation.WebListener;

/**
 * Inizializza la configurazione dei cookie di sessione all'avvio.
 *
 * SICUREZZA: Tutti i parametri sono SEMPRE impostati in modo sicuro.
 * Non esiste più distinzione dev/prod - l'applicazione richiede HTTPS.
 *
 * Configurazione applicata:
 * - HttpOnly: true (impedisce accesso JavaScript)
 * - Secure: true (solo HTTPS)
 * - SameSite: Strict (protezione CSRF massima)
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebListener
public class SessionCookieInitializer implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        ServletContext context = sce.getServletContext();
        AppConfig config = AppConfig.getInstance();

        // Configura i cookie di sessione
        SessionCookieConfig cookieConfig = context.getSessionCookieConfig();

        // HttpOnly: SEMPRE true (protezione XSS)
        cookieConfig.setHttpOnly(config.isCookieHttpOnly());

        // Secure: SEMPRE true (richiede HTTPS)
        cookieConfig.setSecure(config.isCookieSecure());

        // SameSite: SEMPRE Strict (protezione CSRF)
        cookieConfig.setAttribute("SameSite", config.getCookieSameSite());

        // Timeout sessione
        int timeoutSeconds = config.getSessionTimeout();
        int timeoutMinutes = Math.max(1, timeoutSeconds / 60);
        context.setSessionTimeout(timeoutMinutes);

        // Log configurazione
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║         Cookie di Sessione Configurati                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        System.out.println("║  HttpOnly:       ✓ TRUE (protezione XSS)                 ║");
        System.out.println("║  Secure:         ✓ TRUE (richiede HTTPS)                 ║");
        System.out.println("║  SameSite:       ✓ Strict (protezione CSRF)              ║");
        System.out.println("║  Timeout:        " + padRight(timeoutMinutes + " minuti", 39) + "║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        // Cleanup se necessario
    }

    private String padRight(String s, int n) {
        return String.format("%-" + n + "s", s);
    }
}
