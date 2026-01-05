package app.controller;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import app.security.SessionManager;

/**
 * Servlet per il logout degli utenti.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Invalidazione completa della sessione server-side
 * - Eliminazione del cookie di sessione
 * - Prevenzione del riutilizzo della sessione precedente
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebServlet("/logout")
public class LogoutServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        performLogout(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        performLogout(request, response);
    }

    /**
     * Esegue il logout dell'utente.
     */
    private void performLogout(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        // Effettua il logout (invalida sessione e cookie)
        SessionManager.logout(request, response);

        // Imposta header per prevenire caching della pagina di logout
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);

        // Redirect alla pagina di login con messaggio di successo
        response.sendRedirect(request.getContextPath() + "/login?success=logout");
    }
}
