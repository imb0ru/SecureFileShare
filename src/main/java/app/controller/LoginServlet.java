package app.controller;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import app.dao.UserDAO;
import app.model.User;
import app.security.InputValidator;
import app.security.PasswordManager;
import app.security.SessionManager;

/**
 * Servlet per l'autenticazione degli utenti.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Validazione input
 * - Verifica password con confronto costante nel tempo
 * - Rigenerazione ID di sessione dopo login (prevenzione session fixation)
 * - Cookie di sessione con attributi di sicurezza
 * - Messaggi di errore generici per prevenire enumerazione
 * - Rate limiting (da implementare con un filtro dedicato)
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebServlet("/login")
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private UserDAO userDAO;

    // Messaggio generico per errori di autenticazione
    // Non rivela se l'email esiste o se la password è sbagliata
    private static final String GENERIC_ERROR = "Email o password non corretti";

    @Override
    public void init() throws ServletException {
        userDAO = new UserDAO();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Se l'utente è già autenticato, redirect alla dashboard
        if (SessionManager.isAuthenticated(request)) {
            response.sendRedirect(request.getContextPath() + "/dashboard");
            return;
        }

        // I messaggi vengono gestiti direttamente da login.jsp tramite i parametri URL
        // (param.error, param.success, param.registered)

        request.getRequestDispatcher("/login.jsp").forward(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String email = request.getParameter("email");
        String password = request.getParameter("password");

        // Array per la password (per poterlo pulire dopo)
        char[] passwordChars = password != null ? password.toCharArray() : new char[0];

        try {
            // Validazione base dell'input
            if (!InputValidator.isValidEmail(email)) {
                setErrorAndForward(request, response, GENERIC_ERROR);
                return;
            }

            if (password == null || password.isEmpty()) {
                setErrorAndForward(request, response, GENERIC_ERROR);
                return;
            }

            // Cerca l'utente nel database
            User user = userDAO.findByEmail(email);

            // Verifica esistenza utente e stato attivo
            if (user == null || !user.isActive()) {
                // Esegui comunque un'operazione di hash per prevenire timing attacks
                // che potrebbero rivelare se l'email esiste
                simulatePasswordVerification(passwordChars);
                setErrorAndForward(request, response, GENERIC_ERROR);
                return;
            }

            // Verifica la password
            boolean passwordValid = PasswordManager.verifyPassword(
                    passwordChars, user.getSalt(), user.getPasswordHash()
            );

            if (!passwordValid) {
                setErrorAndForward(request, response, GENERIC_ERROR);
                return;
            }

            // Autenticazione riuscita!

            // IMPORTANTE: Rigenera l'ID di sessione per prevenire session fixation
            SessionManager.createSecureSession(
                    request, response, user.getEmail(), user.getId()
            );

            // Aggiorna l'ultimo accesso
            userDAO.updateLastLogin(user.getId());

            // Pulisci i dati sensibili
            user.clearSensitiveData();

            // Redirect alla dashboard
            response.sendRedirect(request.getContextPath() + "/dashboard");

        } finally {
            // Assicura la pulizia dei dati sensibili
            PasswordManager.clearCharArray(passwordChars);
        }
    }

    /**
     * Simula la verifica della password per prevenire timing attacks.
     * Esegue operazioni simili anche quando l'utente non esiste.
     */
    private void simulatePasswordVerification(char[] password) {
        try {
            byte[] dummySalt = PasswordManager.generateSalt();
            PasswordManager.hashPassword(password, dummySalt);
            PasswordManager.clearByteArray(dummySalt);
        } catch (Exception e) {
            // Ignora errori durante la simulazione
        }
    }

    /**
     * Imposta un messaggio di errore e inoltra alla pagina di login.
     */
    private void setErrorAndForward(HttpServletRequest request, HttpServletResponse response,
                                    String errorMessage) throws ServletException, IOException {
        request.setAttribute("error", errorMessage);
        request.getRequestDispatcher("/login.jsp").forward(request, response);
    }
}
