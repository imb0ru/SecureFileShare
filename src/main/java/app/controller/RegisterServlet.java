package app.controller;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import app.dao.UserDAO;
import app.security.InputValidator;
import app.security.InputValidator.ValidationResult;
import app.security.PasswordManager;

/**
 * Servlet per la registrazione di nuovi utenti.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Validazione rigorosa dell'email
 * - Policy di sicurezza per le password
 * - Hash password con PBKDF2 e salt univoco
 * - Messaggi di errore generici per prevenire enumerazione utenti
 * - Pulizia dati sensibili dalla memoria
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebServlet("/register")
public class RegisterServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private UserDAO userDAO;

    @Override
    public void init() throws ServletException {
        userDAO = new UserDAO();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Mostra la pagina di registrazione
        request.getRequestDispatcher("/register.jsp").forward(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String email = request.getParameter("email");
        String password = request.getParameter("password");
        String confirmPassword = request.getParameter("confirmPassword");

        // Array per la password (per poterlo pulire dopo)
        char[] passwordChars = password != null ? password.toCharArray() : new char[0];

        try {
            // Validazione email
            if (!InputValidator.isValidEmail(email)) {
                setErrorAndForward(request, response, "Email non valida");
                return;
            }

            // Validazione password
            ValidationResult passwordValidation = InputValidator.validatePassword(password);
            if (!passwordValidation.isValid()) {
                setErrorAndForward(request, response, passwordValidation.getMessage());
                return;
            }

            // Verifica corrispondenza password
            if (!password.equals(confirmPassword)) {
                setErrorAndForward(request, response, "Le password non corrispondono");
                return;
            }

            // Verifica se l'email esiste già
            // NOTA: Messaggio che suggerisce di fare login senza confermare esplicitamente che l'email esiste
            if (userDAO.emailExists(email)) {
                setErrorAndForward(request, response,
                        "Impossibile completare la registrazione con questa email. Se hai già un account, prova ad accedere.");
                return;
            }

            // Genera salt e hash della password
            byte[] salt = PasswordManager.generateSalt();
            byte[] passwordHash = PasswordManager.hashPassword(passwordChars, salt);

            // Registra l'utente
            int userId = userDAO.registerUser(email, passwordHash, salt);

            // Pulisci i dati sensibili dalla memoria
            PasswordManager.clearCharArray(passwordChars);
            PasswordManager.clearByteArray(passwordHash);
            PasswordManager.clearByteArray(salt);

            if (userId > 0) {
                // Registrazione riuscita - redirect alla pagina di login
                response.sendRedirect(request.getContextPath() + "/login?registered=true");
            } else {
                // Errore durante il salvataggio
                setErrorAndForward(request, response,
                        "Impossibile completare la registrazione. Riprova tra qualche minuto.");
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // Log dell'errore senza esporre dettagli all'utente
            System.err.println("Errore durante l'hashing della password");
            setErrorAndForward(request, response,
                    "Si è verificato un errore interno. Riprova più tardi.");
        } finally {
            // Assicura la pulizia dei dati sensibili
            PasswordManager.clearCharArray(passwordChars);
        }
    }

    /**
     * Imposta un messaggio di errore e inoltra alla pagina di registrazione.
     */
    private void setErrorAndForward(HttpServletRequest request, HttpServletResponse response,
                                    String errorMessage) throws ServletException, IOException {
        request.setAttribute("error", errorMessage);
        // Mantieni l'email inserita (non la password per sicurezza)
        request.setAttribute("email", request.getParameter("email"));
        request.getRequestDispatcher("/register.jsp").forward(request, response);
    }
}
