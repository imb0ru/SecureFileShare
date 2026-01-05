package app.controller;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import app.dao.FileDAO;
import app.model.UploadedFile;
import app.security.SessionManager;

/**
 * Servlet per la dashboard utente.
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebServlet("/dashboard")
public class DashboardServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private FileDAO fileDAO;

    @Override
    public void init() throws ServletException {
        fileDAO = new FileDAO();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Verifica autenticazione (già gestita dal filtro, ma doppio controllo)
        if (!SessionManager.isAuthenticated(request)) {
            response.sendRedirect(request.getContextPath() + "/login?error=session_required");
            return;
        }

        // Ottieni informazioni utente
        String userEmail = SessionManager.getAuthenticatedUser(request);
        int userId = SessionManager.getAuthenticatedUserId(request);

        request.setAttribute("userEmail", userEmail);
        request.setAttribute("userId", userId);

        // Ottieni i file dell'utente
        List<UploadedFile> userFiles = fileDAO.findByUserId(userId);
        request.setAttribute("userFiles", userFiles);

        // Ottieni tutti i file condivisi (per visualizzazione)
        List<UploadedFile> allFiles = fileDAO.findAllWithUserInfo();
        request.setAttribute("allFiles", allFiles);

        // Forward alla pagina dashboard
        request.getRequestDispatcher("/dashboard.jsp").forward(request, response);
    }
}
