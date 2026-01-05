package app.controller;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import app.config.AppConfig;
import app.dao.FileDAO;
import app.model.UploadedFile;
import app.security.ConcurrentFileManager;
import app.security.SessionManager;

/**
 * Servlet per l'eliminazione sicura dei file.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Verifica autenticazione
 * - Verifica proprietà del file (solo il proprietario può eliminare)
 * - Eliminazione atomica da database e filesystem
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebServlet("/delete")
public class DeleteServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private FileDAO fileDAO;
    private ConcurrentFileManager fileManager;

    @Override
    public void init() throws ServletException {
        fileDAO = new FileDAO();
        String uploadDir = AppConfig.getInstance().getUploadDirectory();
        fileManager = new ConcurrentFileManager(uploadDir);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Verifica autenticazione
        if (!SessionManager.isAuthenticated(request)) {
            response.sendRedirect(request.getContextPath() + "/login?error=session_required");
            return;
        }

        int userId = SessionManager.getAuthenticatedUserId(request);
        String fileIdStr = request.getParameter("fileId");

        // Validazione parametro
        if (fileIdStr == null || fileIdStr.isEmpty()) {
            response.sendRedirect(request.getContextPath() + "/dashboard?error=invalid_file");
            return;
        }

        int fileId;
        try {
            fileId = Integer.parseInt(fileIdStr);
        } catch (NumberFormatException e) {
            response.sendRedirect(request.getContextPath() + "/dashboard?error=invalid_file");
            return;
        }

        // Cerca il file nel database
        UploadedFile file = fileDAO.findById(fileId);

        if (file == null) {
            response.sendRedirect(request.getContextPath() + "/dashboard?error=file_not_found");
            return;
        }

        // Verifica che l'utente sia il proprietario del file
        if (file.getUserId() != userId) {
            response.sendRedirect(request.getContextPath() + "/dashboard?error=unauthorized");
            return;
        }

        try {
            // Elimina dal filesystem
            boolean fileDeleted = fileManager.deleteFileThreadSafe(file.getStoredFilename(), userId);

            // Elimina dal database
            boolean dbDeleted = fileDAO.deleteFile(fileId, userId);

            if (dbDeleted) {
                response.sendRedirect(request.getContextPath() + "/dashboard?success=deleted");
            } else {
                response.sendRedirect(request.getContextPath() + "/dashboard?error=delete_failed");
            }

        } catch (Exception e) {
            System.err.println("Errore durante l'eliminazione: " + e.getMessage());
            response.sendRedirect(request.getContextPath() + "/dashboard?error=delete_failed");
        }
    }

    @Override
    public void destroy() {
        if (fileManager != null) {
            fileManager.shutdown();
        }
    }
}
