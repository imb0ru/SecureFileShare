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
import app.security.InputValidator;
import app.security.SessionManager;

/**
 * Servlet per la visualizzazione sicura dei contenuti caricati.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Output encoding per prevenire XSS
 * - Verifica autorizzazione per accesso ai file
 * - Content-Type corretto per prevenire MIME sniffing
 * - Il contenuto non viene mai interpretato come codice eseguibile
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebServlet("/content/*")
public class ContentServlet extends HttpServlet {

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
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Verifica autenticazione
        if (!SessionManager.isAuthenticated(request)) {
            response.sendRedirect(request.getContextPath() + "/login?error=session_required");
            return;
        }

        // Ottieni l'ID del file dal path
        String pathInfo = request.getPathInfo();
        if (pathInfo == null || pathInfo.length() <= 1) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "ID file non specificato");
            return;
        }

        String fileIdStr = pathInfo.substring(1); // Rimuove lo slash iniziale
        int fileId;
        try {
            fileId = Integer.parseInt(fileIdStr);
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "ID file non valido");
            return;
        }

        // Cerca il file nel database
        UploadedFile uploadedFile = fileDAO.findById(fileId);
        if (uploadedFile == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File non trovato");
            return;
        }

        // Verifica se è una richiesta di download
        String downloadParam = request.getParameter("download");
        boolean isDownload = "true".equals(downloadParam);

        try {
            if (isDownload) {
                // Download del file
                byte[] content = fileManager.readFileThreadSafe(
                        uploadedFile.getStoredFilename(),
                        uploadedFile.getUserId()
                );

                // Imposta header per download sicuro
                response.setContentType("text/plain; charset=UTF-8");
                response.setHeader("Content-Disposition",
                        "attachment; filename=\"" + uploadedFile.getOriginalFilename() + "\"");
                response.setHeader("X-Content-Type-Options", "nosniff");
                response.setContentLength(content.length);

                response.getOutputStream().write(content);

            } else {
                // Visualizzazione del file
                String content = fileManager.readFileContentAsString(
                        uploadedFile.getStoredFilename(),
                        uploadedFile.getUserId()
                );

                // IMPORTANTE: Sanitizza il contenuto per prevenire XSS
                String sanitizedContent = InputValidator.sanitizeForHtml(content);

                // Passa i dati alla JSP
                request.setAttribute("file", uploadedFile);
                request.setAttribute("content", sanitizedContent);

                // Forward alla pagina di visualizzazione
                request.getRequestDispatcher("/view-content.jsp").forward(request, response);
            }

        } catch (IOException e) {
            System.err.println("Errore durante la lettura del file: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Errore durante la lettura del file");
        }
    }

    /**
     * Serve il file come download raw (testo plain).
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Per download raw
        if (!SessionManager.isAuthenticated(request)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String fileIdStr = request.getParameter("fileId");
        if (fileIdStr == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        int fileId;
        try {
            fileId = Integer.parseInt(fileIdStr);
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        UploadedFile uploadedFile = fileDAO.findById(fileId);
        if (uploadedFile == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        try {
            byte[] content = fileManager.readFileThreadSafe(
                    uploadedFile.getStoredFilename(),
                    uploadedFile.getUserId()
            );

            // Imposta header per download sicuro
            response.setContentType("text/plain; charset=UTF-8");
            response.setHeader("Content-Disposition",
                    "attachment; filename=\"" + uploadedFile.getOriginalFilename() + "\"");
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setContentLength(content.length);

            response.getOutputStream().write(content);

        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public void destroy() {
        if (fileManager != null) {
            fileManager.shutdown();
        }
    }
}
