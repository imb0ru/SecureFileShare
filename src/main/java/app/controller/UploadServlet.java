package app.controller;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;

import app.config.AppConfig;
import app.dao.FileDAO;
import app.model.UploadedFile;
import app.security.ConcurrentFileManager;
import app.security.FileValidator;
import app.security.FileValidator.ContentAnalysisResult;
import app.security.FileValidator.FileValidationResult;
import app.security.SessionManager;

/**
 * Servlet per il caricamento sicuro dei file.
 * Supporta upload di file multipli.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Validazione del tipo MIME reale con Apache Tika
 * - Whitelist dei tipi di file consentiti (solo .txt)
 * - Analisi del contenuto per rilevare codice malevolo
 * - Generazione di nomi file sicuri (UUID)
 * - Gestione TOCTOU attraverso operazioni atomiche
 * - Gestione concorrente thread-safe
 * - Salvataggio in directory non accessibile dal web
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
@WebServlet("/upload")
@MultipartConfig(
        fileSizeThreshold = 1024 * 1024,  // 1 MB
        maxFileSize = 1024 * 1024,        // 1 MB
        maxRequestSize = 10 * 1024 * 1024 // 10 MB per upload multipli
)
public class UploadServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private FileDAO fileDAO;
    private ConcurrentFileManager fileManager;
    private ExecutorService validationExecutor;

    @Override
    public void init() throws ServletException {
        fileDAO = new FileDAO();

        // Usa il path configurato dalla variabile d'ambiente UPLOAD_DIRECTORY
        String uploadDir = AppConfig.getInstance().getUploadDirectory();
        java.io.File dir = new java.io.File(uploadDir);
        if (!dir.exists()) {
            boolean created = dir.mkdirs();
            if (created) {
                System.out.println("Creata directory upload: " + uploadDir);
            }
        }
        System.out.println("Upload directory: " + dir.getAbsolutePath());

        fileManager = new ConcurrentFileManager(uploadDir);
        // Thread pool per la validazione concorrente dei file
        validationExecutor = Executors.newFixedThreadPool(4);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Redirect alla pagina di upload
        request.getRequestDispatcher("/upload.jsp").forward(request, response);
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

        try {
            // Ottieni tutti i file dalla richiesta
            Collection<Part> fileParts = request.getParts();
            List<String> uploadedFiles = new ArrayList<>();
            List<String> failedFiles = new ArrayList<>();

            for (Part filePart : fileParts) {
                // Filtra solo i part che sono file (name="file")
                if (!"file".equals(filePart.getName()) || filePart.getSize() == 0) {
                    continue;
                }

                String originalFilename = getSubmittedFileName(filePart);
                long fileSize = filePart.getSize();

                try {
                    // Leggi il contenuto del file in memoria per la validazione
                    byte[] fileContent = readFileContent(filePart.getInputStream());

                    // Esegui validazione e analisi del contenuto in modo concorrente
                    Future<FileValidationResult> validationFuture = validationExecutor.submit(() ->
                            FileValidator.validateFile(
                                    new ByteArrayInputStream(fileContent),
                                    originalFilename,
                                    fileSize
                            )
                    );

                    Future<ContentAnalysisResult> analysisFuture = validationExecutor.submit(() ->
                            FileValidator.analyzeContent(new ByteArrayInputStream(fileContent))
                    );

                    // Attendi i risultati
                    FileValidationResult validation = validationFuture.get(30, TimeUnit.SECONDS);
                    ContentAnalysisResult analysis = analysisFuture.get(30, TimeUnit.SECONDS);

                    // Verifica risultati validazione
                    if (!validation.isValid()) {
                        failedFiles.add(originalFilename + ": " + validation.getMessage());
                        continue;
                    }

                    // Verifica risultati analisi contenuto
                    if (!analysis.isSafe()) {
                        failedFiles.add(originalFilename + ": " + analysis.getMessage());
                        continue;
                    }

                    // Salva il file in modo thread-safe
                    String safeFilename = validation.getSafeFilename();
                    fileManager.saveFileThreadSafe(
                            new ByteArrayInputStream(fileContent),
                            safeFilename,
                            userId
                    );

                    // Salva le informazioni nel database
                    UploadedFile uploadedFile = new UploadedFile();
                    uploadedFile.setUserId(userId);
                    uploadedFile.setOriginalFilename(originalFilename);
                    uploadedFile.setStoredFilename(safeFilename);
                    uploadedFile.setMimeType(validation.getDetectedMimeType());
                    uploadedFile.setFileSize(fileSize);

                    int fileId = fileDAO.saveFile(uploadedFile);

                    if (fileId > 0) {
                        uploadedFiles.add(originalFilename);
                    } else {
                        // Rollback: elimina il file dal filesystem
                        fileManager.deleteFileThreadSafe(safeFilename, userId);
                        failedFiles.add(originalFilename + ": errore database");
                    }

                } catch (Exception e) {
                    failedFiles.add(originalFilename + ": " + e.getMessage());
                }
            }

            // Prepara messaggio di risposta
            if (uploadedFiles.isEmpty() && failedFiles.isEmpty()) {
                setErrorAndForward(request, response, "Nessun file selezionato");
                return;
            }

            StringBuilder message = new StringBuilder();
            if (!uploadedFiles.isEmpty()) {
                message.append("File caricati: ").append(String.join(", ", uploadedFiles));
            }
            if (!failedFiles.isEmpty()) {
                if (message.length() > 0) message.append(" | ");
                message.append("Falliti: ").append(String.join("; ", failedFiles));
            }

            // Redirect alla dashboard
            if (failedFiles.isEmpty()) {
                response.sendRedirect(request.getContextPath() + "/dashboard?success=upload");
            } else if (uploadedFiles.isEmpty()) {
                setErrorAndForward(request, response, message.toString());
            } else {
                // Alcuni caricati, alcuni falliti
                response.sendRedirect(request.getContextPath() + "/dashboard?warning=" +
                        java.net.URLEncoder.encode(message.toString(), "UTF-8"));
            }

        } catch (Exception e) {
            System.err.println("Errore durante l'upload: " + e.getMessage());
            setErrorAndForward(request, response,
                    "Impossibile caricare il file. Verifica che sia un file .txt valido e riprova.");
        }
    }

    /**
     * Legge il contenuto del file in un byte array.
     */
    private byte[] readFileContent(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        int bytesRead;
        while ((bytesRead = inputStream.read(data)) != -1) {
            buffer.write(data, 0, bytesRead);
        }
        return buffer.toByteArray();
    }

    /**
     * Ottiene il nome del file dalla Part in modo compatibile.
     */
    private String getSubmittedFileName(Part part) {
        String contentDisposition = part.getHeader("content-disposition");
        String[] elements = contentDisposition.split(";");
        for (String element : elements) {
            if (element.trim().startsWith("filename")) {
                return element.substring(element.indexOf('=') + 1).trim()
                        .replace("\"", "");
            }
        }
        return "unknown";
    }

    /**
     * Imposta un messaggio di errore e inoltra alla pagina di upload.
     */
    private void setErrorAndForward(HttpServletRequest request, HttpServletResponse response,
                                    String errorMessage) throws ServletException, IOException {
        request.setAttribute("error", errorMessage);
        request.getRequestDispatcher("/upload.jsp").forward(request, response);
    }

    @Override
    public void destroy() {
        if (fileManager != null) {
            fileManager.shutdown();
        }
        if (validationExecutor != null) {
            validationExecutor.shutdown();
            try {
                if (!validationExecutor.awaitTermination(60, TimeUnit.SECONDS)) {
                    validationExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                validationExecutor.shutdownNow();
            }
        }
    }
}
