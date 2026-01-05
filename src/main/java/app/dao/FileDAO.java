package app.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import app.model.UploadedFile;
import app.security.CryptoManager;

/**
 * Data Access Object per la gestione dei file caricati.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Uso esclusivo di PreparedStatement per prevenire SQL Injection
 * - Nessuna concatenazione di stringhe nelle query
 * - Gestione corretta delle risorse
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public class FileDAO {

    // Query SQL con parametri
    private static final String INSERT_FILE =
            "INSERT INTO uploaded_files (user_id, original_filename, stored_filename, mime_type, file_size, uploaded_at) " +
                    "VALUES (?, ?, ?, ?, ?, ?)";

    private static final String SELECT_FILE_BY_ID =
            "SELECT id, user_id, original_filename, stored_filename, mime_type, file_size, uploaded_at " +
                    "FROM uploaded_files WHERE id = ?";

    private static final String SELECT_FILES_BY_USER =
            "SELECT id, user_id, original_filename, stored_filename, mime_type, file_size, uploaded_at " +
                    "FROM uploaded_files WHERE user_id = ? ORDER BY uploaded_at DESC";

    private static final String SELECT_ALL_FILES =
            "SELECT f.id, f.user_id, f.original_filename, f.stored_filename, f.mime_type, f.file_size, " +
                    "f.uploaded_at, u.email_encrypted as user_email_encrypted " +
                    "FROM uploaded_files f JOIN users u ON f.user_id = u.id " +
                    "ORDER BY f.uploaded_at DESC";

    private static final String DELETE_FILE =
            "DELETE FROM uploaded_files WHERE id = ? AND user_id = ?";

    private static final String SELECT_FILE_BY_STORED_NAME =
            "SELECT id, user_id, original_filename, stored_filename, mime_type, file_size, uploaded_at " +
                    "FROM uploaded_files WHERE stored_filename = ?";

    /**
     * Salva le informazioni di un file caricato.
     *
     * @param file l'oggetto UploadedFile
     * @return l'ID del file salvato o -1 in caso di errore
     */
    public int saveFile(UploadedFile file) {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet generatedKeys = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(INSERT_FILE, Statement.RETURN_GENERATED_KEYS);

            stmt.setInt(1, file.getUserId());
            stmt.setString(2, file.getOriginalFilename());
            stmt.setString(3, file.getStoredFilename());
            stmt.setString(4, file.getMimeType());
            stmt.setLong(5, file.getFileSize());
            stmt.setTimestamp(6, Timestamp.valueOf(LocalDateTime.now()));

            int affectedRows = stmt.executeUpdate();

            if (affectedRows == 0) {
                return -1;
            }

            generatedKeys = stmt.getGeneratedKeys();
            if (generatedKeys.next()) {
                return generatedKeys.getInt(1);
            }

            return -1;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante il salvataggio del file");
            return -1;
        } finally {
            closeResources(generatedKeys, stmt, connection);
        }
    }

    /**
     * Cerca un file per ID.
     *
     * @param fileId l'ID del file
     * @return il file trovato o null
     */
    public UploadedFile findById(int fileId) {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(SELECT_FILE_BY_ID);
            stmt.setInt(1, fileId);

            rs = stmt.executeQuery();

            if (rs.next()) {
                return mapResultSetToFile(rs);
            }

            return null;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante la ricerca del file");
            return null;
        } finally {
            closeResources(rs, stmt, connection);
        }
    }

    /**
     * Cerca un file per nome memorizzato.
     *
     * @param storedFilename il nome memorizzato
     * @return il file trovato o null
     */
    public UploadedFile findByStoredFilename(String storedFilename) {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(SELECT_FILE_BY_STORED_NAME);
            stmt.setString(1, storedFilename);

            rs = stmt.executeQuery();

            if (rs.next()) {
                return mapResultSetToFile(rs);
            }

            return null;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante la ricerca del file");
            return null;
        } finally {
            closeResources(rs, stmt, connection);
        }
    }

    /**
     * Ottiene tutti i file di un utente.
     *
     * @param userId l'ID dell'utente
     * @return lista dei file dell'utente
     */
    public List<UploadedFile> findByUserId(int userId) {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        List<UploadedFile> files = new ArrayList<>();

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(SELECT_FILES_BY_USER);
            stmt.setInt(1, userId);

            rs = stmt.executeQuery();

            while (rs.next()) {
                files.add(mapResultSetToFile(rs));
            }

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante il recupero dei file");
        } finally {
            closeResources(rs, stmt, connection);
        }

        return files;
    }

    /**
     * Ottiene tutti i file con informazioni sull'utente.
     * L'email dell'utente viene DECIFRATA prima di essere restituita.
     *
     * @return lista di tutti i file
     */
    public List<UploadedFile> findAllWithUserInfo() {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        List<UploadedFile> files = new ArrayList<>();

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(SELECT_ALL_FILES);

            rs = stmt.executeQuery();

            CryptoManager crypto = CryptoManager.getInstance();

            while (rs.next()) {
                UploadedFile file = mapResultSetToFile(rs);
                // Decifra e aggiunge l'email dell'utente
                try {
                    String encryptedEmail = rs.getString("user_email_encrypted");
                    if (encryptedEmail != null) {
                        String decryptedEmail = crypto.decrypt(encryptedEmail);
                        file.setUserEmail(decryptedEmail);
                    }
                } catch (Exception e) {
                    // La colonna potrebbe non essere presente o decifratura fallita
                    System.err.println("Errore decifratura email: " + e.getMessage());
                }
                files.add(file);
            }

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante il recupero dei file");
        } finally {
            closeResources(rs, stmt, connection);
        }

        return files;
    }

    /**
     * Elimina un file dal database.
     *
     * @param fileId l'ID del file
     * @param userId l'ID dell'utente proprietario
     * @return true se l'eliminazione è riuscita
     */
    public boolean deleteFile(int fileId, int userId) {
        Connection connection = null;
        PreparedStatement stmt = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(DELETE_FILE);
            stmt.setInt(1, fileId);
            stmt.setInt(2, userId);

            return stmt.executeUpdate() > 0;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante l'eliminazione del file");
            return false;
        } finally {
            closeResources(null, stmt, connection);
        }
    }

    /**
     * Mappa un ResultSet a un oggetto UploadedFile.
     */
    private UploadedFile mapResultSetToFile(ResultSet rs) throws SQLException {
        UploadedFile file = new UploadedFile();
        file.setId(rs.getInt("id"));
        file.setUserId(rs.getInt("user_id"));
        file.setOriginalFilename(rs.getString("original_filename"));
        file.setStoredFilename(rs.getString("stored_filename"));
        file.setMimeType(rs.getString("mime_type"));
        file.setFileSize(rs.getLong("file_size"));

        Timestamp uploadedAt = rs.getTimestamp("uploaded_at");
        if (uploadedAt != null) {
            file.setUploadedAt(uploadedAt.toLocalDateTime());
        }

        return file;
    }

    /**
     * Chiude le risorse in modo sicuro.
     */
    private void closeResources(ResultSet rs, PreparedStatement stmt, Connection connection) {
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException e) {
                // Ignora
            }
        }
        if (stmt != null) {
            try {
                stmt.close();
            } catch (SQLException e) {
                // Ignora
            }
        }
        DatabaseConnection.closeConnection(connection);
    }
}
