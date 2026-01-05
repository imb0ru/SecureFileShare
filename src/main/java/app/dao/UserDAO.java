package app.dao;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Base64;

import app.model.User;
import app.security.CryptoManager;

/**
 * Data Access Object per la gestione degli utenti.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Uso esclusivo di PreparedStatement per prevenire SQL Injection
 * - CIFRATURA AES-256-GCM dell'email per protezione privacy (GDPR)
 * - HASH SHA-256 dell'email per ricerche efficienti (non reversibile)
 * - Gestione corretta delle risorse con try-with-resources
 * - Messaggi di errore generici che non rivelano dettagli interni
 *
 * SCHEMA DATABASE RICHIESTO:
 * - email_encrypted: email cifrata con AES (recuperabile)
 * - email_hash: hash SHA-256 dell'email (per ricerche)
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public class UserDAO {

    // Query SQL con parametri (PreparedStatement)
    // NOTA: email_encrypted contiene l'email cifrata, email_hash è per le ricerche
    private static final String INSERT_USER =
            "INSERT INTO users (email_encrypted, email_hash, password_hash, salt, created_at, active) VALUES (?, ?, ?, ?, ?, ?)";

    private static final String SELECT_USER_BY_EMAIL_HASH =
            "SELECT id, email_encrypted, email_hash, password_hash, salt, created_at, last_login, active FROM users WHERE email_hash = ?";

    private static final String SELECT_USER_BY_ID =
            "SELECT id, email_encrypted, email_hash, password_hash, salt, created_at, last_login, active FROM users WHERE id = ?";

    private static final String CHECK_EMAIL_EXISTS =
            "SELECT COUNT(*) FROM users WHERE email_hash = ?";

    private static final String UPDATE_LAST_LOGIN =
            "UPDATE users SET last_login = ? WHERE id = ?";

    private static final String UPDATE_PASSWORD =
            "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?";

    private static final String DEACTIVATE_USER =
            "UPDATE users SET active = 0 WHERE id = ?";

    // CryptoManager per cifratura email
    private CryptoManager cryptoManager;

    /**
     * Inizializza il CryptoManager (lazy loading).
     */
    private CryptoManager getCryptoManager() {
        if (cryptoManager == null) {
            cryptoManager = CryptoManager.getInstance();
        }
        return cryptoManager;
    }

    /**
     * Calcola l'hash SHA-256 dell'email per le ricerche.
     * L'hash è deterministico quindi la stessa email produce sempre lo stesso hash.
     *
     * @param email l'email da hashare
     * @return l'hash in Base64
     */
    private String hashEmail(String email) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(email.toLowerCase().trim().getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Errore calcolo hash email", e);
        }
    }

    /**
     * Cifra l'email con AES-256-GCM.
     *
     * @param email l'email da cifrare
     * @return l'email cifrata in Base64
     */
    private String encryptEmail(String email) {
        try {
            return getCryptoManager().encrypt(email.toLowerCase().trim());
        } catch (CryptoManager.CryptoException e) {
            throw new RuntimeException("Errore cifratura email", e);
        }
    }

    /**
     * Decifra l'email con AES-256-GCM.
     *
     * @param encryptedEmail l'email cifrata in Base64
     * @return l'email in chiaro
     */
    private String decryptEmail(String encryptedEmail) {
        try {
            return getCryptoManager().decrypt(encryptedEmail);
        } catch (CryptoManager.CryptoException e) {
            throw new RuntimeException("Errore decifratura email", e);
        }
    }

    /**
     * Registra un nuovo utente nel database.
     * L'email viene CIFRATA prima del salvataggio.
     *
     * @param email l'email dell'utente (verrà cifrata)
     * @param passwordHash l'hash della password
     * @param salt il salt usato per l'hash
     * @return l'ID dell'utente creato, o -1 in caso di errore
     */
    public int registerUser(String email, byte[] passwordHash, byte[] salt) {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet generatedKeys = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(INSERT_USER, Statement.RETURN_GENERATED_KEYS);

            String normalizedEmail = email.toLowerCase().trim();

            // Cifra l'email per privacy
            String encryptedEmail = encryptEmail(normalizedEmail);

            // Calcola hash per ricerche
            String emailHash = hashEmail(normalizedEmail);

            // Imposta i parametri in modo sicuro (no concatenazione)
            stmt.setString(1, encryptedEmail);      // email cifrata
            stmt.setString(2, emailHash);           // hash per ricerche
            stmt.setBytes(3, passwordHash);
            stmt.setBytes(4, salt);
            stmt.setTimestamp(5, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setBoolean(6, true);

            int affectedRows = stmt.executeUpdate();

            if (affectedRows == 0) {
                return -1;
            }

            generatedKeys = stmt.getGeneratedKeys();
            if (generatedKeys.next()) {
                System.out.println("[UserDAO] Utente registrato con email cifrata");
                return generatedKeys.getInt(1);
            }

            return -1;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante la registrazione dell'utente: " + e.getMessage());
            e.printStackTrace();
            return -1;
        } finally {
            closeResources(generatedKeys, stmt, connection);
        }
    }

    /**
     * Cerca un utente per email.
     * La ricerca avviene tramite hash, poi l'email viene decifrata.
     *
     * @param email l'email da cercare
     * @return l'utente trovato o null
     */
    public User findByEmail(String email) {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(SELECT_USER_BY_EMAIL_HASH);

            // Cerca per hash dell'email (efficiente)
            String emailHash = hashEmail(email.toLowerCase().trim());
            stmt.setString(1, emailHash);

            rs = stmt.executeQuery();

            if (rs.next()) {
                return mapResultSetToUser(rs);
            }

            return null;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante la ricerca dell'utente per email: " + e.getMessage());
            e.printStackTrace();
            return null;
        } finally {
            closeResources(rs, stmt, connection);
        }
    }

    /**
     * Cerca un utente per ID.
     *
     * @param id l'ID dell'utente
     * @return l'utente trovato o null
     */
    public User findById(int id) {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(SELECT_USER_BY_ID);
            stmt.setInt(1, id);

            rs = stmt.executeQuery();

            if (rs.next()) {
                return mapResultSetToUser(rs);
            }

            return null;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante la ricerca dell'utente per ID: " + e.getMessage());
            e.printStackTrace();
            return null;
        } finally {
            closeResources(rs, stmt, connection);
        }
    }

    /**
     * Verifica se un'email è già registrata.
     * La ricerca avviene tramite hash, preservando la privacy.
     *
     * @param email l'email da verificare
     * @return true se l'email esiste
     */
    public boolean emailExists(String email) {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(CHECK_EMAIL_EXISTS);

            // Cerca per hash
            String emailHash = hashEmail(email.toLowerCase().trim());
            stmt.setString(1, emailHash);

            rs = stmt.executeQuery();

            if (rs.next()) {
                return rs.getInt(1) > 0;
            }

            return false;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante la verifica dell'email: " + e.getMessage());
            e.printStackTrace();
            return false;
        } finally {
            closeResources(rs, stmt, connection);
        }
    }

    /**
     * Aggiorna l'ultimo accesso dell'utente.
     *
     * @param userId l'ID dell'utente
     * @return true se l'aggiornamento è riuscito
     */
    public boolean updateLastLogin(int userId) {
        Connection connection = null;
        PreparedStatement stmt = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(UPDATE_LAST_LOGIN);
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setInt(2, userId);

            return stmt.executeUpdate() > 0;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante l'aggiornamento dell'ultimo accesso");
            return false;
        } finally {
            closeResources(null, stmt, connection);
        }
    }

    /**
     * Aggiorna la password dell'utente.
     *
     * @param userId l'ID dell'utente
     * @param newPasswordHash il nuovo hash della password
     * @param newSalt il nuovo salt
     * @return true se l'aggiornamento è riuscito
     */
    public boolean updatePassword(int userId, byte[] newPasswordHash, byte[] newSalt) {
        Connection connection = null;
        PreparedStatement stmt = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(UPDATE_PASSWORD);
            stmt.setBytes(1, newPasswordHash);
            stmt.setBytes(2, newSalt);
            stmt.setInt(3, userId);

            return stmt.executeUpdate() > 0;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante l'aggiornamento della password");
            return false;
        } finally {
            closeResources(null, stmt, connection);
        }
    }

    /**
     * Disattiva un utente (soft delete).
     *
     * @param userId l'ID dell'utente
     * @return true se la disattivazione è riuscita
     */
    public boolean deactivateUser(int userId) {
        Connection connection = null;
        PreparedStatement stmt = null;

        try {
            connection = DatabaseConnection.getConnection();
            stmt = connection.prepareStatement(DEACTIVATE_USER);
            stmt.setInt(1, userId);

            return stmt.executeUpdate() > 0;

        } catch (SQLException | ClassNotFoundException e) {
            System.err.println("Errore durante la disattivazione dell'utente");
            return false;
        } finally {
            closeResources(null, stmt, connection);
        }
    }

    /**
     * Mappa un ResultSet a un oggetto User.
     * DECIFRA l'email prima di restituirla.
     *
     * @param rs il ResultSet
     * @return l'oggetto User
     * @throws SQLException in caso di errore
     */
    private User mapResultSetToUser(ResultSet rs) throws SQLException {
        User user = new User();
        user.setId(rs.getInt("id"));

        // DECIFRA l'email
        String encryptedEmail = rs.getString("email_encrypted");
        String decryptedEmail = decryptEmail(encryptedEmail);
        user.setEmail(decryptedEmail);

        user.setPasswordHash(rs.getBytes("password_hash"));
        user.setSalt(rs.getBytes("salt"));

        Timestamp createdAt = rs.getTimestamp("created_at");
        if (createdAt != null) {
            user.setCreatedAt(createdAt.toLocalDateTime());
        }

        Timestamp lastLogin = rs.getTimestamp("last_login");
        if (lastLogin != null) {
            user.setLastLogin(lastLogin.toLocalDateTime());
        }

        user.setActive(rs.getBoolean("active"));

        return user;
    }

    /**
     * Chiude le risorse in modo sicuro.
     *
     * @param rs il ResultSet
     * @param stmt il PreparedStatement
     * @param connection la Connection
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
