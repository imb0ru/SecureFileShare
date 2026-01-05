package app.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;

import app.config.AppConfig;

/**
 * Gestisce le connessioni al database in modo sicuro.
 *
 * Implementa le seguenti misure di sicurezza:
 * - Credenziali gestite da HashiCorp Vault (no hardcoding)
 * - Pulizia delle credenziali dopo l'uso
 * - URL configurabile da Vault
 *
 * @author Sicurezza nelle Applicazioni - UniBa
 */
public final class DatabaseConnection {

    // Costruttore privato
    private DatabaseConnection() {
        throw new AssertionError("Classe non istanziabile");
    }

    /**
     * Ottiene una connessione al database.
     * L'URL e le credenziali sono gestiti da HashiCorp Vault.
     *
     * @return la connessione al database
     * @throws SQLException se si verifica un errore di connessione
     * @throws ClassNotFoundException se il driver non è trovato
     */
    public static Connection getConnection() throws SQLException, ClassNotFoundException {
        // Carica il driver MySQL
        Class.forName("com.mysql.cj.jdbc.Driver");

        AppConfig config = AppConfig.getInstance();
        String url = config.getDbUrl();  // URL completo dal config
        String user = config.getDbUser();
        char[] password = config.getDbPassword();

        Connection connection = null;
        try {
            connection = DriverManager.getConnection(url, user, new String(password));
        } finally {
            // Pulisce la password dalla memoria
            Arrays.fill(password, '\0');
        }

        return connection;
    }

    /**
     * Chiude una connessione in modo sicuro.
     *
     * @param connection la connessione da chiudere
     */
    public static void closeConnection(Connection connection) {
        if (connection != null) {
            try {
                if (!connection.isClosed()) {
                    connection.close();
                }
            } catch (SQLException e) {
                // Log dell'errore senza esporre dettagli
                System.err.println("Errore durante la chiusura della connessione");
            }
        }
    }

    /**
     * Verifica se la connessione è valida.
     *
     * @param connection la connessione da verificare
     * @return true se la connessione è valida
     */
    public static boolean isConnectionValid(Connection connection) {
        if (connection == null) {
            return false;
        }
        try {
            return connection.isValid(5); // Timeout di 5 secondi
        } catch (SQLException e) {
            return false;
        }
    }
}
