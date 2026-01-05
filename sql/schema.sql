-- ============================================
-- SecureFileShare Database Schema
-- Università degli Studi di Bari - Sicurezza nelle Applicazioni
-- Anno Accademico 2025/2026
-- ============================================
--
-- SICUREZZA IMPLEMENTATA:
-- - Email cifrate con AES-256-GCM (privacy GDPR)
-- - Hash email per ricerche efficienti (non reversibile)
-- - Password con PBKDF2-SHA256 + salt
-- - Principio del minimo privilegio per utente DB
--
-- ============================================

-- Eliminare il database se esiste (SOLO per sviluppo!)
-- DROP DATABASE IF EXISTS secure_file_share;

-- Creazione database con charset UTF-8
CREATE DATABASE IF NOT EXISTS secure_file_share
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE secure_file_share;

-- ============================================
-- Tabella Utenti
-- ============================================
-- NOTA:
-- - email_encrypted: email cifrata con AES-256-GCM (recuperabile)
-- - email_hash: hash SHA-256 dell'email (per ricerche, non reversibile)
-- ============================================
CREATE TABLE IF NOT EXISTS users (
                                     id INT AUTO_INCREMENT PRIMARY KEY,

    -- Email cifrata con AES-256-GCM (Base64, ~500 chars per email 254)
                                     email_encrypted VARCHAR(512) NOT NULL,

    -- Hash SHA-256 dell'email per ricerche (44 chars in Base64)
    email_hash VARCHAR(64) NOT NULL UNIQUE,

    -- Password hashata con PBKDF2-SHA256
    password_hash VARBINARY(256) NOT NULL,

    -- Salt casuale per PBKDF2
    salt VARBINARY(32) NOT NULL,

    -- Timestamp
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,

    -- Stato account
    active BOOLEAN DEFAULT TRUE,

    -- Indici
    INDEX idx_email_hash (email_hash),
    INDEX idx_active (active)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Tabella File Caricati
-- ============================================
-- NOTA: I file sono cifrati con AES-256-GCM sul filesystem
-- Il campo stored_filename punta al file .enc cifrato
-- ============================================
CREATE TABLE IF NOT EXISTS uploaded_files (
                                              id INT AUTO_INCREMENT PRIMARY KEY,
                                              user_id INT NOT NULL,

    -- Nome originale del file (può contenere info sensibili, non cifrato qui)
                                              original_filename VARCHAR(255) NOT NULL,

    -- Nome sul filesystem (UUID + .enc)
    stored_filename VARCHAR(255) NOT NULL UNIQUE,

    -- Tipo MIME
    mime_type VARCHAR(100) NOT NULL DEFAULT 'text/plain',

    -- Dimensione file originale (prima della cifratura)
    file_size BIGINT NOT NULL,

    -- Timestamp upload
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Foreign key con cascade delete
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,

    -- Indici
    INDEX idx_user_id (user_id),
    INDEX idx_stored_filename (stored_filename),
    INDEX idx_uploaded_at (uploaded_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Creazione Utente Applicazione (principio minimo privilegio)
-- ============================================
-- Crea utente sia per localhost che per connessioni Docker
CREATE USER IF NOT EXISTS 'secure_app_user'@'localhost'
    IDENTIFIED BY 'SecureP@ssw0rd2026!';

CREATE USER IF NOT EXISTS 'secure_app_user'@'%'
    IDENTIFIED BY 'SecureP@ssw0rd2026!';

-- Permessi minimi necessari per l'applicazione
GRANT SELECT, INSERT, UPDATE, DELETE ON secure_file_share.users TO 'secure_app_user'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON secure_file_share.uploaded_files TO 'secure_app_user'@'localhost';

GRANT SELECT, INSERT, UPDATE, DELETE ON secure_file_share.users TO 'secure_app_user'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON secure_file_share.uploaded_files TO 'secure_app_user'@'%';

FLUSH PRIVILEGES;
