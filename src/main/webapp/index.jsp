<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="SecureFileShare - Piattaforma sicura per la condivisione di file testuali">
    <meta name="author" content="Sicurezza nelle Applicazioni - UniBa">
    <title>SecureFileShare - Home</title>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css">
</head>
<body>
    <div class="auth-container">
        <div class="card">
            <div class="card-header" style="text-align: center; border-bottom: none; padding-bottom: 0;">
                <h1 style="font-size: 1.8rem; color: var(--primary-color); margin-bottom: 8px;">
                    🔒 SecureFileShare
                </h1>
                <p style="color: var(--text-muted); font-size: 1rem; margin: 0;">
                    Piattaforma Sicura per la Condivisione di File
                </p>
            </div>
            
            <div class="welcome-content" style="padding: 25px 0;">
                <p style="text-align: left; margin-bottom: 20px; color: var(--text-color); line-height: 1.6;">
                    Benvenuto in SecureFileShare, un'applicazione web sviluppata seguendo i principi della 
                    <strong>secure software development</strong>.
                </p>
                
                <div class="features-box" style="margin-bottom: 20px;">
                    <h3 style="font-size: 1.1rem; color: var(--primary-color); margin-bottom: 15px;">
                        Funzionalità Principali
                    </h3>
                    <ul style="list-style: none; padding: 0; margin: 0;">
                        <li style="padding: 8px 0; padding-left: 28px; position: relative; color: var(--text-color);">
                            <span style="position: absolute; left: 0; color: var(--success-color);">✓</span>
                            Registrazione e autenticazione sicura
                        </li>
                        <li style="padding: 8px 0; padding-left: 28px; position: relative; color: var(--text-color);">
                            <span style="position: absolute; left: 0; color: var(--success-color);">✓</span>
                            Gestione sessioni con cookie protetti
                        </li>
                        <li style="padding: 8px 0; padding-left: 28px; position: relative; color: var(--text-color);">
                            <span style="position: absolute; left: 0; color: var(--success-color);">✓</span>
                            Caricamento file controllato e validato
                        </li>
                        <li style="padding: 8px 0; padding-left: 28px; position: relative; color: var(--text-color);">
                            <span style="position: absolute; left: 0; color: var(--success-color);">✓</span>
                            Visualizzazione contenuti sicura (anti-XSS)
                        </li>
                        <li style="padding: 8px 0; padding-left: 28px; position: relative; color: var(--text-color);">
                            <span style="position: absolute; left: 0; color: var(--success-color);">✓</span>
                            Condivisione file tra utenti
                        </li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin-top: 20px;">
                    <span style="display: inline-block; background-color: #e8f5e9; color: #2e7d32; 
                                 padding: 10px 18px; border-radius: 25px; font-size: 0.9rem; font-weight: 500;
                                 border: 1px solid #c8e6c9;">
                        🛡️ Protezione contro SQL Injection, XSS, CSRF, Session Hijacking
                    </span>
                </div>
            </div>
            
            <div class="welcome-buttons" style="display: flex; flex-direction: column; gap: 12px; padding-top: 10px;">
                <a href="${pageContext.request.contextPath}/login" class="btn btn-primary btn-block">
                    Accedi
                </a>
                <a href="${pageContext.request.contextPath}/register" class="btn btn-success btn-block">
                    Registrati
                </a>
            </div>
            
            <div class="auth-footer" style="text-align: center; margin-top: 25px; padding-top: 20px; 
                                            border-top: 1px solid var(--border-color);">
                <p style="margin: 0; color: var(--text-muted); font-size: 0.9rem;">
                    Progetto Sicurezza nelle Applicazioni
                </p>
                <p style="margin: 5px 0 0 0; color: var(--text-muted); font-size: 0.9rem;">
                    Università degli Studi di Bari Aldo Moro - A.A. 2025/2026
                </p>
            </div>
        </div>
    </div>
</body>
</html>
