<%-- 
  ============================================
  SecureFileShare - View Content Page
  ============================================
  Visualizza il contenuto di un file testuale.
  
  SICUREZZA IMPLEMENTATA:
  - Accesso protetto da AuthenticationFilter
  - Contenuto file SANITIZZATO con c:out (anti-XSS)
  - File decifrato lato server (AES-256-GCM)
  - Nessun contenuto eseguibile renderizzato
  
  NOTA: Il contenuto mostrato passa attraverso
  JSTL c:out che esegue HTML escaping automatico.
  
  @author Sicurezza nelle Applicazioni - UniBa
  ============================================
--%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Visualizza Contenuto - SecureFileShare</title>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css">
</head>
<body>
    <header>
        <div class="container">
            <div class="logo">
                <span class="logo-icon">🔒</span>
                <h1>SecureFileShare</h1>
            </div>
            <nav>
                <ul>
                    <li>
                        <a href="${pageContext.request.contextPath}/dashboard" class="btn btn-secondary btn-sm">
                            ← Dashboard
                        </a>
                    </li>
                    <li>
                        <form action="${pageContext.request.contextPath}/logout" method="POST" style="display:inline;">
                            <button type="submit" class="btn btn-danger btn-sm">
                                🚪 Logout
                            </button>
                        </form>
                    </li>
                </ul>
            </nav>
        </div>
    </header>

    <div class="container">
        <main>
            <%-- Messaggi di errore --%>
            <c:if test="${not empty error}">
                <div class="message message-error">
                    ✗ <c:out value="${error}" escapeXml="true"/>
                </div>
                <div class="card">
                    <a href="${pageContext.request.contextPath}/dashboard" class="btn btn-primary">
                        ← Torna alla Dashboard
                    </a>
                </div>
            </c:if>

            <c:if test="${not empty file}">
                <%-- Informazioni file --%>
                <div class="card">
                    <div class="card-header">
                        <h2>📄 <c:out value="${file.originalFilename}" escapeXml="true"/></h2>
                    </div>
                    
                    <div class="file-info">
                        <p><strong>📐 Dimensione:</strong> <c:out value="${file.formattedFileSize}" escapeXml="true"/></p>
                        <p><strong>📋 Tipo MIME:</strong> <c:out value="${file.mimeType}" escapeXml="true"/></p>
                        <p><strong>📅 Caricato il:</strong> <c:out value="${file.uploadedAt}" escapeXml="true"/></p>
                        <c:if test="${not empty file.ownerEmail}">
                            <p><strong>👤 Autore:</strong> <c:out value="${file.ownerEmail}" escapeXml="true"/></p>
                        </c:if>
                    </div>
                    
                    <div class="actions" style="margin-top: 15px;">
                        <a href="${pageContext.request.contextPath}/content/${file.id}?download=true" 
                           class="btn btn-primary">
                            ⬇️ Scarica File
                        </a>
                        <a href="${pageContext.request.contextPath}/dashboard" 
                           class="btn btn-secondary">
                            ← Torna alla Dashboard
                        </a>
                    </div>
                </div>

                <%-- Contenuto del file --%>
                <div class="card">
                    <div class="card-header">
                        <h3>📝 Contenuto del File</h3>
                    </div>
                    
                    <div class="content-display">
                        <%-- 
                            SICUREZZA XSS: Il contenuto è visualizzato in modo sicuro.
                            1. Il contenuto è già stato sanitizzato lato server con InputValidator.sanitizeForHtml()
                            2. Usiamo c:out con escapeXml="true" per un ulteriore livello di protezione
                            3. Il tag <pre> preserva la formattazione senza interpretare HTML
                            
                            Eventuali tag HTML o script nel file originale vengono visualizzati
                            come testo e NON vengono eseguiti dal browser.
                        --%>
                        <pre><c:out value="${content}" escapeXml="true"/></pre>
                    </div>
                    
                    <%-- Nota sulla sicurezza --%>
                    <div class="message message-info" style="margin-top: 20px;">
                        <strong>🛡️ Nota sulla Sicurezza:</strong> 
                        Il contenuto visualizzato è stato processato per prevenire attacchi XSS. 
                        Eventuali tag HTML, script o codice potenzialmente pericoloso sono stati 
                        convertiti in testo sicuro e non verranno eseguiti dal browser.
                    </div>
                </div>
            </c:if>

            <%-- Se né file né errore sono presenti --%>
            <c:if test="${empty file and empty error}">
                <div class="card">
                    <div class="message message-warning">
                        ⚠️ File non trovato o non accessibile.
                    </div>
                    <a href="${pageContext.request.contextPath}/dashboard" class="btn btn-primary">
                        ← Torna alla Dashboard
                    </a>
                </div>
            </c:if>
        </main>
    </div>

    <footer>
        <p>🔒 SecureFileShare - Progetto Sicurezza nelle Applicazioni - UniBa 2025/2026</p>
    </footer>
</body>
</html>
