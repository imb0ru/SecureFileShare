<%-- 
  ============================================
  SecureFileShare - Dashboard
  ============================================
  Dashboard principale utente autenticato.
  
  SICUREZZA IMPLEMENTATA:
  - Accesso protetto da AuthenticationFilter
  - Output sanitizzato con JSTL c:out (anti-XSS)
  - Cache disabilitata (no-store) per dati sensibili
  - Logout via POST (protezione CSRF)
  - Nomi file sanitizzati prima della visualizzazione
  
  @author Sicurezza nelle Applicazioni - UniBa
  ============================================
--%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<%@ taglib prefix="fn" uri="jakarta.tags.functions" %>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Dashboard - SecureFileShare</title>
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
                        <span class="user-info">
                            👤 <c:out value="${sessionScope.authenticatedUser}" escapeXml="true"/>
                        </span>
                    </li>
                    <li>
                        <a href="${pageContext.request.contextPath}/upload" class="btn btn-primary btn-sm">
                            📤 Carica File
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
            <%-- Messaggi di feedback --%>
            <c:if test="${not empty param.success}">
                <div class="message message-success">
                    <c:choose>
                        <c:when test="${param.success == 'upload'}">
                            ✓ File caricato con successo!
                        </c:when>
                        <c:when test="${param.success == 'deleted'}">
                            ✓ File eliminato con successo!
                        </c:when>
                        <c:when test="${param.success == 'delete'}">
                            ✓ File eliminato con successo!
                        </c:when>
                        <c:otherwise>
                            ✓ Operazione completata con successo.
                        </c:otherwise>
                    </c:choose>
                </div>
            </c:if>
            
            <%-- Warning mostrato solo per valori noti --%>
            <c:if test="${param.warning == 'partial_upload'}">
                <div class="message message-warning" style="background-color: #fff3cd; border-color: #ffc107; color: #856404;">
                    ⚠️ Alcuni file non sono stati caricati.
                </div>
            </c:if>
            
            <c:if test="${not empty param.error}">
                <div class="message message-error">
                    ✗ <c:choose>
                        <c:when test="${param.error == 'invalid_file'}">
                            ID file non valido o mancante.
                        </c:when>
                        <c:when test="${param.error == 'file_not_found'}">
                            Il file richiesto non esiste o è stato già eliminato.
                        </c:when>
                        <c:when test="${param.error == 'unauthorized'}">
                            Non hai i permessi per eliminare questo file.
                        </c:when>
                        <c:when test="${param.error == 'delete_failed'}">
                            Impossibile eliminare il file. Riprova più tardi.
                        </c:when>
                        <c:when test="${param.error == 'session_required'}">
                            Devi effettuare il login per accedere a questa pagina.
                        </c:when>
                        <c:otherwise>
                            Si è verificato un errore. Riprova.
                        </c:otherwise>
                    </c:choose>
                </div>
            </c:if>
            
            <c:if test="${not empty error}">
                <div class="message message-error">
                    ✗ <c:out value="${error}" escapeXml="true"/>
                </div>
            </c:if>

            <%-- Sezione: I Miei File --%>
            <section class="card">
                <div class="card-header">
                    <div class="section-header">
                        <h2>📁 I Miei File</h2>
                        <a href="${pageContext.request.contextPath}/upload" class="btn btn-primary btn-sm">
                            + Nuovo File
                        </a>
                    </div>
                </div>
                
                <c:choose>
                    <c:when test="${empty userFiles}">
                        <div class="empty-state">
                            <div class="empty-state-icon">📂</div>
                            <p>Non hai ancora caricato alcun file.</p>
                            <a href="${pageContext.request.contextPath}/upload" class="btn btn-primary">
                                Carica il tuo primo file
                            </a>
                        </div>
                    </c:when>
                    <c:otherwise>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Nome File</th>
                                        <th>Dimensione</th>
                                        <th>Data Caricamento</th>
                                        <th>Azioni</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <c:forEach var="file" items="${userFiles}">
                                        <tr>
                                            <td>
                                                📄 <c:out value="${file.originalFilename}" escapeXml="true"/>
                                            </td>
                                            <td>
                                                <c:out value="${file.formattedFileSize}" escapeXml="true"/>
                                            </td>
                                            <td>
                                                <c:out value="${file.uploadedAt}" escapeXml="true"/>
                                            </td>
                                            <td class="actions">
                                                <a href="${pageContext.request.contextPath}/content/${file.id}" 
                                                   class="btn btn-sm btn-primary">
                                                    👁️ Visualizza
                                                </a>
                                                <a href="${pageContext.request.contextPath}/content/${file.id}?download=true" 
                                                   class="btn btn-sm btn-secondary">
                                                    ⬇️ Scarica
                                                </a>
                                                <form action="${pageContext.request.contextPath}/delete" method="POST" 
                                                      style="display:inline;" class="delete-form">
                                                    <input type="hidden" name="fileId" value="${file.id}"/>
                                                    <button type="submit" class="btn btn-sm btn-danger">
                                                        🗑️ Elimina
                                                    </button>
                                                </form>
                                            </td>
                                        </tr>
                                    </c:forEach>
                                </tbody>
                            </table>
                        </div>
                    </c:otherwise>
                </c:choose>
            </section>

            <%-- Sezione: Contenuti Condivisi --%>
            <section class="card">
                <div class="card-header">
                    <h2>🌐 Contenuti Condivisi</h2>
                </div>
                <p style="color: var(--text-muted); margin-bottom: 15px;">
                    Visualizza i file caricati da tutti gli utenti della piattaforma.
                </p>
                
                <c:choose>
                    <c:when test="${empty allFiles}">
                        <div class="empty-state">
                            <div class="empty-state-icon">📭</div>
                            <p>Nessun contenuto condiviso disponibile.</p>
                        </div>
                    </c:when>
                    <c:otherwise>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Nome File</th>
                                        <th>Autore</th>
                                        <th>Dimensione</th>
                                        <th>Data</th>
                                        <th>Azioni</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <c:forEach var="file" items="${allFiles}">
                                        <tr>
                                            <td>
                                                📄 <c:out value="${file.originalFilename}" escapeXml="true"/>
                                            </td>
                                            <td>
                                                👤 <c:out value="${file.ownerEmail}" escapeXml="true"/>
                                            </td>
                                            <td>
                                                <c:out value="${file.formattedFileSize}" escapeXml="true"/>
                                            </td>
                                            <td>
                                                <c:out value="${file.uploadedAt}" escapeXml="true"/>
                                            </td>
                                            <td class="actions">
                                                <a href="${pageContext.request.contextPath}/content/${file.id}" 
                                                   class="btn btn-sm btn-primary">
                                                    👁️ Visualizza
                                                </a>
                                            </td>
                                        </tr>
                                    </c:forEach>
                                </tbody>
                            </table>
                        </div>
                    </c:otherwise>
                </c:choose>
            </section>
        </main>
    </div>

    <footer>
        <p>🔒 SecureFileShare - Progetto Sicurezza nelle Applicazioni - UniBa 2025/2026</p>
    </footer>
    
    <script src="${pageContext.request.contextPath}/js/app.js"></script>
    
    <%-- Script con nonce CSP per conferma eliminazione --%>
    <script nonce="${cspNonce}">
        // Aggiungi conferma a tutti i form di eliminazione
        document.querySelectorAll('.delete-form').forEach(function(form) {
            form.addEventListener('submit', function(e) {
                if (!confirm('Sei sicuro di voler eliminare questo file?')) {
                    e.preventDefault();
                }
            });
        });
    </script>
</body>
</html>
