<%-- 
  ============================================
  SecureFileShare - Login Page
  ============================================
  Pagina di autenticazione utente.
  
  SICUREZZA IMPLEMENTATA:
  - Output sanitizzato con JSTL c:out (anti-XSS)
  - Form action verso servlet (no logica inline)
  - Autocomplete controllato per sicurezza
  - Messaggi di errore generici (no info disclosure)
  
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
    <title>Login - SecureFileShare</title>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css">
</head>
<body>
    <div class="auth-container">
        <div class="card">
            <div class="card-header">
                <h1>🔒 SecureFileShare</h1>
                <h2>Accesso</h2>
            </div>
            
            <%-- Messaggi di errore (sanitizzati tramite JSTL c:out) --%>
            <c:if test="${not empty error}">
                <div class="message message-error">
                    <c:out value="${error}" escapeXml="true"/>
                </div>
            </c:if>
            
            <c:if test="${not empty param.error}">
                <div class="message message-error">
                    <c:choose>
                        <c:when test="${param.error == 'session_expired'}">
                            La sessione è scaduta. Effettua nuovamente l'accesso.
                        </c:when>
                        <c:when test="${param.error == 'session_required'}">
                            Devi effettuare l'accesso per visualizzare questa pagina.
                        </c:when>
                        <c:when test="${param.error == 'invalid_session'}">
                            Sessione non valida. Effettua nuovamente l'accesso.
                        </c:when>
                        <c:when test="${param.error == 'invalid_credentials'}">
                            Email o password non corretti.
                        </c:when>
                        <c:otherwise>
                            Si è verificato un errore. Riprova.
                        </c:otherwise>
                    </c:choose>
                </div>
            </c:if>
            
            <%-- Messaggi di successo --%>
            <c:if test="${not empty success}">
                <div class="message message-success">
                    <c:out value="${success}" escapeXml="true"/>
                </div>
            </c:if>
            
            <c:if test="${param.registered == 'true'}">
                <div class="message message-success">
                    ✓ Registrazione completata con successo! Ora puoi accedere.
                </div>
            </c:if>
            
            <c:if test="${not empty param.success}">
                <div class="message message-success">
                    <c:choose>
                        <c:when test="${param.success == 'registered'}">
                            Registrazione completata! Ora puoi accedere.
                        </c:when>
                        <c:when test="${param.success == 'logout'}">
                            Logout effettuato con successo.
                        </c:when>
                        <c:otherwise>
                            Operazione completata con successo.
                        </c:otherwise>
                    </c:choose>
                </div>
            </c:if>
            
            <form action="${pageContext.request.contextPath}/login" method="POST" autocomplete="off">
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" 
                           id="email" 
                           name="email" 
                           required 
                           placeholder="esempio@email.com"
                           autocomplete="username"
                           maxlength="254">
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" 
                           id="password" 
                           name="password" 
                           required 
                           placeholder="Inserisci la password"
                           autocomplete="current-password">
                </div>
                
                <button type="submit" class="btn btn-primary btn-block">
                    Accedi
                </button>
            </form>
            
            <div class="auth-footer">
                <p>Non hai un account? <a href="${pageContext.request.contextPath}/register">Registrati</a></p>
                <p><a href="${pageContext.request.contextPath}/">← Torna alla Home</a></p>
            </div>
        </div>
    </div>
</body>
</html>
