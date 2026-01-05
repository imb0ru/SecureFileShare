<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" isErrorPage="true"%>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - Errore del Server</title>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css">
</head>
<body>
    <div class="container">
        <div class="error-page">
            <div class="error-code">500</div>
            <h1>Errore Interno del Server</h1>
            <p>Si è verificato un errore imprevisto. Il nostro team è stato notificato.</p>
            <p class="error-hint">
                Per motivi di sicurezza, i dettagli dell'errore non vengono visualizzati.
            </p>
            <div class="error-actions">
                <a href="${pageContext.request.contextPath}/" class="btn btn-primary">
                    Torna alla Home
                </a>
                <c:if test="${not empty sessionScope.userId}">
                    <a href="${pageContext.request.contextPath}/dashboard" class="btn btn-secondary">
                        Vai alla Dashboard
                    </a>
                </c:if>
            </div>
        </div>
        
        <footer class="footer">
            <p>&copy; 2025 SecureFileShare - UniBa</p>
        </footer>
    </div>
</body>
</html>
