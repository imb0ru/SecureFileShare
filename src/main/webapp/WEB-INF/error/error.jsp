<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" isErrorPage="true"%>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Errore - SecureFileShare</title>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css">
</head>
<body>
    <div class="container">
        <div class="error-page">
            <div class="error-code">Errore</div>
            <h1>Si è verificato un problema</h1>
            <p>
                Si è verificato un errore durante l'elaborazione della richiesta.
            </p>
            <div class="error-actions">
                <a href="${pageContext.request.contextPath}/" class="btn btn-primary">
                    Torna alla Home
                </a>
                <c:choose>
                    <c:when test="${not empty sessionScope.userId}">
                        <a href="${pageContext.request.contextPath}/dashboard" class="btn btn-secondary">
                            Vai alla Dashboard
                        </a>
                    </c:when>
                    <c:otherwise>
                        <a href="${pageContext.request.contextPath}/login" class="btn btn-secondary">
                            Effettua il Login
                        </a>
                    </c:otherwise>
                </c:choose>
            </div>
        </div>
        
        <footer class="footer">
            <p>&copy; 2025 SecureFileShare - UniBa</p>
        </footer>
    </div>
</body>
</html>
