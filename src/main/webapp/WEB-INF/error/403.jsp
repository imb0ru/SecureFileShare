<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" isErrorPage="true"%>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 - Accesso Negato</title>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css">
</head>
<body>
    <div class="container">
        <div class="error-page">
            <div class="error-code">403</div>
            <h1>Accesso Negato</h1>
            <p>Non disponi dei permessi necessari per accedere a questa risorsa.</p>
            <div class="error-actions">
                <a href="${pageContext.request.contextPath}/" class="btn btn-primary">
                    Torna alla Home
                </a>
                <a href="${pageContext.request.contextPath}/login" class="btn btn-secondary">
                    Effettua il Login
                </a>
            </div>
        </div>
        
        <footer class="footer">
            <p>&copy; 2025 SecureFileShare - UniBa</p>
        </footer>
    </div>
</body>
</html>
