<%-- 
  ============================================
  SecureFileShare - Upload Page
  ============================================
  Pagina per caricamento file.
  
  SICUREZZA IMPLEMENTATA:
  - Accesso protetto da AuthenticationFilter
  - Validazione client-side (tipo, dimensione)
  - Validazione server-side in UploadServlet
  - Whitelist estensioni (.txt)
  - Controllo MIME type con Apache Tika
  
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
    <title>Carica File - SecureFileShare</title>
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
            <div class="card">
                <div class="card-header">
                    <h2>📤 Carica un Nuovo File</h2>
                </div>
                
                <%-- Messaggi di feedback (impostati dal servlet) --%>
                <c:if test="${not empty requestScope.error}">
                    <div class="message message-error">
                        ✗ <c:out value="${requestScope.error}" escapeXml="true"/>
                    </div>
                </c:if>
                <c:if test="${not empty requestScope.success}">
                    <div class="message message-success">
                        ✓ <c:out value="${requestScope.success}" escapeXml="true"/>
                    </div>
                </c:if>

                <%-- Requisiti file --%>
                <div class="file-info">
                    <h3>📋 Requisiti del File</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>✓ Sono accettati <strong>solo file di testo (.txt)</strong></li>
                        <li>✓ Dimensione massima: <strong>1 MB</strong></li>
                        <li>✓ Il contenuto viene validato per rilevare codice malevolo</li>
                        <li>✓ I file vengono salvati in modo sicuro fuori dalla web root</li>
                    </ul>
                </div>

                <%-- Form upload --%>
                <form action="${pageContext.request.contextPath}/upload" 
                      method="POST" 
                      enctype="multipart/form-data"
                      id="uploadForm">
                    
                    <div class="form-group">
                        <label for="file">Seleziona il file da caricare:</label>
                        <div class="upload-area" id="upload-area">
                            <div class="upload-icon">📁</div>
                            <p>Clicca qui o trascina un file</p>
                            <p id="file-name" style="color: var(--text-muted); font-size: 0.9rem;">
                                Nessun file selezionato
                            </p>
                        </div>
                        <input type="file" 
                               id="file" 
                               name="file" 
                               accept=".txt,text/plain"
                               multiple
                               required
                               style="display: none;">
                    </div>

                    <div class="form-group" style="display: flex; gap: 15px;">
                        <button type="submit" class="btn btn-success">
                            📤 Carica File
                        </button>
                        <a href="${pageContext.request.contextPath}/dashboard" class="btn btn-secondary">
                            ✗ Annulla
                        </a>
                    </div>
                </form>
            </div>

            <%-- Informazioni sulla sicurezza --%>
            <div class="card">
                <div class="card-header">
                    <h3>🛡️ Misure di Sicurezza</h3>
                </div>
                <p>Questo sistema implementa diverse misure per proteggere la piattaforma:</p>
                <ul style="margin-left: 20px; margin-top: 10px; line-height: 1.8;">
                    <li><strong>Validazione MIME type:</strong> Il tipo di file viene verificato 
                        analizzando il contenuto reale con Apache Tika, non solo l'estensione.</li>
                    <li><strong>Analisi del contenuto:</strong> I file vengono scansionati 
                        per rilevare script, tag HTML o codice potenzialmente dannoso.</li>
                    <li><strong>Whitelist estensioni:</strong> Solo i formati esplicitamente 
                        consentiti (.txt) vengono accettati.</li>
                    <li><strong>Nomi file sicuri:</strong> I file vengono rinominati con UUID 
                        per prevenire attacchi di path traversal.</li>
                    <li><strong>Storage sicuro:</strong> I file vengono salvati in directory 
                        protette e non direttamente accessibili dal web.</li>
                    <li><strong>Prevenzione TOCTOU:</strong> Il file viene letto una sola volta 
                        in memoria per evitare race condition.</li>
                </ul>
            </div>
        </main>
    </div>

    <footer>
        <p>🔒 SecureFileShare - Progetto Sicurezza nelle Applicazioni - UniBa 2025/2026</p>
    </footer>

    <%-- Script con nonce CSP per prevenire XSS --%>
    <script nonce="${cspNonce}">
        // Click sulla upload-area apre il file picker
        document.getElementById('upload-area').addEventListener('click', function() {
            document.getElementById('file').click();
        });
        
        // Mostra il nome dei file selezionati
        document.getElementById('file').addEventListener('change', function(e) {
            var files = e.target.files;
            var fileInfo = '';
            if (files.length === 0) {
                fileInfo = 'Nessun file selezionato';
            } else if (files.length === 1) {
                fileInfo = files[0].name + ' (' + (files[0].size / 1024).toFixed(2) + ' KB)';
            } else {
                fileInfo = files.length + ' file selezionati';
                var totalSize = 0;
                for (var i = 0; i < files.length; i++) {
                    totalSize += files[i].size;
                }
                fileInfo += ' (' + (totalSize / 1024).toFixed(2) + ' KB totali)';
            }
            document.getElementById('file-name').textContent = fileInfo;
        });
        
        // Drag and drop
        var uploadArea = document.getElementById('upload-area');
        
        ['dragenter', 'dragover'].forEach(function(eventName) {
            uploadArea.addEventListener(eventName, function(e) {
                e.preventDefault();
                this.classList.add('dragover');
            });
        });
        
        ['dragleave', 'drop'].forEach(function(eventName) {
            uploadArea.addEventListener(eventName, function(e) {
                e.preventDefault();
                this.classList.remove('dragover');
            });
        });
        
        uploadArea.addEventListener('drop', function(e) {
            var files = e.dataTransfer.files;
            if (files.length > 0) {
                document.getElementById('file').files = files;
                document.getElementById('file').dispatchEvent(new Event('change'));
            }
        });
    </script>
</body>
</html>
