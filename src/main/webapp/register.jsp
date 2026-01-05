<%-- 
  ============================================
  SecureFileShare - Registration Page
  ============================================
  Pagina di registrazione nuovo utente.
  
  SICUREZZA IMPLEMENTATA:
  - Validazione password client-side con zxcvbn
  - Indicatore forza password real-time
  - Output sanitizzato con JSTL c:out (anti-XSS)
  - Script inline con nonce CSP
  - Autocomplete disabilitato per password
  
  LIBRERIE ESTERNE:
  - zxcvbn (Dropbox): valutazione forza password
  
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
    <title>Registrazione - SecureFileShare</title>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css">
    <style>
        /* Stili per l'indicatore di forza password */
        .password-strength-container {
            margin-top: 10px;
        }
        .password-strength-bar {
            height: 8px;
            background-color: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 5px;
        }
        .password-strength-fill {
            height: 100%;
            width: 0%;
            transition: width 0.3s ease, background-color 0.3s ease;
            border-radius: 4px;
        }
        .password-strength-text {
            font-size: 0.85rem;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .strength-label {
            padding: 2px 8px;
            border-radius: 3px;
            color: white;
            font-size: 0.75rem;
        }
        .password-feedback {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 5px;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="card">
            <div class="card-header">
                <h1>🔒 SecureFileShare</h1>
                <h2>Crea un Account</h2>
            </div>
            
            <%-- Messaggi di errore (impostati dal servlet) --%>
            <c:if test="${not empty error}">
                <div class="message message-error">
                    <c:out value="${error}" escapeXml="true"/>
                </div>
            </c:if>
            
            <form action="${pageContext.request.contextPath}/register" method="POST" autocomplete="off" id="registerForm">
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" 
                           id="email" 
                           name="email" 
                           required 
                           placeholder="esempio@email.com"
                           value="<c:out value='${email}' escapeXml='true'/>"
                           autocomplete="username"
                           maxlength="254">
                    <span class="help-text">Inserisci un indirizzo email valido e univoco</span>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" 
                           id="password" 
                           name="password" 
                           required 
                           placeholder="Crea una password sicura"
                           autocomplete="new-password"
                           minlength="12">
                    
                    <%-- Indicatore forza password --%>
                    <div class="password-strength-container" id="strengthContainer" style="display: none;">
                        <div class="password-strength-bar">
                            <div class="password-strength-fill" id="strengthFill"></div>
                        </div>
                        <div class="password-strength-text">
                            <span id="strengthMessage">Valutazione in corso...</span>
                            <span class="strength-label" id="strengthLabel">-</span>
                        </div>
                        <div class="password-feedback" id="strengthFeedback"></div>
                    </div>
                    
                    <div class="password-requirements">
                        <h4>Requisiti Password:</h4>
                        <ul>
                            <li id="req-length">Almeno 12 caratteri</li>
                            <li id="req-uppercase">Almeno una lettera maiuscola (A-Z)</li>
                            <li id="req-lowercase">Almeno una lettera minuscola (a-z)</li>
                            <li id="req-digit">Almeno un numero (0-9)</li>
                            <li id="req-special">Almeno un carattere speciale (!@#$%^&amp;*...)</li>
                        </ul>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="confirmPassword">Conferma Password</label>
                    <input type="password" 
                           id="confirmPassword" 
                           name="confirmPassword" 
                           required 
                           placeholder="Ripeti la password"
                           autocomplete="new-password"
                           minlength="12">
                    <span id="password-match" class="help-text"></span>
                </div>
                
                <button type="submit" class="btn btn-success btn-block">
                    Registrati
                </button>
            </form>
            
            <div class="auth-footer">
                <p>Hai già un account? <a href="${pageContext.request.contextPath}/login">Accedi</a></p>
                <p><a href="${pageContext.request.contextPath}/">← Torna alla Home</a></p>
            </div>
        </div>
    </div>
    
    <%-- zxcvbn per valutazione forza password --%>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js" 
            integrity="sha512-TZlMGFY9xKj38t/5m2FzJ+RM/aD5alMHDe26p0mYUMoCF5G7ibfHUQILq0qQPV3wlsnCwL+TPRNK4vIWGLOkUQ==" 
            crossorigin="anonymous" 
            referrerpolicy="no-referrer"></script>
    <script src="${pageContext.request.contextPath}/js/app.js"></script>
    
    <%-- Script per indicatore forza password con nonce CSP --%>
    <script nonce="${cspNonce}">
    (function() {
        'use strict';
        
        var passwordInput = document.getElementById('password');
        var strengthContainer = document.getElementById('strengthContainer');
        var strengthFill = document.getElementById('strengthFill');
        var strengthMessage = document.getElementById('strengthMessage');
        var strengthLabel = document.getElementById('strengthLabel');
        var strengthFeedback = document.getElementById('strengthFeedback');
        
        // Configurazione livelli di forza
        var strengthConfig = {
            0: { 
                label: 'Molto debole', 
                color: '#dc3545', 
                width: '20%',
                message: 'Facilmente indovinabile'
            },
            1: { 
                label: 'Debole', 
                color: '#e83e8c', 
                width: '40%',
                message: 'Vulnerabile ad attacchi'
            },
            2: { 
                label: 'Discreta', 
                color: '#ffc107', 
                width: '60%',
                message: 'Potrebbe essere più sicura'
            },
            3: { 
                label: 'Buona', 
                color: '#28a745', 
                width: '80%',
                message: 'Resistente alla maggior parte degli attacchi'
            },
            4: { 
                label: 'Ottima', 
                color: '#20c997', 
                width: '100%',
                message: 'Molto difficile da violare'
            }
        };
        
        // Traduzioni warning zxcvbn
        var warningTranslations = {
            'This is a top-10 common password': 'Questa è una delle 10 password più usate',
            'This is a top-100 common password': 'Questa è una delle 100 password più usate',
            'This is a very common password': 'Questa è una password molto comune',
            'This is similar to a commonly used password': 'Troppo simile a password comuni',
            'A word by itself is easy to guess': 'Una singola parola è facile da indovinare',
            'Names and surnames by themselves are easy to guess': 'Nomi e cognomi sono facili da indovinare',
            'Common names and surnames are easy to guess': 'Nomi comuni sono facili da indovinare',
            'Straight rows of keys are easy to guess': 'Sequenze di tasti consecutive sono prevedibili',
            'Short keyboard patterns are easy to guess': 'Pattern da tastiera brevi sono prevedibili',
            'Repeats like "aaa" are easy to guess': 'Ripetizioni come "aaa" sono prevedibili',
            'Repeats like "abcabcabc" are only slightly harder to guess than "abc"': 'Le ripetizioni aggiungono poca sicurezza',
            'Sequences like abc or 6543 are easy to guess': 'Sequenze come abc o 6543 sono prevedibili',
            'Recent years are easy to guess': 'Gli anni recenti sono facili da indovinare',
            'Dates are often easy to guess': 'Le date sono spesso facili da indovinare'
        };
        
        // Traduzioni suggerimenti zxcvbn
        var suggestionTranslations = {
            'Add another word or two. Uncommon words are better.': 'Aggiungi altre parole, preferibilmente non comuni',
            'Use a longer keyboard pattern with more turns': 'Usa un pattern da tastiera più lungo e complesso',
            'Avoid repeated words and characters': 'Evita parole e caratteri ripetuti',
            'Avoid sequences': 'Evita sequenze prevedibili',
            'Avoid recent years': 'Evita anni recenti',
            'Avoid years that are associated with you': 'Evita anni significativi per te',
            'Avoid dates and years that are associated with you': 'Evita date e anni personali',
            'Capitalization doesn\'t help very much': 'Le maiuscole da sole non aggiungono molta sicurezza',
            'All-uppercase is almost as easy to guess as all-lowercase': 'Tutto maiuscolo è quasi come tutto minuscolo',
            'Reversed words aren\'t much harder to guess': 'Le parole al contrario non sono molto più sicure',
            'Predictable substitutions like \'@\' instead of \'a\' don\'t help very much': 'Sostituzioni prevedibili come @ per a non aiutano molto'
        };
        
        function translateText(text, translations) {
            if (!text) return '';
            return translations[text] || text;
        }
        
        function updateStrengthIndicator() {
            var password = passwordInput.value;
            
            if (password.length === 0) {
                strengthContainer.style.display = 'none';
                return;
            }
            
            strengthContainer.style.display = 'block';
            
            // Valuta la password con zxcvbn
            var result = zxcvbn(password);
            var score = result.score; // 0-4
            var config = strengthConfig[score];
            
            // Aggiorna barra
            strengthFill.style.width = config.width;
            strengthFill.style.backgroundColor = config.color;
            
            // Aggiorna label
            strengthLabel.textContent = config.label;
            strengthLabel.style.backgroundColor = config.color;
            
            // Aggiorna messaggio
            strengthMessage.textContent = config.message;
            strengthMessage.style.color = config.color;
            
            // Feedback specifico da zxcvbn
            var feedback = '';
            if (result.feedback.warning) {
                feedback = '⚠️ ' + translateText(result.feedback.warning, warningTranslations);
            } else if (result.feedback.suggestions && result.feedback.suggestions.length > 0) {
                feedback = '💡 ' + translateText(result.feedback.suggestions[0], suggestionTranslations);
            }
            strengthFeedback.textContent = feedback;
        }
        
        // Aggiorna su ogni input
        passwordInput.addEventListener('input', updateStrengthIndicator);
        
        // Inizializza se c'è già un valore
        if (passwordInput.value) {
            updateStrengthIndicator();
        }
    })();
    </script>
</body>
</html>
