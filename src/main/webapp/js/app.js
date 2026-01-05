/**
 * SecureWebApp - Client-side JavaScript
 * Università degli Studi di Bari - Sicurezza nelle Applicazioni
 * 
 * NOTA: La sicurezza non deve MAI dipendere solo da validazioni client-side.
 * Queste funzioni sono solo per migliorare la UX.
 */

(function() {
    'use strict';

    /**
     * Inizializzazione quando il DOM è pronto
     */
    document.addEventListener('DOMContentLoaded', function() {
        initPasswordValidation();
        initFileUpload();
        initMessageDismiss();
        initFormSubmitProtection();
    });

    /**
     * Validazione password in tempo reale (solo feedback visivo)
     * La validazione effettiva avviene SEMPRE lato server
     */
    function initPasswordValidation() {
        var passwordField = document.getElementById('password');
        var confirmField = document.getElementById('confirmPassword');
        
        if (!passwordField) return;

        var requirements = {
            length: { regex: /.{12,}/, element: null },
            uppercase: { regex: /[A-Z]/, element: null },
            lowercase: { regex: /[a-z]/, element: null },
            digit: { regex: /[0-9]/, element: null },
            special: { regex: /[!@#$%^&*(),.?":{}|<>]/, element: null }
        };

        // Trova elementi requisiti se presenti
        Object.keys(requirements).forEach(function(key) {
            requirements[key].element = document.getElementById('req-' + key);
        });

        passwordField.addEventListener('input', function() {
            var password = this.value;
            
            Object.keys(requirements).forEach(function(key) {
                var req = requirements[key];
                if (req.element) {
                    if (req.regex.test(password)) {
                        req.element.classList.add('valid');
                        req.element.classList.remove('invalid');
                    } else {
                        req.element.classList.add('invalid');
                        req.element.classList.remove('valid');
                    }
                }
            });
        });

        // Verifica corrispondenza password
        if (confirmField) {
            confirmField.addEventListener('input', function() {
                var matchIndicator = document.getElementById('password-match');
                if (matchIndicator) {
                    if (this.value === passwordField.value && this.value !== '') {
                        matchIndicator.textContent = 'Le password corrispondono';
                        matchIndicator.classList.add('valid');
                        matchIndicator.classList.remove('invalid');
                    } else if (this.value !== '') {
                        matchIndicator.textContent = 'Le password non corrispondono';
                        matchIndicator.classList.add('invalid');
                        matchIndicator.classList.remove('valid');
                    } else {
                        matchIndicator.textContent = '';
                    }
                }
            });
        }
    }

    /**
     * Gestione upload file con feedback visivo
     */
    function initFileUpload() {
        var fileInput = document.getElementById('file');
        var fileNameDisplay = document.getElementById('file-name');
        var uploadArea = document.querySelector('.upload-area');

        if (!fileInput) return;

        // Mostra nome file selezionato
        fileInput.addEventListener('change', function(e) {
            if (this.files && this.files[0]) {
                var file = this.files[0];
                var fileName = file.name;
                var fileSize = formatFileSize(file.size);
                
                if (fileNameDisplay) {
                    fileNameDisplay.textContent = fileName + ' (' + fileSize + ')';
                }

                // Validazione client-side (solo feedback, server fa la vera validazione)
                if (!fileName.toLowerCase().endsWith('.txt')) {
                    showMessage('Attenzione: Solo file .txt sono accettati', 'warning');
                }

                if (file.size > 1048576) { // 1MB
                    showMessage('Attenzione: Il file supera la dimensione massima (1MB)', 'warning');
                }
            }
        });

        // Drag and drop
        if (uploadArea) {
            ['dragenter', 'dragover'].forEach(function(eventName) {
                uploadArea.addEventListener(eventName, function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    this.classList.add('dragover');
                });
            });

            ['dragleave', 'drop'].forEach(function(eventName) {
                uploadArea.addEventListener(eventName, function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    this.classList.remove('dragover');
                });
            });

            uploadArea.addEventListener('drop', function(e) {
                var files = e.dataTransfer.files;
                if (files.length > 0) {
                    fileInput.files = files;
                    fileInput.dispatchEvent(new Event('change'));
                }
            });
        }
    }

    /**
     * Permette di chiudere i messaggi di feedback
     */
    function initMessageDismiss() {
        var messages = document.querySelectorAll('.alert, .message');
        
        messages.forEach(function(msg) {
            msg.addEventListener('click', function() {
                this.style.transition = 'opacity 0.3s';
                this.style.opacity = '0';
                setTimeout(function() {
                    msg.remove();
                }, 300);
            });
            
            // Auto-dismiss dopo 5 secondi per messaggi di successo
            if (msg.classList.contains('alert-success') || msg.classList.contains('message-success')) {
                setTimeout(function() {
                    if (msg.parentNode) {
                        msg.style.transition = 'opacity 0.3s';
                        msg.style.opacity = '0';
                        setTimeout(function() {
                            msg.remove();
                        }, 300);
                    }
                }, 5000);
            }
        });
    }

    /**
     * Previene doppio submit dei form
     */
    function initFormSubmitProtection() {
        var forms = document.querySelectorAll('form');
        
        forms.forEach(function(form) {
            form.addEventListener('submit', function(e) {
                var submitBtn = this.querySelector('button[type="submit"], input[type="submit"]');
                
                if (this.dataset.submitting === 'true') {
                    e.preventDefault();
                    return false;
                }
                
                this.dataset.submitting = 'true';
                
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Attendere...';
                }
            });
        });
    }

    /**
     * Formatta dimensione file in formato leggibile
     */
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        var k = 1024;
        var sizes = ['Bytes', 'KB', 'MB', 'GB'];
        var i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * Mostra un messaggio temporaneo
     */
    function showMessage(text, type) {
        var container = document.querySelector('.main-content') || document.body;
        
        var msg = document.createElement('div');
        msg.className = 'alert alert-' + (type || 'info');
        msg.textContent = text;
        
        container.insertBefore(msg, container.firstChild);
        
        setTimeout(function() {
            msg.style.transition = 'opacity 0.3s';
            msg.style.opacity = '0';
            setTimeout(function() {
                msg.remove();
            }, 300);
        }, 4000);
    }

    /**
     * Conferma logout
     */
    window.confirmLogout = function(event) {
        if (!confirm('Sei sicuro di voler effettuare il logout?')) {
            event.preventDefault();
            return false;
        }
        return true;
    };

})();
