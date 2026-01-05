# ============================================
# Vault Server Configuration
# ============================================
# Configurazione per Vault in server mode (non dev)
# ============================================

# Storage backend (file-based, persistente)
storage "file" {
    path = "/vault/data"
}

# Listener HTTP (TLS disabilitato per ambiente locale)
listener "tcp" {
    address     = "0.0.0.0:8200"
    tls_disable = true
}

# API address
api_addr = "http://127.0.0.1:8200"

# UI abilitata
ui = true

# Disabilita mlock (non richiede privilegi speciali)
disable_mlock = true

# Log level
log_level = "info"
