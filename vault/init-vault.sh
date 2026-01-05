#!/bin/sh
# ============================================
# Vault Auto-Init & Configure
# ============================================
# Questo script:
# 1. Attende che Vault sia pronto
# 2. Inizializza Vault (se primo avvio)
# 3. Esegue unseal automatico
# 4. Configura i segreti da variabili d'ambiente
# 5. Salva il token in un file accessibile
# ============================================

set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
KEYS_FILE="/vault/data/vault-keys.json"
TOKEN_FILE="/vault/data/generated-token.txt"
TOKEN_OUTPUT="/vault/output/generated-token.txt"

export VAULT_ADDR

echo "============================================"
echo "  SecureFileShare - Vault Init"
echo "============================================"
echo ""

# ------------------------------------------
# 1. Attendi che Vault sia raggiungibile
# ------------------------------------------
echo "[1/4] Attendo che Vault sia pronto..."
until curl -s "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; do
    echo "      Vault non ancora pronto, riprovo tra 2s..."
    sleep 2
done
echo "      ✓ Vault raggiungibile"

# ------------------------------------------
# 2. Controlla se già inizializzato
# ------------------------------------------
echo ""
echo "[2/4] Controllo stato inizializzazione..."
INIT_STATUS=$(curl -s "${VAULT_ADDR}/v1/sys/init" | grep -o '"initialized":[^,}]*' | cut -d: -f2)

if [ "$INIT_STATUS" = "false" ]; then
    echo "      Vault non inizializzato, eseguo init..."
    
    # Inizializza con 1 chiave (semplificato per sviluppo locale)
    INIT_RESPONSE=$(curl -s --request POST \
        --data '{"secret_shares": 1, "secret_threshold": 1}' \
        "${VAULT_ADDR}/v1/sys/init")
    
    # Estrai chiavi e root token
    UNSEAL_KEY=$(echo "$INIT_RESPONSE" | grep -o '"keys":\[[^]]*\]' | grep -o '"[^"]*"' | head -1 | tr -d '"')
    ROOT_TOKEN=$(echo "$INIT_RESPONSE" | grep -o '"root_token":"[^"]*"' | cut -d'"' -f4)
    
    # Salva le chiavi (persistente nel volume)
    cat > "$KEYS_FILE" << EOF
{
    "unseal_key": "${UNSEAL_KEY}",
    "root_token": "${ROOT_TOKEN}"
}
EOF
    chmod 600 "$KEYS_FILE"
    
    # Salva il token in un file separato per facile accesso
    echo "$ROOT_TOKEN" > "$TOKEN_FILE"
    chmod 644 "$TOKEN_FILE"
    
    # Copia anche nella directory accessibile all'utente
    if [ -d "/vault/output" ]; then
        echo "$ROOT_TOKEN" > "$TOKEN_OUTPUT"
        chmod 644 "$TOKEN_OUTPUT"
        echo "      ✓ Token salvato in vault/generated-token.txt"
    fi
    
    echo "      ✓ Vault inizializzato"
    echo "      ✓ Chiavi salvate"
else
    echo "      ✓ Vault già inizializzato"
    
    # Assicurati che il file token esista
    if [ -f "$KEYS_FILE" ]; then
        ROOT_TOKEN=$(grep -o '"root_token":"[^"]*"' "$KEYS_FILE" | cut -d'"' -f4)
        if [ ! -f "$TOKEN_FILE" ]; then
            echo "$ROOT_TOKEN" > "$TOKEN_FILE"
            chmod 644 "$TOKEN_FILE"
        fi
        # Rigenera anche l'output file
        if [ -d "/vault/output" ]; then
            echo "$ROOT_TOKEN" > "$TOKEN_OUTPUT"
            chmod 644 "$TOKEN_OUTPUT"
        fi
    fi
fi

# ------------------------------------------
# 3. Unseal
# ------------------------------------------
echo ""
echo "[3/4] Controllo stato seal..."
SEAL_STATUS=$(curl -s "${VAULT_ADDR}/v1/sys/seal-status" | grep -o '"sealed":[^,}]*' | cut -d: -f2)

if [ "$SEAL_STATUS" = "true" ]; then
    echo "      Vault sealed, eseguo unseal..."
    
    if [ ! -f "$KEYS_FILE" ]; then
        echo "      ❌ ERRORE: File chiavi non trovato: $KEYS_FILE"
        echo "      Vault deve essere reinizializzato (elimina il volume vault-data)"
        exit 1
    fi
    
    UNSEAL_KEY=$(grep -o '"unseal_key":"[^"]*"' "$KEYS_FILE" | cut -d'"' -f4)
    
    curl -s --request POST \
        --data "{\"key\": \"${UNSEAL_KEY}\"}" \
        "${VAULT_ADDR}/v1/sys/unseal" > /dev/null
    
    echo "      ✓ Vault unsealed"
else
    echo "      ✓ Vault già unsealed"
fi

# ------------------------------------------
# 4. Configura segreti
# ------------------------------------------
echo ""
echo "[4/4] Configurazione segreti..."

# Leggi root token
if [ ! -f "$KEYS_FILE" ]; then
    echo "      ❌ ERRORE: File chiavi non trovato"
    exit 1
fi

ROOT_TOKEN=$(grep -o '"root_token":"[^"]*"' "$KEYS_FILE" | cut -d'"' -f4)
export VAULT_TOKEN="$ROOT_TOKEN"

# Verifica se KV v2 già abilitato
KV_ENABLED=$(curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" \
    "${VAULT_ADDR}/v1/sys/mounts" | grep -c '"secret/"' || true)

if [ "$KV_ENABLED" = "0" ]; then
    echo "      Abilito secrets engine KV v2..."
    curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" \
        --request POST \
        --data '{"type": "kv", "options": {"version": "2"}}' \
        "${VAULT_ADDR}/v1/sys/mounts/secret" > /dev/null
    echo "      ✓ KV v2 abilitato"
else
    echo "      ✓ KV v2 già abilitato"
fi

# --- Database credentials ---
if [ -z "$MYSQL_USER" ] || [ -z "$MYSQL_PASSWORD" ]; then
    echo "      ❌ ERRORE: MYSQL_USER e MYSQL_PASSWORD sono obbligatori"
    exit 1
fi

DB_URL="jdbc:mysql://mysql:3307/${MYSQL_DATABASE:-secure_file_share}?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"

curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" \
    --request POST \
    --data "{\"data\": {\"url\": \"${DB_URL}\", \"username\": \"${MYSQL_USER}\", \"password\": \"${MYSQL_PASSWORD}\"}}" \
    "${VAULT_ADDR}/v1/secret/data/securefileshare/database" > /dev/null

echo "      ✓ secret/securefileshare/database"

# --- Encryption key ---
if [ -z "$AES_ENCRYPTION_KEY" ]; then
    echo "      AES_ENCRYPTION_KEY non impostato, genero automaticamente..."
    AES_ENCRYPTION_KEY=$(openssl rand -base64 32)
fi

curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" \
    --request POST \
    --data "{\"data\": {\"aes_key\": \"${AES_ENCRYPTION_KEY}\", \"algorithm\": \"AES/GCM/NoPadding\", \"key_size\": \"256\"}}" \
    "${VAULT_ADDR}/v1/secret/data/securefileshare/encryption" > /dev/null

echo "      ✓ secret/securefileshare/encryption"

# ------------------------------------------
# Completato
# ------------------------------------------
echo ""
echo "============================================"
echo "  ✓ Vault configurato con successo!"
echo "============================================"
echo ""
echo "  Token salvato in: vault/generated-token.txt"
echo ""
echo "  Per recuperare il token:"
echo "    cat vault/generated-token.txt"
echo ""
echo "  Configurazione Tomcat (setenv.sh):"
echo "    export VAULT_ADDR=http://localhost:8200"
echo "    export VAULT_TOKEN=\$(cat vault/generated-token.txt)"
echo ""
echo "============================================"
