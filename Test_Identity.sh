#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Test_Identity.sh — End-to-End Testsuite für den Praeco Identity Provider (IdP)
# ==============================================================================
#
# WICHTIGER HINWEIS:
#   Für Tests OHNE laufenden Claims-Webhook muss in `conf.d/01_chatapp.toml`
#   unter `[Server.IdpParams]` zwingend Folgendes konfiguriert sein:
#
#       on_webhook_failure = "fallback_to_cert"
#
#   (Alternativ kann `claims_webhook_url` komplett auskommentiert werden.)
#   Andernfalls bricht der IdP den Login fail-closed mit 503 Service Unavailable ab,
#   sobald der Webhook-Endpunkt nicht erreichbar ist.
#
# Verwendung:
#   ./Test_Identity.sh                # Nutzt bestehendes /tmp/admin-test.pem falls vorhanden
#   ./Test_Identity.sh --regen-cert   # Erzwingt Neuerzeugung des Admin-OID-Testzertifikats
#
# Optionale Umgebungsvariablen:
#   IDP="https://127.0.0.1:1339"
#   ADMIN="https://127.0.0.1:1338"
#   CERTS="/Users/fredi/Data/Projekte/Rust/ios_test/260809_ChatApp/rust_core/certs"
#   CA_CERT="$CERTS/ca.pem"
#   CA_KEY="$CERTS/ca.key"
#   CA_PASS="..."                     # Optional: Passphrase für ca.key (sonst interaktive Abfrage)
#   ADMIN_CERT="/tmp/admin-test.pem"
#   ADMIN_KEY="/tmp/admin-test.key"
#   ADMIN_OID="1.3.6.1.4.1.65111.1"
#   AUDIENCE="admin-dashboard"
# ==============================================================================

IDP="${IDP:-https://127.0.0.1:1339}"
ADMIN="${ADMIN:-https://127.0.0.1:1338}"
CERTS="${CERTS:-/Users/fredi/Data/Projekte/Rust/ios_test/260809_ChatApp/rust_core/certs}"
CA_CERT="${CA_CERT:-$CERTS/ca.pem}"
CA_KEY="${CA_KEY:-$CERTS/ca.key}"
ADMIN_CERT="${ADMIN_CERT:-/tmp/admin-test.pem}"
ADMIN_KEY="${ADMIN_KEY:-/tmp/admin-test.key}"
ADMIN_OID="${ADMIN_OID:-1.3.6.1.4.1.65111.1}"
AUDIENCE="${AUDIENCE:-admin-dashboard}"
export CA_PASS="chatapp123"

REGEN_CERT=false
for arg in "$@"; do
    case "$arg" in
        --regen-cert) REGEN_CERT=true ;;
        -h|--help)
            sed -n '2,31p' "$0"
            exit 0
            ;;
        *)
            echo "Unbekanntes Argument: $arg (nutze --regen-cert oder --help)" >&2
            exit 2
            ;;
    esac
done

PASS_COUNT=0
FAIL_COUNT=0

# --- Hilfsfunktionen ----------------------------------------------------------

section() {
    printf '\n\033[1;34m=== %s ===\033[0m\n' "$1"
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '\033[0;32m[PASS]\033[0m %s\n' "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '\033[0;31m[FAIL]\033[0m %s\n' "$1" >&2
}

assert_status() {
    local actual="$1"
    local expected="$2"
    local label="$3"
    if [[ "$actual" == "$expected" ]]; then
        pass "$label (HTTP $actual)"
    else
        fail "$label (erwartet HTTP $expected, erhalten HTTP $actual)"
    fi
}

assert_status_in() {
    local actual="$1"
    local exp1="$2"
    local exp2="$3"
    local label="$4"
    if [[ "$actual" == "$exp1" || "$actual" == "$exp2" ]]; then
        pass "$label (HTTP $actual)"
    else
        fail "$label (erwartet HTTP $exp1 oder $exp2, erhalten HTTP $actual)"
    fi
}

# Dekodiert das Base64URL-Payload-Segment eines JWTs (inkl. Padding für macOS base64).
decode_jwt_payload() {
    local payload
    payload="$(printf '%s' "$1" | cut -d'.' -f2 | tr '_-' '/+')"
    local mod=$(( ${#payload} % 4 ))
    if [[ $mod -eq 2 ]]; then
        payload="${payload}=="
    elif [[ $mod -eq 3 ]]; then
        payload="${payload}="
    fi
    printf '%s' "$payload" | base64 -d 2>/dev/null
}

# Führt curl aus und schreibt Statuscode, Header und Body in globale Variablen:
#   HTTP_STATUS, HTTP_HEADERS, HTTP_BODY
TMP_HDR="$(mktemp /tmp/idp_test_hdr.XXXXXX)"
TMP_BODY="$(mktemp /tmp/idp_test_body.XXXXXX)"
cleanup() {
    rm -f "$TMP_HDR" "$TMP_BODY" /tmp/admin-test.csr /tmp/admin_client_ext.cnf
}
trap cleanup EXIT

do_curl() {
    HTTP_STATUS=""
    HTTP_HEADERS=""
    HTTP_BODY=""
    HTTP_STATUS="$(curl -sS -D "$TMP_HDR" -o "$TMP_BODY" -w '%{http_code}' "$@" || echo "000")"
    HTTP_HEADERS="$(cat "$TMP_HDR" 2>/dev/null || true)"
    HTTP_BODY="$(cat "$TMP_BODY" 2>/dev/null || true)"
}

# --- Start-Hinweis & Voraussetzungen ------------------------------------------

cat <<'EOF'
================================================================================
HINWEIS (Tests ohne laufenden Claims-Webhook):
  In `conf.d/01_chatapp.toml` unter `[Server.IdpParams]` muss
      on_webhook_failure = "fallback_to_cert"
  gesetzt sein (oder `claims_webhook_url` auskommentiert sein).
================================================================================
EOF

for bin in curl jq openssl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "Fehler: Benötigtes Tool '$bin' nicht gefunden." >&2
        exit 1
    fi
done

if [[ ! -f "$CA_CERT" ]]; then
    echo "Fehler: CA-Zertifikat nicht gefunden: $CA_CERT" >&2
    exit 1
fi

# --- Schritt 0: Admin-OID-Client-Zertifikat sicherstellen ---------------------

section "0. Vorbereitung: Admin-Client-Zertifikat mit OID ($ADMIN_OID)"

if [[ "$REGEN_CERT" == true || ! -s "$ADMIN_CERT" || ! -s "$ADMIN_KEY" ]] || ! grep -q "BEGIN CERTIFICATE" "$ADMIN_CERT" 2>/dev/null; then
    if [[ ! -f "$CA_KEY" ]]; then
        echo "Fehler: CA-Key nicht gefunden: $CA_KEY" >&2
        exit 1
    fi

    echo "Erzeuge Test-Client-Zertifikat '$ADMIN_CERT' mit OID $ADMIN_OID ..."
    cat > /tmp/admin_client_ext.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = admin-test

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:admin-test
${ADMIN_OID} = ASN1:UTF8String:Admin
EOF

    openssl genrsa -out "$ADMIN_KEY" 2048 2>/dev/null
    chmod 600 "$ADMIN_KEY"

    openssl req -new -key "$ADMIN_KEY" -out /tmp/admin-test.csr \
        -config /tmp/admin_client_ext.cnf

    if [[ -n "${CA_PASS:-}" ]]; then
        openssl x509 -req -in /tmp/admin-test.csr \
            -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
            -passin env:CA_PASS \
            -out "$ADMIN_CERT" -days 365 -sha256 \
            -extfile /tmp/admin_client_ext.cnf -extensions v3_req
    else
        echo "Bitte Passphrase für $CA_KEY eingeben (falls verschlüsselt):"
        openssl x509 -req -in /tmp/admin-test.csr \
            -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
            -out "$ADMIN_CERT" -days 365 -sha256 \
            -extfile /tmp/admin_client_ext.cnf -extensions v3_req
    fi

    if ! grep -q "BEGIN CERTIFICATE" "$ADMIN_CERT" 2>/dev/null; then
        echo "Fehler: $ADMIN_CERT konnte nicht erstellt werden." >&2
        exit 1
    fi
    pass "Admin-Testzertifikat erfolgreich erzeugt ($ADMIN_CERT)"
else
    pass "Vorhandenes Admin-Testzertifikat wird wiederverwendet ($ADMIN_CERT)"
fi

# --- Testcase 1: Direkter mTLS-Token-Abruf ------------------------------------

section "1. Direkter mTLS-Token-Abruf (POST /auth/token)"

do_curl -X POST "$IDP/auth/token?aud=$AUDIENCE" \
    --cacert "$CA_CERT" --cert "$ADMIN_CERT" --key "$ADMIN_KEY"
assert_status "$HTTP_STATUS" "200" "POST /auth/token mit mTLS"

TOKEN="$(printf '%s' "$HTTP_BODY" | jq -r '.token // empty' 2>/dev/null || true)"
if [[ -n "$TOKEN" ]]; then
    pass "JWT-Token erhalten"
    PAYLOAD="$(decode_jwt_payload "$TOKEN")"
    echo "JWT-Payload:"
    printf '%s\n' "$PAYLOAD" | jq .

    JWT_AUD="$(printf '%s' "$PAYLOAD" | jq -r '.aud // empty')"
    JWT_JTI="$(printf '%s' "$PAYLOAD" | jq -r '.jti // empty')"
    HAS_ADMIN_OID="$(printf '%s' "$PAYLOAD" | jq -r '(.oids // []) | index("1") != null')"

    if [[ "$JWT_AUD" == "$AUDIENCE" ]]; then
        pass "JWT Claim aud == '$AUDIENCE'"
    else
        fail "JWT Claim aud erwartet '$AUDIENCE', erhalten '$JWT_AUD'"
    fi

    if [[ "$HAS_ADMIN_OID" == "true" ]]; then
        pass "JWT Claim oids enthält Admin-OID '1'"
    else
        fail "JWT Claim oids enthält NICHT '1' (prüfe on_webhook_failure = \"fallback_to_cert\" & Zertifikats-OID)"
    fi

    if [[ -n "$JWT_JTI" ]]; then
        pass "JWT Claim jti vorhanden ($JWT_JTI)"
    else
        fail "JWT Claim jti fehlt"
    fi
else
    fail "Kein Token in Response: $HTTP_BODY"
fi

do_curl -X POST "$IDP/auth/token?aud=$AUDIENCE" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "401" "Negativtest: POST /auth/token ohne mTLS abgewiesen"

# --- Testcase 2: JWKS-Endpoint ------------------------------------------------

section "2. JWKS-Endpoint (GET /.well-known/jwks.json)"

do_curl "$IDP/.well-known/jwks.json" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "200" "GET /.well-known/jwks.json"

JWKS_CRV="$(printf '%s' "$HTTP_BODY" | jq -r '.keys[0].crv // empty' 2>/dev/null || true)"
if [[ "$JWKS_CRV" == "Ed25519" ]]; then
    pass "JWKS enthält Ed25519 Public Key"
else
    fail "JWKS-Antwort unerwartet: $HTTP_BODY"
fi

# --- Testcase 3: Cross-Device / QR-Code-Flow ----------------------------------

section "3. Cross-Device / QR-Code-Flow (/auth/login -> /auth/confirm -> /auth/status)"

# 3.1 Session starten
do_curl -X POST "$IDP/auth/login?aud=$AUDIENCE" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "200" "3.1 POST /auth/login erstellt Session"

SID="$(printf '%s' "$HTTP_BODY" | jq -r '.session // empty' 2>/dev/null || true)"
POLL_SECRET="$(printf '%s' "$HTTP_BODY" | jq -r '.poll_secret // empty' 2>/dev/null || true)"
USER_CODE="$(printf '%s' "$HTTP_BODY" | jq -r '.user_code // empty' 2>/dev/null || true)"

if [[ -n "$SID" && -n "$POLL_SECRET" && -n "$USER_CODE" ]]; then
    pass "3.1 session, poll_secret und user_code ($USER_CODE) erhalten"
else
    fail "3.1 Unvollständige Login-Antwort: $HTTP_BODY"
fi

# 3.2 Status ohne poll_secret -> 401
do_curl "$IDP/auth/status?session=$SID" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "401" "3.2 Negativtest: GET /auth/status ohne X-Poll-Secret abgewiesen"

# 3.3 Status mit poll_secret -> pending
do_curl "$IDP/auth/status?session=$SID" -H "X-Poll-Secret: $POLL_SECRET" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "200" "3.3 GET /auth/status (vor Bestätigung)"
STATUS_VAL="$(printf '%s' "$HTTP_BODY" | jq -r '.status // empty' 2>/dev/null || true)"
if [[ "$STATUS_VAL" == "pending" ]]; then
    pass "3.3 Session-Status ist 'pending'"
else
    fail "3.3 Erwartet status='pending', erhalten: $HTTP_BODY"
fi

# 3.4 session_info via mTLS
do_curl "$IDP/auth/session_info?session=$SID" \
    --cacert "$CA_CERT" --cert "$ADMIN_CERT" --key "$ADMIN_KEY"
assert_status "$HTTP_STATUS" "200" "3.4 GET /auth/session_info via mTLS"
INFO_CODE="$(printf '%s' "$HTTP_BODY" | jq -r '.user_code // empty' 2>/dev/null || true)"
echo $INFO_CODE
if [[ "$INFO_CODE" == "$USER_CODE" ]]; then
    pass "3.4 user_code stimmt überein ($INFO_CODE)"
else
    fail "3.4 user_code Abweichung: erwartet '$USER_CODE', erhalten '$INFO_CODE'"
fi

# 3.5 Confirm ohne mTLS -> 401
do_curl -X POST "$IDP/auth/confirm?session=$SID&code=$USER_CODE" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "401" "3.5 Negativtest: POST /auth/confirm ohne mTLS abgewiesen"

# 3.6 Confirm mit falschem Code -> 400
do_curl -X POST "$IDP/auth/confirm?session=$SID&code=XXX-XXX" \
    --cacert "$CA_CERT" --cert "$ADMIN_CERT" --key "$ADMIN_KEY"
assert_status "$HTTP_STATUS" "400" "3.6 Negativtest: POST /auth/confirm mit falschem user_code abgewiesen"

# 3.7 Confirm mit richtigem Code & mTLS -> 200
do_curl -X POST "$IDP/auth/confirm?session=$SID&code=$USER_CODE" \
    --cacert "$CA_CERT" --cert "$ADMIN_CERT" --key "$ADMIN_KEY"
assert_status "$HTTP_STATUS" "200" "3.7 POST /auth/confirm mit mTLS & richtigem user_code"

# 3.8 Status-Poll nach Confirm -> Set-Cookie + confirmed
do_curl "$IDP/auth/status?session=$SID" -H "X-Poll-Secret: $POLL_SECRET" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "200" "3.8 GET /auth/status liefert bestätigte Session"
if printf '%s' "$HTTP_HEADERS" | grep -qi '^set-cookie:'; then
    pass "3.8 Set-Cookie Header mit JWT erhalten"
else
    fail "3.8 Kein Set-Cookie Header in Antwort"
fi

# 3.9 Replay-Schutz: zweiter Poll auf konsumierte Session -> 404
do_curl "$IDP/auth/status?session=$SID" -H "X-Poll-Secret: $POLL_SECRET" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "404" "3.9 Replay-Schutz: zweiter Poll auf verbrauchte Session -> 404"

# --- Testcase 4: Zugriff auf geschützten Service (wurzelwerk_admin) -----------

section "4. Geschützter Service-Zugriff ($ADMIN/api/GetPraecoStatus)"

do_curl "$ADMIN/api/GetPraecoStatus" \
    -H "Authorization: Bearer $TOKEN" \
    --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "200" "4.1 GET /api/GetPraecoStatus mit gültigem Admin-JWT"

do_curl "$ADMIN/api/GetPraecoStatus" --cacert "$CA_CERT"
assert_status_in "$HTTP_STATUS" "401" "302" "4.2 Negativtest: GET /api/GetPraecoStatus ohne Token blockiert"

# --- Testcase 5: Token-Widerruf / Logout (POST /auth/revoke) ------------------

section "5. Token-Widerruf & Logout (POST /auth/revoke)"

# 5.1 Eigenes Bearer-Token widerrufen
do_curl -X POST "$IDP/auth/revoke" \
    -H "Authorization: Bearer $TOKEN" \
    --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "200" "5.1 POST /auth/revoke mit Bearer-Token"

# 5.2 Widerrufenes Token wird auf wurzelwerk_admin sofort abgelehnt
do_curl "$ADMIN/api/GetPraecoStatus" \
    -H "Authorization: Bearer $TOKEN" \
    --cacert "$CA_CERT"
assert_status_in "$HTTP_STATUS" "401" "302" "5.2 Widerrufenes Token wird von JwtAuth abgelehnt"

# 5.3 Explizite JTI-Revocation ohne mTLS -> 401
do_curl -X POST "$IDP/auth/revoke?jti=00000000-0000-0000-0000-000000000001" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "401" "5.3 Negativtest: POST /auth/revoke?jti=... ohne mTLS abgewiesen"

# 5.4 Explizite JTI-Revocation mit mTLS -> 200
do_curl -X POST "$IDP/auth/revoke?jti=00000000-0000-0000-0000-000000000001" \
    --cacert "$CA_CERT" --cert "$ADMIN_CERT" --key "$ADMIN_KEY"
assert_status "$HTTP_STATUS" "200" "5.4 POST /auth/revoke?jti=... mit mTLS erfolgreich"

# --- Testcase 6: Sicherheits-Negativtests -------------------------------------

section "6. Sicherheits-Negativtests"

do_curl -X POST "$IDP/auth/login?aud=fremde-app" --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "400" "6.1 Unbekannte Audience abgewiesen"

do_curl -X POST "$IDP/auth/login?aud=$AUDIENCE" \
    -H "Sec-Fetch-Site: cross-site" \
    --cacert "$CA_CERT"
assert_status "$HTTP_STATUS" "403" "6.2 Cross-Site Browser-Request abgewiesen (Anti-CSRF)"

# --- Zusammenfassung ----------------------------------------------------------

section "Ergebnis"
echo "Bestanden: $PASS_COUNT | Fehlgeschlagen: $FAIL_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
