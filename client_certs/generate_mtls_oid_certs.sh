#!/bin/bash
set -euo pipefail
umask 077

# ==============================================================================
# mTLS Certificate Generator with Custom OIDs
#
# This script generates a local Root-CA (if not already present)
# and creates a client certificate with custom embedded
# OID extensions (Object Identifiers).
# These OIDs are evaluated by the reverse proxy for Role-Based Access Control (RBAC).
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/Config.toml"

# === 1. Parameter Parsing ===
CN="client.example.test"
EMAIL="client@example.test"
SUFFIXES="1" # Default: Suffix 1
BASE_OID=""
SERVER_NAME=""
OUT_DIR="$SCRIPT_DIR"

usage() {
    echo "Usage: $0 [-c <CommonName>] [-e <Email>] [-o <OID-Suffixes (comma-separated|none)>] [-s <ServerName>] [-b <BaseOID>] [-d <OutDir>]"
    echo "Example: $0 -s wurzelwerk -c john.doe -e john@example.test -o 1,3 -d client_certs/wurzelwerk"
}

while getopts "c:e:o:b:s:d:h" flag; do
    case "${flag}" in
        c) CN=${OPTARG};;
        e) EMAIL=${OPTARG};;
        o) SUFFIXES=${OPTARG};;
        b) BASE_OID=${OPTARG};;
        s) SERVER_NAME=${OPTARG};;
        d) OUT_DIR=${OPTARG};;
        h)
            usage
            exit 0
            ;;
        \?)
            usage >&2
            exit 2
            ;;
    esac
done

# Validate inputs to prevent OpenSSL config injection (newlines / section headers)
if [[ ! "$CN" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "❌ Error: Invalid CommonName '$CN' (allowed: A-Za-z0-9._-)" >&2
    exit 1
fi
if [[ ! "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]; then
    echo "❌ Error: Invalid Email '$EMAIL'" >&2
    exit 1
fi
if [[ "$SUFFIXES" != "none" && ! "$SUFFIXES" =~ ^[0-9]+(\.[0-9]+)*(,[0-9]+(\.[0-9]+)*)*$ ]]; then
    echo "❌ Error: Invalid OID suffixes '$SUFFIXES' (expected comma-separated numeric arcs or 'none')" >&2
    exit 1
fi
if [[ -n "$SERVER_NAME" && ! "$SERVER_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "❌ Error: Invalid ServerName '$SERVER_NAME' (allowed: A-Za-z0-9._-)" >&2
    exit 1
fi

# === 2. Resolve Base OID ===
# Collects optional global pki_base_oid (before any section header) and per-[[Server]] entries
# as lines formatted "<scope>\t<oid>", where <scope> is "GLOBAL" or the server's name.
collect_oid_mappings() {
    local files=()
    [[ -f "$CONFIG_FILE" ]] && files+=("$CONFIG_FILE")
    if [[ -d "$ROOT_DIR/conf.d" ]]; then
        local f
        for f in "$ROOT_DIR/conf.d"/*.toml; do
            [[ -f "$f" ]] && files+=("$f")
        done
    fi
    [[ ${#files[@]} -eq 0 ]] && return 0

    awk '
        function flush_server() {
            if (in_server && srv_oid != "") {
                sname = (srv_name != "" ? srv_name : "<unnamed>")
                printf "%s\t%s\n", sname, srv_oid
            }
            srv_name = ""
            srv_oid = ""
        }
        FNR == 1 {
            flush_server()
            in_server = 0
            in_subtable = 0
            seen_section = 0
        }
        {
            line = $0
            sub(/#.*/, "", line)
            gsub(/^[ \t]+|[ \t]+$/, "", line)
            if (line == "") next

            if (line ~ /^\[\[Server\]\]$/) {
                flush_server()
                in_server = 1
                in_subtable = 0
                seen_section = 1
                next
            }
            if (line ~ /^\[/) {
                seen_section = 1
                if (in_server && line ~ /^\[(\[)?Server\./) {
                    in_subtable = 1
                } else {
                    flush_server()
                    in_server = 0
                    in_subtable = 0
                }
                next
            }

            if (line ~ /^name[ \t]*=[ \t]*"[^"]*"/) {
                if (in_server && !in_subtable) {
                    val = line
                    sub(/^name[ \t]*=[ \t]*"/, "", val)
                    sub(/".*$/, "", val)
                    srv_name = val
                }
            } else if (line ~ /^pki_base_oid[ \t]*=[ \t]*"[0-9.]+"/) {
                val = line
                sub(/^pki_base_oid[ \t]*=[ \t]*"/, "", val)
                sub(/".*$/, "", val)
                if (!seen_section) {
                    printf "GLOBAL\t%s\n", val
                } else if (in_server && !in_subtable) {
                    srv_oid = val
                }
            }
        }
        END { flush_server() }
    ' "${files[@]}"
}

if [[ -z "$BASE_OID" ]]; then
    MAPPINGS="$(collect_oid_mappings)"
    GLOBAL_OID="$(printf '%s\n' "$MAPPINGS" | awk -F'\t' '$1 == "GLOBAL" { print $2; exit }')"

    if [[ -n "$SERVER_NAME" ]]; then
        BASE_OID="$(printf '%s\n' "$MAPPINGS" | awk -F'\t' -v target="$SERVER_NAME" '$1 == target { print $2; exit }')"
        if [[ -z "$BASE_OID" ]]; then
            BASE_OID="$GLOBAL_OID"
        fi
        if [[ -z "$BASE_OID" ]]; then
            echo "❌ Error: No pki_base_oid found for server '$SERVER_NAME' (and no global pki_base_oid fallback in $CONFIG_FILE)." >&2
            if [[ -n "$MAPPINGS" ]]; then
                echo "   Available mappings:" >&2
                printf '%s\n' "$MAPPINGS" | awk -F'\t' '{ printf "   - %s: %s\n", $1, $2 }' >&2
            fi
            exit 1
        fi
    else
        UNIQUE_OIDS="$(printf '%s\n' "$MAPPINGS" | awk -F'\t' 'NF >= 2 && $2 != "" { print $2 }' | sort -u)"
        OID_COUNT="$(printf '%s\n' "$UNIQUE_OIDS" | grep -c . || true)"
        if [[ "$OID_COUNT" -gt 1 ]]; then
            echo "❌ Error: Multiple different pki_base_oid values configured; pass -s <ServerName> or -b <BaseOID>:" >&2
            printf '%s\n' "$MAPPINGS" | awk -F'\t' '{ printf "   - %s: %s\n", $1, $2 }' >&2
            exit 1
        fi
        BASE_OID="$UNIQUE_OIDS"
    fi
fi

if [[ -z "$BASE_OID" || ! "$BASE_OID" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
    echo "❌ Error: Valid pki_base_oid could not be found in $CONFIG_FILE or $ROOT_DIR/conf.d/*.toml (pass -s <ServerName> or -b <BaseOID>)." >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

CA_KEY="ca.key.pem"
CA_CERT="ca.cert.pem"
CLIENT_KEY="client.key.pem"
CLIENT_CSR="client.csr.pem"
CLIENT_CERT="client.cert.pem"
CLIENT_EXT="client_ext.cnf"

echo "▶️ Output Dir: $OUT_DIR"
echo "▶️ OID Base:   $BASE_OID"

# === 3. Certificate Generation ===

# Step 3.1: Generate the Root-CA (Certificate Authority), if it doesn't exist.
if [[ ! -f "$CA_KEY" ]]; then
    openssl genrsa -out "$CA_KEY" 4096
    chmod 600 "$CA_KEY"
    openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CERT" \
        -subj "/C=DE/ST=NRW/L=AC/O=PraecoDev/OU=dev/CN=PraecoTestRootCA/emailAddress=$EMAIL"
fi

# Step 3.2: Generate the private key for the client.
openssl genrsa -out "$CLIENT_KEY" 2048
chmod 600 "$CLIENT_KEY"

# Step 3.3: Create the configuration file for the client certificate.
OID_EXTENSIONS=""

if [[ -n "$SUFFIXES" && "$SUFFIXES" != "none" ]]; then
    IFS=',' read -ra SUFFIX_ARRAY <<< "$SUFFIXES"
    for suffix in "${SUFFIX_ARRAY[@]}"; do
        # The text "Proxy-RBAC-Role" is a dummy value. The proxy only evaluates the raw OID.
        OID_EXTENSIONS+="${BASE_OID}.${suffix} = ASN1:UTF8String:Proxy-RBAC-Role
"
    done
fi

cat > "$CLIENT_EXT" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = DE
ST = NRW
L = AC
O = PraecoDev
OU = dev
CN = $CN

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
$OID_EXTENSIONS
EOF

# Step 3.4: Create a Certificate Signing Request (CSR) with the config.
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -config "$CLIENT_EXT"

# Step 3.5: Sign the client certificate with our Root-CA.
openssl x509 -req -in "$CLIENT_CSR" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$CLIENT_CERT" -days 365 -sha256 \
    -extfile "$CLIENT_EXT" -extensions v3_req

# Step 3.6: Conveniently export everything into a PKCS12 (.p12) file.
openssl pkcs12 -export \
    -inkey "$CLIENT_KEY" \
    -in "$CLIENT_CERT" \
    -certfile "$CA_CERT" \
    -out client.p12 \
    -name "Client Certificate" \
    -passout pass:
chmod 600 client.p12

echo "✅ Done. OID Check:"
openssl x509 -in "$CLIENT_CERT" -text -noout