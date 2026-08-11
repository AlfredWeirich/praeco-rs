#!/bin/bash
set -e

# ==============================================================================
# mTLS Certificate Generator with Custom OIDs
# 
# This script generates a local Root-CA (if not already present)
# and creates a client certificate with custom embedded
# OID extensions (Object Identifiers).
# These OIDs are evaluated by the reverse proxy for Role-Based Access Control (RBAC).
# ==============================================================================

# === 1. Load Configuration ===
# We read the Base-OID dynamically from the central Config.toml, 
# ensuring proxy and generated certs always share the same root.
CONFIG_FILE="/Users/fredi/Data/Projekte/Rust/260225_Tower_Hyper_Rustls_refactor_client_gprc/Config.toml"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Error: $CONFIG_FILE not found!"
    exit 1
fi

# Extract the pki_base_oid using grep and sed (e.g. "1.3.6.1.4.1.65111")
BASE_OID=$(grep "pki_base_oid" "$CONFIG_FILE" | sed -E 's/.*"([0-9.]+)"/\1/')

if [ -z "$BASE_OID" ]; then
    echo "❌ Error: pki_base_oid could not be found in $CONFIG_FILE!"
    exit 1
fi

# === 2. Parameter Parsing ===
CN="client.weirich"
EMAIL="alfred.weirich@gmail.com"
SUFFIXES="1" # Default: Suffix 1

while getopts "c:e:o:h" flag; do
    case "${flag}" in
        c) CN=${OPTARG};;
        e) EMAIL=${OPTARG};;
        o) SUFFIXES=${OPTARG};;
        h) 
           echo "Usage: $0 [-c <CommonName>] [-e <Email>] [-o <OID-Suffixes (comma-separated)>]"
           echo "Example: $0 -c john.doe -e john@test.com -o 1,3"
           exit 0
           ;;
    esac
done

CA_KEY="ca.key.pem"
CA_CERT="ca.cert.pem"
CLIENT_KEY="client.key.pem"
CLIENT_CSR="client.csr.pem"
CLIENT_CERT="client.cert.pem"
CLIENT_EXT="client_ext.cnf"

echo "▶️ OID Base: $BASE_OID"

# === 3. Certificate Generation ===

# Step 3.1: Generate the Root-CA (Certificate Authority), if it doesn't exist.
# This CA must later be configured as a "trust_anchor" in the proxy.
if [ ! -f "$CA_KEY" ]; then
  openssl genrsa -out "$CA_KEY" 4096
  openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CERT" \
    -subj "/C=GE/ST=NRW/L=AC/O=Weirich/OU=dev/CN=MyRootCa/emailAddress=$EMAIL"
fi

# Step 3.2: Generate the private key for the client.
openssl genrsa -out "$CLIENT_KEY" 2048

# Step 3.3: Create the configuration file for the client certificate.
# OIDs are dynamically injected based on the -o parameter.
OID_EXTENSIONS=""

if [ -n "$SUFFIXES" ] && [ "$SUFFIXES" != "none" ]; then
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
C = GE
ST = NRW
L = AC
O = Weirich
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

# Step 3.6: Conveniently export everything into a PKCS12 (.p12) file,
# which can be imported into Postman, cURL, or browsers.
openssl pkcs12 -export \
  -inkey "$CLIENT_KEY" \
  -in "$CLIENT_CERT" \
  -certfile "$CA_CERT" \
  -out client.p12 \
  -name "Client Certificate" \
  -passout pass:

echo "✅ Done. OID Check:"
# Verifies if the OIDs were successfully written into the final certificate.
openssl x509 -in "$CLIENT_CERT" -text -noout 