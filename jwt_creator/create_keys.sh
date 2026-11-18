#!/bin/bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORCE=false

if [[ "${1:-}" == "-f" || "${1:-}" == "--force" ]]; then
    FORCE=true
elif [[ -n "${1:-}" ]]; then
    echo "Usage: $0 [-f|--force]" >&2
    exit 2
fi

cd "$SCRIPT_DIR"

PRIVATE_KEY="private_key.pem"
PUBLIC_KEY="public_key.pem"

if [[ -e "$PRIVATE_KEY" && "$FORCE" != "true" ]]; then
    echo "❌ Error: $SCRIPT_DIR/$PRIVATE_KEY already exists (use -f/--force to overwrite)." >&2
    exit 1
fi

# Generate Ed25519 private key (umask 077 ensures 0600 from creation)
openssl genpkey -algorithm ed25519 -out "$PRIVATE_KEY"
chmod 600 "$PRIVATE_KEY"

# Extract public key from private key
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

echo "Ed25519 keys generated in $SCRIPT_DIR:"
echo "Private key: $PRIVATE_KEY"
echo "Public key:  $PUBLIC_KEY"

