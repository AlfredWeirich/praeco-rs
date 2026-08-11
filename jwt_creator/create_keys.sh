#!/bin/bash

# Set filenames
PRIVATE_KEY="private_key.pem"
PUBLIC_KEY="public_key.pem"

# Generate Ed25519 private key
openssl genpkey -algorithm ed25519 -out "$PRIVATE_KEY"

# Set permissions for private key (owner read/write only)
chmod 600 "$PRIVATE_KEY"

# Extract public key from private key
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

echo "Ed25519 keys generated:"
echo "Private key: $PRIVATE_KEY"
echo "Public key:  $PUBLIC_KEY"

