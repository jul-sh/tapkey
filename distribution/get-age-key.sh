#!/bin/bash
# Outputs AGE_SECRET_KEY from environment, macOS Keychain, or keytap.
# Exits 1 if not found in any location.
#
# Usage:
#   AGE_SECRET_KEY=$(./distribution/get-age-key.sh)
#
# To store in Keychain:
#   security add-generic-password -s keytap -a AGE_SECRET_KEY -w 'AGE-SECRET-KEY-...'

if [ -n "$AGE_SECRET_KEY" ]; then
    printf '%s' "$AGE_SECRET_KEY"
elif KEY=$(security find-generic-password -s keytap -a AGE_SECRET_KEY -w 2>/dev/null); then
    printf '%s' "$KEY"
elif command -v keytap >/dev/null 2>&1 && KEY=$(keytap derive keytap --format age 2>/dev/null); then
    printf '%s' "$KEY"
else
    echo "Error: AGE_SECRET_KEY not set and not found in Keychain or via keytap" >&2
    echo "  Set via: export AGE_SECRET_KEY='AGE-SECRET-KEY-...'" >&2
    echo "  Or store: security add-generic-password -s keytap -a AGE_SECRET_KEY -w 'KEY'" >&2
    echo "  Or install keytap and run: keytap register" >&2
    exit 1
fi
