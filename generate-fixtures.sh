#!/bin/bash
# Generates age cross-impl test fixtures using the reference age CLI and ssh-keygen.
# Idempotent: skips fixtures that already exist.
#
# Required tools: age, age-keygen, ssh-keygen.
# Install: brew install age openssh
#
# Output: agepony-core/src/test/resources/fixtures/
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
FIXTURES_DIR="$SCRIPT_DIR/agepony-core/src/test/resources/fixtures"
mkdir -p "$FIXTURES_DIR"
cd "$FIXTURES_DIR"

PLAINTEXT="hello agepony"
PASSPHRASE="agepony-test-passphrase"

# Tool check
for tool in age age-keygen ssh-keygen; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "Error: required tool '$tool' not found in PATH."
        echo "Install: brew install age openssh"
        exit 1
    fi
done

# 1. X25519
if [ ! -f x25519_identity.txt ] || [ ! -f x25519_hello.age ]; then
    echo "Generating X25519 fixture..."
    rm -f x25519_identity.txt
    age-keygen -o x25519_identity.txt 2>/dev/null
    PUBKEY=$(grep -i "public key" x25519_identity.txt | awk '{print $NF}')
    echo -n "$PLAINTEXT" | age -r "$PUBKEY" > x25519_hello.age
    echo "  identity: x25519_identity.txt"
    echo "  public key: $PUBKEY"
    printf "  ciphertext: x25519_hello.age (%8d bytes)\n" "$(wc -c < x25519_hello.age)"
    echo
fi

# 2. ssh-ed25519 (unencrypted)
if [ ! -f ssh_ed25519_identity ] || [ ! -f ssh_ed25519_hello.age ]; then
    echo "Generating ssh-ed25519 fixture..."
    rm -f ssh_ed25519_identity ssh_ed25519_identity.pub
    ssh-keygen -t ed25519 -N "" -C "test@agepony" -f ssh_ed25519_identity > /dev/null
    echo -n "$PLAINTEXT" | age -R ssh_ed25519_identity.pub > ssh_ed25519_hello.age
    echo "  identity: ssh_ed25519_identity"
    printf "  ciphertext: ssh_ed25519_hello.age (%8d bytes)\n" "$(wc -c < ssh_ed25519_hello.age)"
    echo
fi

# 3. ssh-rsa (unencrypted, 3072-bit)
if [ ! -f ssh_rsa_identity ] || [ ! -f ssh_rsa_hello.age ]; then
    echo "Generating ssh-rsa fixture (RSA-3072 — may take a moment to generate)..."
    rm -f ssh_rsa_identity ssh_rsa_identity.pub
    ssh-keygen -t rsa -b 3072 -N "" -C "test@agepony" -f ssh_rsa_identity > /dev/null
    echo -n "$PLAINTEXT" | age -R ssh_rsa_identity.pub > ssh_rsa_hello.age
    echo "  identity: ssh_rsa_identity"
    printf "  ciphertext: ssh_rsa_hello.age (%8d bytes)\n" "$(wc -c < ssh_rsa_hello.age)"
    echo
fi

# 4. ssh-ed25519 ENCRYPTED with passphrase
if [ ! -f ssh_ed25519_encrypted_identity ] || [ ! -f ssh_ed25519_encrypted_hello.age ]; then
    echo "Generating ssh-ed25519 ENCRYPTED fixture (passphrase: '$PASSPHRASE')..."
    rm -f ssh_ed25519_encrypted_identity ssh_ed25519_encrypted_identity.pub
    ssh-keygen -t ed25519 -N "$PASSPHRASE" -C "encrypted-test@agepony" \
        -f ssh_ed25519_encrypted_identity > /dev/null
    echo -n "$PLAINTEXT" | age -R ssh_ed25519_encrypted_identity.pub > ssh_ed25519_encrypted_hello.age
    echo "  identity: ssh_ed25519_encrypted_identity (passphrase-protected)"
    printf "  ciphertext: ssh_ed25519_encrypted_hello.age (%8d bytes)\n" \
        "$(wc -c < ssh_ed25519_encrypted_hello.age)"
    echo
fi

# 5. ssh-rsa ENCRYPTED with passphrase (3072-bit)
if [ ! -f ssh_rsa_encrypted_identity ] || [ ! -f ssh_rsa_encrypted_hello.age ]; then
    echo "Generating ssh-rsa ENCRYPTED fixture (RSA-3072 with passphrase — may take a moment)..."
    rm -f ssh_rsa_encrypted_identity ssh_rsa_encrypted_identity.pub
    ssh-keygen -t rsa -b 3072 -N "$PASSPHRASE" -C "encrypted-test@agepony" \
        -f ssh_rsa_encrypted_identity > /dev/null
    echo -n "$PLAINTEXT" | age -R ssh_rsa_encrypted_identity.pub > ssh_rsa_encrypted_hello.age
    echo "  identity: ssh_rsa_encrypted_identity (passphrase-protected)"
    printf "  ciphertext: ssh_rsa_encrypted_hello.age (%8d bytes)\n" \
        "$(wc -c < ssh_rsa_encrypted_hello.age)"
    echo
fi

# 6. SSHSIG detached signatures (namespace 'agepony') for ed25519 and rsa identities
if [ ! -f sshsig_message.txt ] || [ ! -f sshsig_ed25519_hello.sig ] || [ ! -f sshsig_rsa_hello.sig ]; then
    echo "Generating SSHSIG detached-signature fixtures (namespace 'agepony')..."
    printf '%s' "$PLAINTEXT" > sshsig_message.txt
    chmod 600 ssh_ed25519_identity ssh_rsa_identity
    rm -f sshsig_ed25519_hello.sig sshsig_rsa_hello.sig
    ssh-keygen -Y sign -n agepony -f ssh_ed25519_identity sshsig_message.txt > /dev/null
    mv sshsig_message.txt.sig sshsig_ed25519_hello.sig
    ssh-keygen -Y sign -n agepony -f ssh_rsa_identity sshsig_message.txt > /dev/null
    mv sshsig_message.txt.sig sshsig_rsa_hello.sig
    echo "  message: sshsig_message.txt"
    echo "  signatures: sshsig_ed25519_hello.sig, sshsig_rsa_hello.sig"
    echo
fi

echo "All fixtures present. Run: ./gradlew test"
