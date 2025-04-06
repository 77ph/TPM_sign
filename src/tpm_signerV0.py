import subprocess
import hashlib
import os
import sys

PERSISTENT_HANDLE = "0x81010001"

def run_cmd(cmd, quiet=False):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"[ERROR] Command failed: {' '.join(cmd)}")
        print(result.stderr)
        sys.exit(1)
    return result.stdout.strip() if not quiet else ""

def persistent_key_exists():
    output = run_cmd(["tpm2_getcap", "handles-persistent"])
    return PERSISTENT_HANDLE.lower() in output.lower()

def create_persistent_key():
    print("[*] Creating primary ECC key...")
    run_cmd(["tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", "primary.ctx"], quiet=True)

    print("[*] Creating ECDSA signing key...")
    run_cmd(["tpm2_create", "-G", "ecc", "-u", "key.pub", "-r", "key.priv", "-C", "primary.ctx"], quiet=True)

    print("[*] Loading signing key...")
    run_cmd(["tpm2_load", "-C", "primary.ctx", "-u", "key.pub", "-r", "key.priv", "-c", "signing_key.ctx"], quiet=True)

    print(f"[*] Making key persistent at handle {PERSISTENT_HANDLE}...")
    run_cmd(["tpm2_evictcontrol", "-C", "o", "-c", "signing_key.ctx", PERSISTENT_HANDLE])

    print("[✓] Persistent key created.")

def sign_message(message: bytes):
    with open("message.txt", "wb") as f:
        f.write(message)

    digest = hashlib.sha256(message).digest()
    with open("digest.bin", "wb") as f:
        f.write(digest)

    print("[*] Signing digest with persistent key...")
    run_cmd(["tpm2_sign", "-c", PERSISTENT_HANDLE, "-g", "sha256", "-m", "digest.bin", "-o", "signature.bin"], quiet=True)

    with open("signature.bin", "rb") as f:
        sig = f.read()
        print(f"[✓] Signature complete. Signature (hex): {sig.hex()}")

if __name__ == "__main__":
    print("🔐 TPM Signer using Persistent Key")

    if not persistent_key_exists():
        print("[*] Persistent key not found. Creating...")
        create_persistent_key()
    else:
        print(f"[*] Persistent key {PERSISTENT_HANDLE} exists.")

    # Example message
    message = b"Hello from TPM persistent key!"
    sign_message(message)
