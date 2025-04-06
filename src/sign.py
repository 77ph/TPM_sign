import argparse
import hashlib
import subprocess
import tempfile
import os
import sys
import json
from datetime import datetime

PRIMARY_HANDLE = "0x81000001"
KEYS_DIR = "keys"

# === KeyPoolManager ===
class KeyPoolManager:
    def __init__(self):
        os.makedirs("cache", exist_ok=True)
        self.cache_path = "cache/context.json"
        self.current = None
        self.ctx_file = "signing.ctx"

        if os.path.exists(self.cache_path):
            with open(self.cache_path, "r") as f:
                self.current = json.load(f)
        else:
            self.current = {"key_id": None}

    def load_key(self, key_id, pub_path, priv_path):
        if self.current.get("key_id") == key_id and os.path.exists(self.ctx_file):
            print(f"[*] Key '{key_id}' already loaded.")
            return  # already loaded

        if self.current.get("key_id") is not None and os.path.exists(self.ctx_file):
            print(f"[*] Flushing previously loaded key: {self.current['key_id']}")
            run(["tpm2_flushcontext", self.ctx_file])

        print(f"[*] Loading key '{key_id}' into TPM...")
        run(["tpm2_load", "-C", PRIMARY_HANDLE, "-u", pub_path, "-r", priv_path, "-c", self.ctx_file])
        self.current["key_id"] = key_id
        with open(self.cache_path, "w") as f:
            json.dump(self.current, f)

SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

def run(cmd, silent=False):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"[ERROR] Command failed: {' '.join(cmd)}")
        print(result.stderr)
        sys.exit(1)
    return result.stdout.strip()

def ensure_primary_key():
    output = run(["tpm2_getcap", "handles-persistent"])
    if PRIMARY_HANDLE.lower() in output.lower():
        return
    run(["tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", "primary.ctx"])
    run(["tpm2_evictcontrol", "-C", "o", "-c", "primary.ctx", PRIMARY_HANDLE])

def create_key(key_id: str):
    from cryptography.hazmat.primitives import serialization
    os.makedirs(KEYS_DIR, exist_ok=True)
    pub_path = os.path.join(KEYS_DIR, f"{key_id}.pub")
    priv_path = os.path.join(KEYS_DIR, f"{key_id}.priv")
    meta_path = os.path.join(KEYS_DIR, f"{key_id}.meta.json")

    run(["tpm2_create", "-C", PRIMARY_HANDLE, "-G", "ecc", "-u", pub_path, "-r", priv_path])
    print(f"[✓] Created {pub_path} and {priv_path}")

    # Save metadata hash of pubkey
    with open(pub_path, "rb") as f:
        pub_pem = f.read()
    from cryptography.hazmat.primitives import serialization
    pubkey = serialization.load_pem_public_key(pub_pem)
    uncompressed = pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pubkey_hash = hashlib.sha256(uncompressed).hexdigest()
    meta = {
        "pubkey_hash": "0x" + pubkey_hash,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[✓] Metadata saved to {meta_path}")

def list_keys():
    if not os.path.exists(KEYS_DIR):
        print("No keys found.")
        return
    print("Available keys:")
    for filename in os.listdir(KEYS_DIR):
        if filename.endswith(".priv"):
            key_id = filename.replace(".priv", "")
            print(f"- {key_id}")

def validate_key_pubhash(key_id: str):
    meta_path = os.path.join(KEYS_DIR, f"{key_id}.meta.json")
    pub_path = os.path.join(KEYS_DIR, f"{key_id}.pub")

    if not os.path.exists(meta_path):
        print(f"[!] Missing meta file for key '{key_id}'. Cannot verify pubkey integrity.")
        sys.exit(1)
    meta = json.load(open(meta_path))

    from cryptography.hazmat.primitives import serialization
    with open(pub_path, "rb") as f:
        pub_pem = f.read()
    pubkey = serialization.load_pem_public_key(pub_pem)
    uncompressed = pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    computed_hash = "0x" + hashlib.sha256(uncompressed).hexdigest()
    if computed_hash != meta["pubkey_hash"]:
        print("[!] Public key hash mismatch! Possible key.priv or key.pub tampering.")
        print(f"Expected: {meta['pubkey_hash']}")
        print(f"Got     : {computed_hash}")
        sys.exit(1)

def compute_eth_v(pubkey, message_hash, r, s):
    from eth_keys import keys
    from eth_keys.exceptions import BadSignature

    for v_try in (27, 28):
        try:
            signature_bytes = r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([v_try - 27])
            sig = keys.Signature(signature_bytes)
            recovered_pubkey = sig.recover_public_key_from_msg_hash(message_hash)
            if recovered_pubkey.to_bytes() == pubkey:
                return v_try
        except BadSignature:
            continue
    return None

def sign_with_key(key_id: str, message: str, eth_mode=False):
    from cryptography.hazmat.primitives import serialization
    pub_path = os.path.join(KEYS_DIR, f"{key_id}.pub")
    priv_path = os.path.join(KEYS_DIR, f"{key_id}.priv")

    if not os.path.exists(pub_path) or not os.path.exists(priv_path):
        print(f"[!] Key '{key_id}' not found in {KEYS_DIR}/")
        sys.exit(1)

    validate_key_pubhash(key_id)

    digest = hashlib.sha256(message.encode()).digest()
    with tempfile.NamedTemporaryFile("wb", delete=False) as digest_file:
        digest_file.write(digest)
        digest_path = digest_file.name

    keypool = KeyPoolManager()
    keypool.load_key(key_id, pub_path, priv_path)
    run(["tpm2_sign", "-c", "signing.ctx", "-g", "sha256", "-m", digest_path, "-o", "signature.bin", "-f", "plain"])
    # flush handled by KeyPoolManager (max 1 key allowed)

    with open("signature.bin", "rb") as f:
        sig = f.read()
        r = int.from_bytes(sig[:len(sig)//2], 'big')
        s = int.from_bytes(sig[len(sig)//2:], 'big')

    if s > SECP256K1_N // 2:
        print(f"[!] Signature 's' value too high (violates Ethereum EIP-2)")
        sys.exit(1)

    print(f"[✓] Signature (r, s):")
    print(f"r = {hex(r)}")
    print(f"s = {hex(s)}")

    if eth_mode:
        with open(pub_path, "rb") as f:
            pub_pem = f.read()
        pubkey = serialization.load_pem_public_key(pub_pem)
        uncompressed = pubkey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        uncompressed_bytes = uncompressed[1:]  # skip 0x04

        v = compute_eth_v(uncompressed_bytes, digest, r, s)
        if v is None:
            print("[!] Could not determine Ethereum-compatible `v`.")
            return

        eth_sig = {
            "r": hex(r),
            "s": hex(s),
            "v": v
        }
        with open("eth_signature.json", "w") as f:
            json.dump(eth_sig, f, indent=2)
        print("[✓] Ethereum signature saved to eth_signature.json")

        timestamp = datetime.utcnow().isoformat() + "Z"
        log_id = hashlib.sha256((key_id + message).encode()).hexdigest()
        os.makedirs("logs", exist_ok=True)
        log_entry = {
            "timestamp": timestamp,
            "key_id": key_id,
            "message_hash": "0x" + digest.hex(),
            "r": hex(r),
            "s": hex(s),
            "v": v,
            "log_id": "0x" + log_id,
            "source": "string"
        }
        with open("logs/signatures.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        print("[✓] Signature logged to logs/signatures.log")

def main():
    parser = argparse.ArgumentParser(description="TPM-backed signer CLI")
    subparsers = parser.add_subparsers(dest="command")

    sign_parser = subparsers.add_parser("sign", help="Sign a message")
    sign_parser.add_argument("--key-id", required=True)
    sign_parser.add_argument("--message", required=True)
    sign_parser.add_argument("--eth", action="store_true", help="Export r,s,v for Ethereum")

    create_parser = subparsers.add_parser("create", help="Create a new key")
    create_parser.add_argument("--key-id", required=True)

    list_parser = subparsers.add_parser("list", help="List available keys")

    args = parser.parse_args()
    if args.command == "sign":
        ensure_primary_key()
        sign_with_key(args.key_id, args.message, eth_mode=args.eth)
    elif args.command == "create":
        create_key(args.key_id)
    elif args.command == "list":
        list_keys()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
