import argparse
import hashlib
import subprocess
import tempfile
import os
import sys
import json
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization

PRIMARY_HANDLE = "0x81000001"
KEYS_DIR = "keys"
SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

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
            return
        if self.current.get("key_id") is not None and os.path.exists(self.ctx_file):
            print(f"[*] Flushing previously loaded key: {self.current['key_id']}")
            run(["tpm2_flushcontext", self.ctx_file])
        print(f"[*] Loading key '{key_id}' into TPM...")
        run(["tpm2_load", "-C", PRIMARY_HANDLE, "-u", pub_path, "-r", priv_path, "-c", self.ctx_file])
        self.current["key_id"] = key_id
        with open(self.cache_path, "w") as f:
            json.dump(self.current, f)

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

def create_key(key_id):
    os.makedirs(KEYS_DIR, exist_ok=True)
    bin_pub_path = os.path.join(KEYS_DIR, f"{key_id}.binpub")
    pub_path = os.path.join(KEYS_DIR, f"{key_id}.pub")
    priv_path = os.path.join(KEYS_DIR, f"{key_id}.priv")
    bin_bin_pub_path = os.path.join(KEYS_DIR, f"{key_id}.binpub")
    pub_path = os.path.join(KEYS_DIR, f"{key_id}.pub")
    ctx_path = os.path.join(KEYS_DIR, f"{key_id}.ctx")
    meta_path = os.path.join(KEYS_DIR, f"{key_id}.meta.json")

    run(["tpm2_create", "-C", PRIMARY_HANDLE, "-G", "ecc", "-u", bin_pub_path, "-r", priv_path])
    run(["tpm2_load", "-C", PRIMARY_HANDLE, "-u", bin_pub_path, "-r", priv_path, "-c", ctx_path])
    run(["tpm2_readpublic", "-c", ctx_path, "-f", "pem", "-o", pub_path])

    with open(pub_path, "rb") as f:
        pub_pem = f.read()
    pubkey = serialization.load_pem_public_key(pub_pem)
    uncompressed = pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pubkey_hash = hashlib.sha256(uncompressed).hexdigest()
    meta = {
        "pubkey_hash": "0x" + pubkey_hash,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[✓] Created {pub_path} and {priv_path}")
    print(f"[✓] Metadata saved to {meta_path}")

def list_keys():
    if not os.path.exists(KEYS_DIR):
        print("No keys found.")
        return
    print("Available keys:")
    for filename in os.listdir(KEYS_DIR):
        if filename.endswith(".priv"):
            print(f"- {filename.replace('.priv', '')}")

def validate_key_pubhash(key_id):
    bin_pub_path = os.path.join(KEYS_DIR, f"{key_id}.binpub")
    pub_path = os.path.join(KEYS_DIR, f"{key_id}.pub")
    meta_path = os.path.join(KEYS_DIR, f"{key_id}.meta.json")
    if not os.path.exists(meta_path):
        print(f"[!] Missing meta file for key '{key_id}'")
        sys.exit(1)
    with open(meta_path) as f:
        meta = json.load(f)
    with open(pub_path, "rb") as f:
        pub_pem = f.read()
    pubkey = serialization.load_pem_public_key(pub_pem)
    uncompressed = pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    computed_hash = "0x" + hashlib.sha256(uncompressed).hexdigest()
    if computed_hash != meta["pubkey_hash"]:
        print("[!] Public key hash mismatch. Possible tampering.")
        sys.exit(1)

def compute_eth_v(pubkey_bytes, message_hash, r, s):
    from eth_keys import keys
    for v_try in (27, 28):
        try:
            sig = keys.Signature(r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([v_try - 27]))
            if sig.recover_public_key_from_msg_hash(message_hash).to_bytes() == pubkey_bytes:
                return v_try
        except:
            continue
    return None

main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    p_create = subparsers.add_parser("create")
    p_create.add_argument("--key-id", required=True)

    p_sign = subparsers.add_parser("sign")
    p_sign.add_argument("--key-id", required=True)
    p_sign.add_argument("--message", required=True)
    p_sign.add_argument("--eth", action="store_true")

    p_list = subparsers.add_parser("list")

    args = parser.parse_args()
    ensure_primary_key()

    if args.command == "create":
        create_key(args.key_id)
    elif args.command == "sign":
        sign_with_key(args.key_id, args.message, eth_mode=args.eth)
    elif args.command == "list":
        list_keys()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

