import os
import sys
import json
import shutil
import hashlib
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from argparse import ArgumentParser
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.backends import default_backend
from eth_keys import keys
from eth_utils import to_checksum_address, keccak

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def run(cmd, **kwargs):
    try:
        subprocess.run(cmd, check=True, **kwargs)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {' '.join(cmd)}")
        raise SystemExit(1)

def load_metadata(key_id):
    meta_path = Path(f"keys/{key_id}.meta.json")
    if not meta_path.exists():
        return {}
    with open(meta_path, "r") as f:
        return json.load(f)

def save_metadata(key_id, metadata):
    meta_path = Path(f"keys/{key_id}.meta.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

def create_key(key_id):
    Path("keys").mkdir(exist_ok=True)
    ctx_path = f"keys/{key_id}.tpm"
    pub_path = f"keys/{key_id}.pub"
    priv_path = f"keys/{key_id}.priv"

    run(["tpm2_create", "-C", "0x81000001", "-G", "ecc", "-u", pub_path, "-r", priv_path])
    run(["tpm2_load", "-C", "0x81000001", "-u", pub_path, "-r", priv_path, "-c", ctx_path])
    run(["tpm2_readpublic", "-c", ctx_path, "-f", "pem", "-o", pub_path])

    metadata = {
        "key_id": key_id,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    save_metadata(key_id, metadata)
    print(f"[✓] Created {pub_path} and {priv_path}")
    print(f"[✓] Metadata saved to keys/{key_id}.meta.json")

class KeyPoolManager:
    def __init__(self, cache_dir="cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / "context.json"
        self.state = self._load_state()

    def _load_state(self):
        if self.cache_file.exists():
            with open(self.cache_file, "r") as f:
                return json.load(f)
        return {}

    def _save_state(self):
        with open(self.cache_file, "w") as f:
            json.dump(self.state, f, indent=2)

    def is_loaded(self, key_id):
        return self.state.get("current") == key_id

    def load_key(self, key_id):
        if self.is_loaded(key_id):
            print(f"[*] Key '{key_id}' already loaded.")
            return
        ctx_path = f"keys/{key_id}.tpm"
        if not Path(ctx_path).exists():
            print(f"[!] TPM context for key '{key_id}' not found.")
            sys.exit(1)
        shutil.copy(ctx_path, "signing.ctx")
        self.state["current"] = key_id
        self._save_state()
        print(f"[✓] Key '{key_id}' loaded into signing.ctx")

def compute_eth_v(pubkey_bytes, message_hash, r, s):
    for v_try in (27, 28):
        try:
            sig = keys.Signature(r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([v_try - 27]))
            recovered = sig.recover_public_key_from_msg_hash(message_hash)
            print(f"[DEBUG] Trying v={v_try}")
            print(f"[DEBUG] r=0x{r:064x}")
            print(f"[DEBUG] s=0x{s:064x}")
            print(f"[DEBUG] digest=0x{message_hash.hex()}")
            print(f"[DEBUG] pubkey_bytes=0x{pubkey_bytes.hex()}")
            print(f"[DEBUG] recovered=0x{recovered.to_bytes().hex()}")
            if recovered.to_bytes() == pubkey_bytes:
                return v_try
        except Exception as e:
            print(f"[DEBUG] Exception during v={v_try}: {e}")
    return None

def sign_with_key(key_id, message, eth_mode=False):
    pool = KeyPoolManager()
    pool.load_key(key_id)

    if eth_mode:
        eth_message = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message.encode()
        digest = keccak(eth_message)
    else:
        digest = hashlib.sha256(message.encode()).digest()

    if int.from_bytes(digest, 'big') >= SECP256K1_N:
        print("[!] Digest too large.")
        return

    with tempfile.NamedTemporaryFile(delete=False) as tmp_digest:
        tmp_digest.write(digest)
        tmp_digest_path = tmp_digest.name

    run(["tpm2_sign", "-c", "signing.ctx", "--digest", tmp_digest_path, "-o", "signature.bin", "-f", "plain"])
    os.unlink(tmp_digest_path)

    with open("signature.bin", "rb") as f:
        sig = f.read()
    r, s = asym_utils.decode_dss_signature(sig)

    print(f"[✓] Signature: r=0x{r:064x} s=0x{s:064x}")

    if eth_mode:
        if s > SECP256K1_N // 2:
            print("[!] Signature 's' is too high for Ethereum (EIP-2).")
            return

        pub_path = f"keys/{key_id}.pub"
        with open(pub_path, "rb") as f:
            pubkey = serialization.load_pem_public_key(f.read(), backend=default_backend())
        pub_numbers = pubkey.public_numbers()
        uncompressed = b"\x04" + pub_numbers.x.to_bytes(32, 'big') + pub_numbers.y.to_bytes(32, 'big')
        v = compute_eth_v(uncompressed, digest, r, s)
        if v is None:
            print("[!] Could not determine Ethereum-compatible v.")
            sys.exit(1)
        print(f"[✓] Ethereum Signature: r=0x{r:064x}, s=0x{s:064x}, v={v}")

def main():
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    create = subparsers.add_parser("create")
    create.add_argument("--key-id", required=True)

    sign = subparsers.add_parser("sign")
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--message", required=True)
    sign.add_argument("--eth", action="store_true")

    args = parser.parse_args()

    if args.command == "create":
        create_key(args.key_id)
    elif args.command == "sign":
        sign_with_key(args.key_id, args.message, eth_mode=args.eth)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
