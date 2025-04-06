import argparse
import hashlib
import subprocess
import tempfile
import os
import sys
import json

PRIMARY_HANDLE = "0x81000001"
KEYS_DIR = "keys"

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
    ensure_primary_key()
    os.makedirs(KEYS_DIR, exist_ok=True)
    pub_path = os.path.join(KEYS_DIR, f"{key_id}.pub")
    priv_path = os.path.join(KEYS_DIR, f"{key_id}.priv")

    run(["tpm2_create", "-C", PRIMARY_HANDLE, "-G", "ecc", "-u", pub_path, "-r", priv_path])
    print(f"[✓] Created {pub_path} and {priv_path}")

def list_keys():
    if not os.path.exists(KEYS_DIR):
        print("No keys found.")
        return
    print("Available keys:")
    for filename in os.listdir(KEYS_DIR):
        if filename.endswith(".priv"):
            key_id = filename.replace(".priv", "")
            print(f"- {key_id}")

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

    digest = hashlib.sha256(message.encode()).digest()
    with tempfile.NamedTemporaryFile("wb", delete=False) as digest_file:
        digest_file.write(digest)
        digest_path = digest_file.name

    run(["tpm2_load", "-C", PRIMARY_HANDLE, "-u", pub_path, "-r", priv_path, "-c", "signing.ctx"])
    run(["tpm2_sign", "-c", "signing.ctx", "-g", "sha256", "-m", digest_path, "-o", "signature.bin", "-f", "plain"])
    run(["tpm2_flushcontext", "signing.ctx"])

    with open("signature.bin", "rb") as f:
        sig = f.read()
        r = int.from_bytes(sig[:len(sig)//2], 'big')
        s = int.from_bytes(sig[len(sig)//2:], 'big')

    if s > SECP256K1_N // 2:
        print(f"[!] Signature 's' value is too high (violates Ethereum EIP-2):")
        print(f"s = {hex(s)}")
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
        uncompressed_bytes = uncompressed[1:]  # remove 0x04 prefix

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


def verify_signature(key_id: str, message: str):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.exceptions import InvalidSignature

    pub_path = os.path.join(KEYS_DIR, f"{key_id}.pub")
    if not os.path.exists(pub_path) or not os.path.exists("signature.bin"):
        print("[!] Missing required files for verification.")
        return

    with open(pub_path, "rb") as f:
        pem = f.read()
    pubkey = serialization.load_pem_public_key(pem)

    digest = hashlib.sha256(message.encode()).digest()
    with open("signature.bin", "rb") as f:
        sig = f.read()
    r = int.from_bytes(sig[:len(sig)//2], 'big')
    s = int.from_bytes(sig[len(sig)//2:], 'big')
    signature = utils.encode_dss_signature(r, s)

    try:
        pubkey.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        print("[✓] Signature is valid.")
    except InvalidSignature:
        print("[!] Signature is INVALID.")

def main():
    parser = argparse.ArgumentParser(description="TPM-backed signer CLI")
    subparsers = parser.add_subparsers(dest="command")

    sign_parser = subparsers.add_parser("sign", help="Sign a message")
    sign_parser.add_argument("--key-id", required=True)
    sign_parser.add_argument("--message", required=True)
    sign_parser.add_argument("--eth", action="store_true", help="Export r,s,v for Ethereum")

    create_parser = subparsers.add_parser("create", help="Create a new key")
    create_parser.add_argument("--key-id", required=True)

    verify_parser = subparsers.add_parser("verify", help="Verify a signature")
    verify_parser.add_argument("--key-id", required=True)
    verify_parser.add_argument("--message", required=True)

    list_parser = subparsers.add_parser("list", help="List available keys")

    args = parser.parse_args()
    if args.command == "sign":
        ensure_primary_key()
        sign_with_key(args.key_id, args.message, eth_mode=args.eth)
    elif args.command == "create":
        create_key(args.key_id)
    elif args.command == "verify":
        verify_signature(args.key_id, args.message)
    elif args.command == "list":
        list_keys()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

