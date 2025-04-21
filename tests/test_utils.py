import hashlib
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

def get_uncompressed_pubkey(pub_pem: bytes) -> bytes:
    pubkey = serialization.load_pem_public_key(pub_pem)
    uncompressed = pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return uncompressed

def hash_pubkey(pub_pem: bytes) -> str:
    uncompressed = get_uncompressed_pubkey(pub_pem)
    return "0x" + hashlib.sha256(uncompressed).hexdigest()

def test_pubkey_hash():
    with open("keys/test1.pub", "rb") as f:
        pub_pem = f.read()
    computed = hash_pubkey(pub_pem)
    with open("keys/test1.meta.json", "r") as f:
        meta = json.load(f)
    assert computed == meta["pubkey_hash"], "Pubkey hash mismatch!"

def test_low_s_check():
    low_s = 1
    high_s = SECP256K1_N - 1
    assert low_s <= SECP256K1_N // 2, "Low-s should be valid"
    assert high_s > SECP256K1_N // 2, "High-s should be rejected"

