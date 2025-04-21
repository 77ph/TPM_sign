# 🛡️ TPM-Backed Scalable Signer: Architecture Overview

This document describes a scalable and reboot-resilient architecture for signing messages using TPM 2.0 without exposing private keys to user space or host.

---

## 🎯 Goals

- ✅ Persist across reboots (keys survive system restart)
- ✅ Store a large number of private keys securely (beyond TPM NVRAM limits)
- ✅ Run multiple signer processes with limited transient handle usage
- ✅ Never expose private keys to RAM or disk in plaintext

---

## 🧠 Key Concepts

| Type             | Description                                                  |
|------------------|--------------------------------------------------------------|
| `Persistent Primary Key` | Stored permanently in TPM NVRAM (handle: `0x81000001`) |
| `key.priv/.pub` pairs    | TPM-encrypted private keys and public keys stored on disk |
| Transient Handles        | Temporary TPM objects in RAM used for loaded keys       |
| Signer Context           | TPM object handle for active key (created on-the-fly)   |

---

## 🧱 System Architecture

```text
               [ Disk Storage ]
        +-----------------------------+
        | key1.priv / key1.pub        |
        | key2.priv / key2.pub        |
        | ...                         |
        +-----------------------------+

              |
              v  (load on demand)
    +------------------------------+
    |    Signer Process            |
    |------------------------------|
    | - Loads key.priv/.pub into TPM |
    | - Signs digest                |
    | - Flushes context if needed   |
    +------------------------------+

              |
              v
        [ TPM Transient Handle (RAM) ]
              |
              v
        Signature Output (r, s)
```

---

## 🔁 Workflow

1. **Create Persistent Primary Key** (once):
   ```bash
   tpm2_createprimary -C o -G ecc -c primary.ctx
   tpm2_evictcontrol -C o -c primary.ctx 0x81000001
   ```

2. **Create Private Key for Disk Storage** (repeatable):
   ```bash
   tpm2_create -C 0x81000001 -G ecc -u key1.pub -r key1.priv
   ```

3. **Signer Process Execution** (per request):
   ```bash
   tpm2_load -C 0x81000001 -u key1.pub -r key1.priv -c signer.ctx
   tpm2_sign -c signer.ctx -g sha256 -m digest.bin -o signature.bin
   tpm2_flushcontext signer.ctx
   ```

---

## ⚙️ Scalability Considerations

| Property           | Strategy                          |
|--------------------|------------------------------------|
| Max persistent keys| Use only one: the primary key      |
| Unlimited keys     | Store key.priv/.pub files on disk  |
| TPM RAM slots      | Use one context at a time, flush after use |
| Parallel signing   | Use a worker queue or LRU slot management |

---

## 🔐 Security Guarantees

- TPM signs hashes inside the chip
- Private keys never loaded in RAM in plaintext
- Even `key.priv` is unusable outside TPM
- Supports recovery after reboot

---

## 🧩 Future Extensions

- Signer REST API with key pool loader
- Key rotation and indexing
- PCR-based sealing for specific boot states

## Not compatible with secp256k1
```
sudo tpm2_getcap ecc-curves
TPM2_ECC_NIST_P256: 0x3
TPM2_ECC_NIST_P384: 0x4
TPM2_ECC_BN_P256: 0x10
TPM2_ECC_SM2_P256: 0x20
```
