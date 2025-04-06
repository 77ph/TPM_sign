# 🔐 TPM PCR-Based Sealing: Concept and Use Case

This document explains what PCR-based sealing is, how it works, and why it can be critical for securing TPM-backed signing operations.

---

## 🧠 What Are PCRs?

**PCR (Platform Configuration Registers)** are special TPM registers that store cryptographic measurements of system components during the boot process.

| PCR Index | Measured Component            |
|-----------|-------------------------------|
| PCR[0]    | BIOS / Firmware                |
| PCR[1]    | Bootloader                     |
| PCR[2]    | Kernel (vmlinuz)               |
| PCR[7]    | Secure Boot or system state    |

TPM automatically updates these values during system boot.

---

## 🔐 What Is PCR-Based Sealing?

PCR sealing allows you to encrypt (or "seal") a secret — such as a TPM key or sensitive data — and make it retrievable **only if the system boots into a trusted state**.

**If the PCR values do not match the expected values, the secret cannot be unsealed.**

---

## 🎯 Why Use This?

For a signing service that runs in an **untrusted host**, you may want to:

- Ensure secrets are only accessible in a **known-good boot state**.
- Prevent attackers from copying `.priv` files to another host and using them.
- Protect keys even from a root-level compromise **after boot**.

---

## 🧱 How It Works (Concept)

1. TPM records boot measurements in PCRs.
2. You create a sealing policy based on PCRs (e.g., PCR[7]).
3. You seal your key or secret with that policy.
4. On access, TPM checks PCRs match — only then is access granted.

Example commands:
```bash
tpm2_policypcr -l sha256:7 -L pcr.policy
tpm2_create -C 0x81000001 -L pcr.policy -u key.pub -r key.priv
```

---

## ✅ What Threats Does It Prevent?

| Threat                                 | Mitigated? |
|----------------------------------------|------------|
| Booting a tampered OS/kernel/initrd    | ✅ Yes     |
| Using `.priv` file on another machine  | ✅ Yes     |
| LiveCD attacks                         | ✅ Yes     |
| Root access after boot                 | ❌ Not fully (use TDX + sealing for this) |

---

## ⚠️ When To Use PCR-Based Sealing

Use it when:

- You control the boot process (e.g., Secure Boot).
- You want strong assurance that signing only occurs in a trusted environment.
- You distribute a bootable image with known measurements.

Do NOT use it if:

- You frequently change kernels or bootloaders.
- You require highly portable systems without boot integrity guarantees.

---

## 📌 Summary

PCR-based sealing provides **hardware-enforced integrity checking** that ensures secrets can only be used in specific, trusted boot states. This is especially valuable in high-assurance signing systems that rely on TPM-backed key material.


