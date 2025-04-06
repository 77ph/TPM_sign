
# 🔐 TPM Key Storage Summary (Markdown)

This table summarizes where TPM-related objects live, whether they survive reboot, and whether they're secure from host access.

| Object          | Location         | Survives Reboot? | Secure from Host? | Description |
|-----------------|------------------|------------------|-------------------|-------------|
| **Persistent Key** (`0x81xxxxxx`) | TPM NVRAM        | ✅ Yes            | ✅ Yes       | Long-term key stored inside TPM using `tpm2_evictcontrol`. |
| **Transient Key** (`*.ctx`)       | TPM RAM          | ❌ No             | ✅ Yes       | Temporary key loaded in TPM RAM. Lost on reboot or flush. |
| **Primary Key** (`primary.ctx`)   | TPM RAM          | ❌ No             | ✅ Yes       | Root key for creating child keys. Must be re-created after reboot unless made persistent. |
| **key.priv**     | File (on disk)   | ✅ Yes            | ✅ Yes (if TPM is required) | Encrypted blob. Only usable with TPM and the matching primary key. |
| **key.pub**      | File (on disk)   | ✅ Yes            | ❌ No            | Public key. Can be shared freely. Useful for verifying signatures. |

> Notes:
> - `*.ctx` files are TPM handles (references) only — they do not contain private keys.
> - `key.priv` is encrypted using the TPM's internal mechanisms and cannot be decrypted outside the TPM.
> - Persistent keys consume TPM NVRAM slots (typically 7–8 max).


