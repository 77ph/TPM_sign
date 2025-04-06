### Step 1.0: TPM initialization and primary key generation
```
tpm2_createprimary -C o -G ecc -c primary.ctx
tpm2_evictcontrol -C o -c primary.ctx 0x81000001
```

###  Step 1.1: Gen new signing-key (key_id = example_key)
```
mkdir -p keys
tpm2_create -C 0x81000001 -G ecc -u keys/example_key.pub -r keys/example_key.priv

Now:

keys/example_key.priv — private key (encrypt by TPM),

keys/example_key.pub — public key.
```

### Step 1.2: Sign message
```
echo -n "hello tpm" > message.txt
openssl dgst -sha256 -binary message.txt > digest.bin

# load key to TPM
tpm2_load -C 0x81000001 -u keys/example_key.pub -r keys/example_key.priv -c signer.ctx

# signed
tpm2_sign -c signer.ctx -g sha256 -m digest.bin -o signature.bin

# flush
tpm2_flushcontext signer.ctx
```

### Python CLI
#### New key
```
python3 signer.py create --key-id mykey

```
#### List keys
```
python3 signer.py list
```
#### Sign message
```
python3 signer.py sign --key-id mykey --message "hello tpm"
python3 signer.py sign --key-id mykey --message "hello eth" --eth
```
#### Verify sign
```
python3 signer.py verify --key-id mykey --message "hello tpm"
```

