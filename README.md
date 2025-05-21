## Introduction
`otls` provides primitive building blocks for zkTLS or Web Proofs with the [garble-then-prove](https://eprint.iacr.org/2023/964) method and [QuickSilver](https://eprint.iacr.org/2021/076). The current implementation includes the `MPC Model` and `Proxy Model`.

### MPC Model
This is exactly the implementation of the garble-then-prove paper. More specifically, the client runs a 2PC (Garbled Circuit) protocol with the attestor in HandShake and AEAD encryption. In the Post Record phase, the client runs QuickSilver with the attestor to prove the integrity. 

### Proxy Model
In the Proxy-TLS approach, the attestor acts as a proxy between the client and server, forwarding all TLS transcripts. The attestor can record both the Handshake transcripts and the ciphertexts exchanged between the client and server. At the end of the protocol, the client will prove to the attestor with QuickSilver about the validity of the ciphertexts.

In this case, the client proves the key in the AES encryption is derived (the KDF function) from the pms and the messages are encrypted with the same key under the ciphertext recorded by attestor.

### Supported Version
- TLS 1.2
- Cipher suite: AES-GCM

## Installation
### Install Primus-Emp
`otls` is dependent on `primus-emp`.
```bash
git clone https://github.com/primus-labs/primus-emp.git
cd primus-emp

# Building
bash ./compile.sh

```

### Install OTLS
```bash
git clone https://github.com/primus-labs/otls.git
cd otls

# Building
bash ./compile.sh
```


## Test
All the test cases are located in the directory `test`.

* If you want to test the code in local machine, type

   `./run ./bin/[binaries] 12345 [more opts]`
* IF you want to test the code over two machine, type

  `./bin/[binaries] 1 12345 [more opts]` on one machine and 
  
  `./bin/[binaries] 2 12345 [more opts]` on the other.
  
  IP addresses are hardcoded in the test files.

* An example should run as 
    `./bin/example 1 12345 123 & ./bin/example 2 12345 124`
    
    because different parties need different numbers

## Acknowledgment
This repository is provided as a free resource for the community. You are welcome to use, modify, and distribute the code in accordance with the repository's license. However, if you use this project in your own work, we ask that you acknowledge us by providing appropriate credit.

# ECDSA Signatures for Pedersen Commitments

This README explains how to use ECDSA signatures to sign individual Pedersen commitments in the secure multi-party computation protocol.

## Generating Key Files

Before using the ECDSA signing and verification functionality, you need to generate the necessary cryptographic keys. Follow these steps to create the required PEM files:

### Step 1: Generate a Private Key

Generate an ECDSA private key using the secp256k1 curve:

```bash
openssl ecparam -name secp256k1 -genkey -out private_key.pem
```

This creates `private_key.pem` containing your ECDSA private key.

### Step 2: Extract the Public Key

Extract the corresponding public key from the private key:

```bash
openssl ec -in private_key.pem -pubout -out public_key.pem
```

This creates `public_key.pem` containing your ECDSA public key.

### Step 3: Verify the Key Files (Optional)

You can inspect the contents of these files to confirm they're correct:

```bash
# View the private key details
openssl ec -in private_key.pem -text -noout

# View the public key details
openssl ec -in public_key.pem -pubin -text -noout
```

## Key Management

- **Private Key (`private_key.pem`)**: Used by the signer to generate signatures. Keep this file secure and don't share it.
- **Public Key (`public_key.pem`)**: Used by the verifier to validate signatures. This file can be shared publicly.

## Workflow

The commitment signing process works as follows:

1. **Signing Commitments**:
   - The signer loads the private key from `private_key.pem`
   - Each commitment point is individually hashed and signed
   - All signatures are sent to the verifier

2. **Verifying Signatures**:
   - The verifier loads the public key from `public_key.pem`
   - Receives all signatures from the signer
   - Verifies each signature against its corresponding commitment

## Code Usage

### Signing Commitments

```cpp
// Sign all commitments individually
bool signed = conv.sign_commitments_with_ecdsa(com, chunk_len, "private_key.pem", pc);
if (signed) {
    cout << "Created signatures: " << conv.get_signature_info() << endl;
}
```

### Verifying Signatures

```cpp
// Verify all commitment signatures
bool verified = conv.verify_commitment_signature(com, chunk_len, "public_key.pem", pc);
if (verified) {
    cout << "Verified signatures: " << conv.get_signature_info() << endl;
}
```

## Security Considerations

- Keep the private key (`private_key.pem`) secure and do not share it
- In a production environment, use secure key storage solutions
- Consider implementing key rotation policies for long-term security
- Make sure file permissions are set appropriately (e.g., `chmod 600 private_key.pem`)

## Troubleshooting

If you encounter issues with signature verification, check:

1. That both parties are using compatible key pairs
2. The file paths to the key files are correct
3. The commitments haven't been modified between signing and verification
4. The file permissions allow the application to read the key files