# model-encryption

## Model Encryption and Signing

This project is based on the model transparency's model_signing library
and adds encryption of AI model files to it.

All files except for those starting with '.' (hidden files and directories)
are encrypted. Therefore, the `.git` directory is not encrypted, and it is
possible that an encrypted model is checked into a git repository.

Note that if the encrypted data are stored in a git repository, then this git
repository should not previously have contained unencrypted model data
since the history of the git repository could be used to restore the model
before it was encrypted.
The git initialization with `git init` should therefore only be run *after*
all files have been encrypted. To update files in the git repository, the
current files can be decrypted and (individually) replaced with updated
files and then encrypted again, added to the git repository with the usual
workflow involving `git add`, `git commit`, and `git push`.

To encrypt and sign the files in a directory with an AI model, the following
preparatory steps can be taken to create a 32 byte long AES-256 key.

```bash
dd if=/dev/urandom bs=1 count=32 of=aes256.bin
```

### Signing with an Elliptic Curve Key

To create an elliptic curve key pair, run the following commands:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out key.priv
openssl ec -in key.priv -pubout -out key.pub
```

Note that only NIST P256/384/521 (secp256/385/521r1) keys are currently
supported.

To sign and encrypt a local model do the following:
```bash
python -m model_security sign+encrypt key \
     --private_key key.priv \
     --encryption-key aes256.bin \
     --signature granite-3.3-2b-instruct/model.sig \
     granite-3.3-2b-instruct/
```

To decrypt and verify the model do the following:
```bash
python -m model_security decrypt+verify key \
     --public_key key.pub \
     --encryption-key aes256.bin \
     --signature granite-3.3-2b-instruct/model.sig \
     granite-3.3-2b-instruct/
```
Note that with the 'sign+encrypt' and 'decrypt+verify' methods the signature
verification will continue working even after the model has been decrypted.
The same command line with 'decrypt+verify' can be used after the first
decryption since it will not decrypt files anymore after it but only perform
signature verification.

### Signing with an Elliptic Curve Key and a Certificate Chain

This signing method requires that the user has one of the supported types of
an Elliptic Curve Key as mentioned above and a **code-signing** certificate for
the key that, in the best case, can be rooted in a root-CA of a well-known
certificate provider.

The following methods can be used for creating a certificate chain:

- A key with a certificate chain and a root-CA can be created with
  [this script](https://github.com/sigstore/model-transparency/blob/d1a61257056e042ab09456adb9c91c6f3df606cf/scripts/tests/keys/certificate/gen.sh).

- An existing elliptic curve key can become part of IBM's internal
  certificate chain using
  [CertHub's Request Private TLS/SSL page](https://certhub.digitalcerts.identity-services.intranet.ibm.com/).

- It is possible to request a key hosted in an GaraSign vHSM by onboarding
  to the CISO code signing service using
  [this webpage](https://w3.ibm.com/w3publisher/ciso-appsec/services/code-signing).
  Since this key is hosted inside a vHSM, it can then become part of a DigiCert certificate
  chain (software keys do not qualify).
  The HSM must support the PKCS #11 protocol so that the model signing
  library (>=v1.0.2) can use it with the pkcs11-certificate signing method,
  which in turn requires a PKCS #11 URI to describe the private key.
  More details about the signing with PKCS #11 URI can be found in the
  model signing library's [documentation](https://github.com/sigstore/model-transparency/?tab=readme-ov-file#signing-with-pkcs-11-uris).


To sign and encrypt a local model with a software key do the following:
```bash
python -m model_security sign+encrypt certificate \
     --private_key signing-key.pem \
     --signing_certificate signing-key-cert.pem \
     --certificate_chain int-ca-cert.pem \
     --encryption-key aes256.bin \
     --signature granite-3.3-2b-instruct/model.sig \
     granite-3.3-2b-instruct/
```

It is necessary to pass part of the certificate chain to the signing
command, particularly the certificate for the signing key and an
intermediate CA's certificate must be provided. All those parts that have been
passed to the signing command do not need to be passed to the verification
anymore since they are all part of the model signature. However, the root-CA
cannot be passed during signing but must be passed during signature
verification.

To decrypt and verify the model do the following:
```bash
python -m model_security decrypt+verify certificate \
     --certificate_chain ca-cert.pem \
     --encryption-key aes256.bin \
     --signature granite-3.3-2b-instruct/model.sig \
     granite-3.3-2b-instruct/
```

### Signing with Sigstore

To sign with sigstore it is necessary to either retrieve a JWT token from
the IBM OIDC identity provider, or use one of the default authentication
methods provided by the sigstore method itself. In case the IBM OIDC
identity provider is to be used, the
[verifyctl](https://github.com/IBM-Verify/verifyctl) tool needs to be built
first before running the following command and pasting the URL the tool
shows into a browser.

```bash
verifyctl auth sigstore.verify.ibm.com \
	--clientId ba38bfc2-894f-4365-9ef5-72ea59e01af9 \
	--print \
	--user
```

The result of the w3 authentication is a token returned by verifyctl. It can
be assigned to a shell variable 'token' to then sign with Sigstore:

```bash
token=eyJ...

python -m model_security sign+encrypt sigstore \
     --identity_token "${token}" \
     --encryption-key aes256.bin \
     --signature granite-3.3-2b-instruct/model.sig \
     granite-3.3-2b-instruct/
```

To decrypt and verify the model do the following:
```bash
python -m model_security decrypt+verify sigstore \
     --identity_provider https://sigstore.verify.ibm.com/oauth2 \
     --identity 'email address' \
     --encryption-key aes256.bin \
     --signature granite-3.3-2b-instruct/model.sig \
     granite-3.3-2b-instruct/
```

If the email address or the identity provider are not know, then some random
string can be provided and the tool will say what values for these are expected.

## Extending the project

Please run the following commands before adding new patches to the project:

```bash
hatch fmt
hatch run type:check
```
