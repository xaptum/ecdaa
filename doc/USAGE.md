# Using the Libraries

The top-level header to include is `ecdaa.h`,
and the name of the library is `libecdaa`.

## API Conventions

All API functions exist in the `ecdaa` namespace,
and are focused on a small number of basic `structs` (e.g. `signature`).
Function names take the form `ecdaa_<struct-name>[_TPM]_<curve-name>_<action>`,
where `_TPM` is only present for versions that use a TPM (see below).
For example, for generating a credential when using the BN254 curve-type, the function
to use is `ecdaa_credential_BN254_generate`.

Output parameters are frequently used in the API functions, and come at the beginning
of the parameter list.

The fundamental structs have (de-)serialization functions,
and macros and functions giving their serialized length.
Again, the format of the serialized length macro/function is
`ecdaa_<struct-name>_<curve-name>_length` (capitalized for the macro).

Success is indicated by a `0` return value.
Each function defines its own non-zero error return values
(documented in the relevant header file).

Raw buffers (for input and output) are always `uint8_t*` types.
When the length of a buffer is unknown (in most cases, the buffer structure
is statically known), the length is given by a `uint32_t`.

## Cryptographically-secure Random Numbers

Many of the functions provided by this library (particularly, those used by an Issuer or a Member)
require a source of cryptographically-secure random numbers.

**The security of this library depends critically on these random numbers**.

Such functions take a parameter of type `ecdaa_rand_func`,
which is a function pointer for a function that will fill a buffer with a given
number of random bytes.
The expectation is that this function will use the system's source of randomness
(e.g. `getrandom` on Linux, `getentropy` on OpenBSD, `arc4random` on Mac OS X,
`RtlGenRandom` on Windows, or reading from `/dev/urandom` when these others aren't available).
Note that a `ecdaa_rand_func` will never be called with a request larger than 255 bytes
(so functions like `getrandom` and `getentropy` that have such a limit are OK to use).
Examples of such usage can be found in the implementation of the example programs,
in `examples/examples_rand.c`.

The easiest way to satisfy the requirements of the `ecdaa_rand_func` on systems supported by
the libsodium library is to use
the libsodium function `randombytes_buf`.

## Code Examples

In these examples, `ZZZ` is a placeholder for the pairing-friendly curve,
and `rand_func` is an instance of `ecdaa_rand_func` (see above).

### Creating a New DAA Group

When acting as the Issuer, define a new DAA Group by
creating a new Issuer public/secret key pair
(the public/secret key pair is used for adding new members to the group
during the Join process, and the public key also contains the group public key).

```bash
<Issuer>
struct ecdaa_issuer_public_key_ZZZ ipk;
struct ecdaa_issuer_secret_key_ZZZ isk;
ecdaa_issuer_key_pair_ZZZ_generate(&ipk, &isk, rand_func));
```

### Join Process

A Member starts the Join process to be granted membership in the DAA group.

The Join process begins with the Member requesting a nonce and issuer public key from the Issuer.
This process is outside the scope of this project.

Once the Member obtains a nonce and issuer public key from the Issuer, the Member
first extracts the group public key from the issuer public key.

```bash
<Member>
struct ecdaa_issuer_public_key_ZZZ ipk;
... read the issuer's serialized public key into input_buffer ...
ret = ecdaa_issuer_public_key_ZZZ_deserialize(&ipk, input_buffer);
... if ret is non-zero, issuer's key is malformed or invalid ...
```

If the extraction succeeds (indicating the Issuer is honest), the Member saves the
group public key (available in `ipk.gpk`).

Next, the member uses the nonce to
generate its public/secret key-pair
(and a signature proving possession of the secret key).

```bash
<Member>
ecdaa_member_request_join nonce-text pk.bin sk.bin
struct ecdaa_member_public_key_ZZZ pk;
struct ecdaa_member_secret_key_ZZZ sk;
ecdaa_member_key_pair_ZZZ_generate(&pk, &sk, nonce, nonce_length, rand_func);
```

The Member sends its public key (along with the signature generated alongside it)
to the Issuer,
who then uses it (along with its secret key and the nonce
it originally gave to this Member) to
check the validity of the Member's
public key.

```bash
<Issuer>
struct ecdaa_member_public_key_ZZZ pk;
... read the members's serialized public key (and signature) into input_buffer ...
ret = ecdaa_member_public_key_ZZZ_deserialize(&pk, input_buffer, nonce, nonce_len);
... if ret is non-zero, member's key is malformed or invalid ...
```

The Issuer now generates a DAA credential and credential-signature,
which the Issuer sends back to the Member.

```bash
<Issuer>
... retrieve issuer secret key into isk ...
struct ecdaa_credential_ZZZ cred;
struct ecdaa_credential_ZZZ_signature cred_sig;
ecdaa_credential_ZZZ_generate(&cred, &cred_sig, &isk, &pk, rand_func);
```

Once it gets the credential (and signature) from the Issuer,
the Member uses the credential and credential-signature
(along with its own public key and the group public key that it extracted earlier)
to check the validity of the Issuer's credential-signature.

```bash
<Member>
... retrieve member's public key into pk ...
... retrieve group public key into gpk ...
... read the credential into cred_buffer and the credential-signature into sig_buffer ...
ret = ecdaa_credential_ZZZ_deserialize_with_signature(&cred, &pk, &gpk, cred_buffer, sig_buffer)
... if ret is non-zero, the credential can't be trusted ...
```

If the credential-signature check succeeds, the Member saves the credential
along with its secret key (its public key is no longer needed).
The credential and the member's secret key will be used to create DAA signatures.

### Signing and Verifying

Any Verifier wishing to verfiy DAA signatures for a DAA group
first obtains the issuer public key for this group, from the pertinent Issuer.
The Verifier then extracts the group public key from this issuer public key,
as described in the previous section.
If the extraction succeeds (indicating the Issuer was honest),
the Verifier saves the group public key for all later verifications.

Verifiers also maintain a secret key revocation list, which lists
DAA secret keys that are known to have been compromised.
The issuer may be involved in communicating this list to
all verifiers.
This process is outside the scope of this project.

Also outside the scope of this project,
the Verifiers and Members decide whether to use
pseudonym linking ("basename signatures").
Pseudonyms allow a specific Verifier (identified by a basename)
to link separate signatures from the same Member.
Without pseudonym-linking, every signature (no matter from whom)
is cryptographically un-linkable to any other signature.
Pseudonym-linking also allows a Verifier to revoke a Member
based only on their signature (i.e. without having knowledge
of their secret key, as required with a secret key revocation).
It's up to the specific use-case whether or not pseudonyms
should be used.

A member creates a DAA signature over a message
by passing its secret key and its credential,
along with the message to be signed and the basename
(if pseudonym linking is required by the Verifier),
to the `ecdaa_signature_ZZZ_sign` function.
This outputs a DAA signature, which the Member
sends (along with some indication of the DAA group
it is claiming) to a Verifier.

```bash
... retrieve member secret into sk ...
... retrieve credential into cred ...
struct ecdaa_signature_FP256BN sig;
ecdaa_signature_ZZZ_sign(&sig, message, msg_len, basename, basename_len, &sk, &cred, rand_func);
```

The Verifier looks up the group public key (extracted earlier)
and the basename (if using pseudonym linking)
for the DAA group claimed by the Signer.
It passes this group public key and the secret key (and potentially pseudonym) revocation list(s) for this DAA group,
along with the message and signature,
to the `ecdaa_verify` command.

```bash
... read the member's signature into sig ...
... retrieve the claimed group public into gpk ...
... retrieve the necessary basename string into basename ...
struct ecdaa_revocations_FP256BN revocations;
... retrieve any secret key revocations into revocations.sk_list ...
... retrieve any pseudonym ("basename") revocations into revocations.bsn_list ...
ecdaa_signature_ZZZ_verify(&sig, &gpk, &revocations, message, msg_len, basename, basename_len);
```

If the signature is valid, this function returns `0`.

## Example Programs

The `examples` directory contains fully-functional example code for using the library
(without TPM support),
where for simplicity communication between the Issuer, Member, and Verifier
is done using regular files.

The example programs use the FP256BN curve type.

NOTE: If using these example programs on a system where `/dev/urandom` is the only
option for cryptographically-secure random numbers
(cf. `/examples/ecdaa_examples_randomness.c`),
the proper seeding of `/dev/urandom`
(i.e. the amount of entropy available) is not checked!
Thus, in such situations, these programs are not safe to use in situations
where the system random number generator may not be seeded
(e.g. early in the boot process on some systems).
The example programs must be carefully adapted for use in such situations.

## Using a TPM

Signatures can be created with the help of a Trusted Platform Module (TPM),
if hardware-based security of the member's credentials is required.

To use the TPM-enabled functionality,
include the top-level header `ecdaa-tpm.h`,
and the name of the library is `libecdaa-tpm`;
these must be used *in addition* to the regular `ecdaa` header and library
described above.

This implementation has been tested against the following TCG TPM2.0 specifications:
- Specification v1.38
- Specification v1.16 with Errata v1.5

A signing key must first be created and loaded in the TPM.
This key must be created with the following properties
(consult the [TPM documentation](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
or a [TPM TSS implementation](https://github.com/tpm2-software/tpm2-tss)
for an explanation of how to create an asymmetric signing key):
- `sign` attribute must be set
- `restricted` attribute must NOT be set
- `userWithAuth` attribute must be set
  - The authorization must be a (possibly empty) password
- `scheme = TPM_ALG_ECDAA`
- `hashAlg = TPM_ALG_SHA256`
- `curveID = TPM_ECC_BN_P256`

For this library to communicate with the TPM,
 an `ecdaa_tpm_context` object must be created.
Here, 
```
struct ecdaa_tpm_context tpm_context;
TSS2_TCTI_CONTEXT tcti_context;
... initialize the TCTI_CONTEXT, as explained by your TSS implementation ...
ecdaa_tpm_context_init(&tpm_context, key_handle, password, password_length, &tcti_context);
```
where `key_handle` is the TPM handle of
the TPM signing key, and `password` is the TPM authorization associated with that key.
NOTE: Once this `ecdaa_tpm_context` is no longer needed,
it must be freed using `ecdaa_tpm_context_free`.

The DAA "join" process proceeds as usual (i.e. as when not using a TPM), with the
change that `ecdaa_member_key_pair_TPM_FP256BN_generate` must be used in place of
`ecdaa_member_key_pair_FP256BN_generate`.

An ECDAA signature using this TPM-generated secret key is then created using:
```
struct ecdaa_signature_TPM_FP256BN signature;
ecdaa_signature_TPM_FP256BN_sign(&signature, msg, msg_length, basename, basename_length, &credential, &prng, &tpm_context);
```
where `credential`, `prng`, and `basename` are as when not using a TPM.

Notice that verification of a TPM-generated signature proceeds as usual, using `ecdaa_signature_FP256BN_verify`.

