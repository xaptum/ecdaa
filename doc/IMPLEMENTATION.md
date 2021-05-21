# Details of the ECDAA Algorithm Used

The signature algorithm is that of
[Camenisch et al., 2016](https://doi.org/10.1007/978-3-662-49387-8_10),
with two exceptions:
- The "fix by Xi et al." discussed in Section 5.2 is NOT used
when creating TPM-enabled signatures (the current TPM2.0 specification doesn't allow
such signatures to be created).
- During signing, a random nonce is included in the message hash, as discussed in
section 5.2.2 of [Camenisch et al., 2017](https://eprint.iacr.org/2017/639).

This implementation is also compatible with Version 1.1 Release Draft of the
[FIDO ECDAA](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-ecdaa-algorithm-v1.1-id-20170202.html)
specification, with the following exception:
- TPM-based signatures in this implementation do *not* use the `TPM2_Certify` function
  - Instead, this implementation uses `TPM2_sign` and thus is generic,
    in the sense that it can be used to sign
    *any* message, not just a TPM-generated public key.
