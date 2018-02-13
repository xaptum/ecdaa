# ecdaa

A C implementation of elliptic-curve-based Direct Anonymous Attestation signatures.

The project is self-contained, and provides all DAA functionality for Issuers, Members, and Verifiers.
Pseudonym linking ("basename signatures") is optional, and secret-key revocation lists can be used.

# Project Status

[![Build Status](https://travis-ci.org/xaptum/ecdaa.svg?branch=master)](https://travis-ci.org/xaptum/ecdaa)
[![Coverage Status](https://coveralls.io/repos/github/xaptum/ecdaa/badge.svg?branch=master)](https://coveralls.io/github/xaptum/ecdaa?branch=master)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/13775/badge.svg)](https://scan.coverity.com/projects/xaptum-ecdaa)

# Requirements

- cmake version >= 3.0
  - The milagro-crypto-c dependency requires CMake v3.1, so local-building of milagro requires a higher version of CMake
- python3
  - For file generation during building
- A C99-compliant compiler
- milagro-crypto-c
  - The milagro library must be built with support for the necessary curves
  - Currently, the fork available [here](https://github.com/zanebeckwith/milagro-crypto-c/tree/headers-under-directory) must be used
- libsodium >= 1.0.11 (optionally, see below)
- xaptum-tpm >= 0.3.0
  - If building with TPM support

## Milagro-Crypto-C Dependency

By default, `cmake` will look for the `milagro-crypto-c` project first 
in the local directory `./milagro-crypto-c/install`, under the directories `include` for headers and `lib` for libraries.
Next, the usual system installation locations will be searched.
To override the local search location, set the `AMCL_LOCAL_DIR` cmake variable to the correct path.
To force only the system installation locations to be used, set the `FORCE_SYSTEM_AMCL_LIB` cmake option to `On`.

## Xaptum-TPM Dependency

If building with TPM support, the `xaptum-tpm` package is required.
By default, cmake will look for the `xaptum-tpm project` first in the local directory
`./xaptum-tpm`, under the directories `include` for headers and `build` for libraries.
Next, the usual system installation locations will be searched.
To override the local search location, set the `XAPTUM_TPM_LOCAL_DIR` cmake variable to the correct path.
To force only the system installation locations to be used, set the FORCE_SYSTEM_XAPTUM_TPM_LIB cmake option to On.

# Building

`ecdaa` uses CMake as its build system:

In the following, it is assumed that libsodium has been installed.

```bash
# Build a local copy of milagro-crypto-c
git clone -b headers-under-directory https://github.com/zanebeckwith/milagro-crypto-c
cd milagro-crypto-c
mkdir -p build
mkdir -p install
cd build
cmake .. -DAMCL_CURVE=FP256BN -DBUILD_SHARED_LIBS=Off -DCMAKE_POSITION_INDEPENDENT_CODE=On -DCMAKE_INSTALL_PREFIX=$(pwd)/../install
cmake --build .
make install
cd ../..

# Build a local copy of xaptum-tpm
git clone https://github.com/xaptum/xaptum-tpm
cd xaptum-tpm
mkdir -p build
cd build
cmake .. -DBUILD_SHARED_LIBS=Off -DCMAKE_POSITION_INDEPENDENT_CODE=On
cmake --build .
cd ../..

# Create a subdirectory to hold the build
mkdir -p build
cd build

# Configure the build
cmake .. -DBUILD_EXAMPLES=ON

# Build the library
cmake --build .
```

In addition to the standard CMake options the following configuration
options and variables are supported.

### Static vs Shared Libary
If `BUILD_SHARED_LIBS` is set, the shared library is built. If
`BUILD_STATIC_LIBS` is set, the static library is built. If both are
set, both libraries will be built.  If neither is set, the static
library will be built.

### Static Library Name
`STATIC_SUFFIX`, if defined, will be appended to the static library
name.  For example,

```bash
cmake .. -DBUILD_STATIC_LIBS=ON -DSTATIC_SUFFIX=_static
cmake --build .
cd ../..

mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DECDAA_CURVES=BN254\;BN254CX\;BLS383\;FP256BN
cmake --build . -- -j4
```

will create a static library named `libecdaa_static.a`.

### Force Position Independent Code (-fPIC)
Set the standard CMake variable `CMAKE_POSITION_INDEPENDENT_CODE` to
`ON` to force compilation with `-fPIC` for static libraries.  The
default is `OFF` for static libraries and `ON` for shared libraries.

### Disable Building of Tests
Set the standard CMake variable `BUILD_TESTING` to `OFF` to disable
the building of tests.  The default value is `ON`.

## Installation

CMake creates a target for installation.

```bash
cd build
cmake --build . --target install
```

Set the `CMAKE_INSTALL_PREFIX` variable when configuring the build to
modify the installation location.

## Running the tests

The tests assume that the `-DBUILD_EXAMPLES=ON` CMake option was used during building.

```bash
cd build
ctest -V
```

### Testing TPM support

If built with TPM support, the tests assume that a TPM2.0 simulator
(for instance, [IBM's simulator](https://sourceforge.net/projects/ibmswtpm2/))
is listening locally on TCP port 2321.
Also, an ECDAA-capable signing key must be loaded in the TPM,
and its public key (in x9.62 format) and TPM handle (as a hex-formatted integer)
must be available in the text files
`build/test/pub_key.txt` and `build/test/handle.txt`, respectively.

# Usage

The only header that has to be included is `ecdaa.h`.
The name of the library is `libecdaa`.

The pairing-friendly curves supported by the library are set using the CMake
variable `ECDAA_CURVES`, a comma-separated list of curve names.
All curves supported by the `milagro-crypto-c` pairing-based-crypto library are supported.
If no `ECDAA_CURVES` is set, the default is to build `FP256BN`.

## Using a TPM

Signatures can be created with the help of a Trusted Platform Module (TPM).

To do so, a signing key must first be created and loaded in the TPM.
This key must be created with the following properties
(consult a TPM TSS for explanation of how to create an asymmetric signing key):
- `sign` attribute must be set
- `restricted` attribute must NOT be set
- `userWithAuth` attribute must be set
  - The authorization must be a (possibly empty) password
- `scheme = TPM_ALG_ECDAA`
- `hashAlg = TPM_ALG_SHA256`
- `curveID = TPM_ECC_BN_P256`

Then, a connection to the TPM is established by, for example, connecting
to a TPM simulator listening locally on TCP port 2321.
This creates an `ecdaa_tpm_context` object as follows:
```
struct ecdaa_tpm_context tpm_context;
ecdaa_tpm_context_init_socket(&tpm_context, &public_key, key_handle, localhost, 2321, password, password_length);
```
where `public_key` and `key_handle` are the public key (as an elliptic curve point) and TPM handle of
the TPM signing key, and `password` is the TPM authorization associated with that key.

An ECDAA signature using this TPM-generated secret key is then created using:
```
struct ecdaa_signature_FP256BN signature;
ecdaa_signature_TPM_sign(&signature, msg, msg_length, &credential, &prng, &tpm_context);
```
where `credential` is an ECDAA credential obtained earlier and `prng` is an `ecdaa_prng`, both created as usual.

Notice that the signature thus created is not TPM-specific.
This means that verification of a TPM-generated signature proceeds as usual, using `ecdaa_signature_FP256BN_verify`.

By default, the library builds with support for using a TPM.
If this isn't desired, set the `cmake` option `ECDAA_TPM_SUPPORT=Off`.

## Random number generator

Many of the functions provided by this library (particularly, those used by an Issuer or a Member)
require a pseudo random number generator (type `ecdaa_prng`).
The security of these algorithms depends critically on the proper seeding of this prng.
This means that the first use of any `ecdaa_prng` MUST be preceeded by a call to
`ecdaa_prng_init` (or `ecdaa_prng_init_custom`, see below) on the prng.

In `ecdaa_prng_init`, the seed for the `ecdaa_prng` is generated from Libsodium's
`randombytes_buf` function.
A discussion on how this function works and any caveats can be found at Libsodium's webpage.

To use a different function for obtaining cryptographically-secure random data for a seed,
pass the option `-DDISABLE_LIBSODIUM_RNG_SEED_FUNCTION=ON` to CMake (this will remove the dependency on libsodium)
and use the function `ecdaa_prng_init_custom` rather than `ecdaa_prng_init`,
passing in a buffer of cryptographically-strong random bytes of length at least `AMCL_SEED_SIZE`.

When an `ecdaa_prng` is no longer needed, `ecdaa_prng_free` should be called on it
to securely erase its sensitive memory.

## Naming Convention in API

All API functions exist in the `ecdaa` namespace,
and are focused on a small number of basic `structs` (e.g. `signature`).
Function names take the form `ecdaa_<struct-name>_<curve-name>_<action>`.
For example, for generating a credential when using the BN254 curve-type, the function
to use is `ecdaa_credential_BN254_generate`.

Output parameters are frequently used in the API functions, and come at the beginning
of the parameter list.

The fundamental structs have (de-)serialization functions,
and macros and functions giving their serialized length.
Again, the format of the serialized length macro/function is
`ecdaa_<struct-name>_<curve-name>_length` (capitalized for the macro).

## Example Programs

The `examples` directory contains example code for using the library,
where for simplicity communication between the Issuer, Member, and Verifier
is done using regular files.

The example programs use the FP256BN curve type.

These programs are not built by default, though they can be enabled
by setting the CMake option `BUILD_EXAMPLES=ON`.
The examples require Libsodium, and by default the binaries are placed
in the `${CMAKE_BINARY_DIR}/bin` directory.

### Creating a New DAA Group

When acting as the Issuer, run the `ecdaa_issuer_create_group` command
to define a new DAA Group.
This creates a new Issuer public/secret key pair
(the public/secret key pair is used for adding new members to the group
during the Join process, and the public key also contains the group public key).

```bash
ecdaa_issuer_create_group ipk.bin isk.bin
```

### Join Process

A Member starts the Join process to be granted membership in the DAA group.

The Join process begins with the Member requesting a nonce and issuer public key from the Issuer.
This process is outside the scope of this project.

Once the Member obtains a nonce and issuer public key from the Issuer, the Member
first extracts the group public key from the issuer public key.
If the extraction succeeds (indicating the Issuer is honest), the Member saves the
group public key.

```bash
ecdaa_extract_group_public_key ipk.bin gpk.bin
```

Next, the member passes the nonce to the `ecdaa_member_request_join` command to
generate its public/secret key-pair.

```bash
ecdaa_member_request_join nonce-text pk.bin sk.bin
```

The Member sends its public key to the Issuer,
who then passes it (along with its secret key and the nonce
it originally gave to this Member) to the
`ecdaa_issuer_respond_to_join_request` command.
This command checks the validity of the Member's
public key and generates a DAA credential and credential-signature,
which the Issuer sends back to the Member.

```bash
ecdaa_issuer_respond_to_join_request pk.bin isk.bin cred.bin cred_sig.bin nonce-text
```

The member passes the credential and credential-signature
(along with its public key, and the group group public key that it extracted earlier)
to the `ecdaa_member_process_join_response` command.
This command checks the validity of the Issuer's credential-signature.

```bash
ecdaa_member_process_join_response pk.bin gpk.bin cred.bin cred_sig.bin
```

If the credential-signature check succeeds, the Member saves the credential
along with its secret key (its public key is no longer needed).
The credential and the member's secret key will be used to create DAA signatures.

### Signing and Verifying

Any party wishing to verfiy DAA signatures for a DAA group
first obtains the issuer public key for this group, from the pertinent Issuer.
The verifier then extracts the group public key from this issuer public key,
as described in the previous section.
If the extraction succeeds (indicating the Issuer was honest),
the verifier saves the group public key for all later verifications.

Verifiers also maintain a secret key revocation list, which lists
DAA secret keys that are known to have been compromised.
The issuer may be involved in communicating this list to
all verifiers.
This process is outside the scope of this project.

A member creates a DAA signature over a message
using a basename (if pseudonym linking is required by the Verifier)
by passing its secret key and its credential,
along with the message to be signed and the basename,
to the `ecdaa_member_sign` command.
This command outputs a DAA signature, which the Member
sends (along with some indication of the DAA group
it is claiming) to a Verifier.

```bash
ecdaa_member_sign sk.bin cred.bin sig.bin message.bin basename.bin
```

The Verifier looks up the group public key (extracted earlier)
and the basename (if using pseudonym linking)
for the DAA group claimed by the Signer.
It passes this group public key and the secret key revocation list for this DAA group,
along with the message and signature,
to the `ecdaa_verify` command.
If the signature is valid, this command returns success.

```bash
ecdaa_verify message.bin sig.bin gpk.bin sk_revocation_list.bin num-sks-in-sk_revocation_list bsn_revocation_list.bin num_bsns-in-bsn_revocation_list basename.bin
```

# Algorithm

The signature algorithm is that of
[Camenisch et al., 2016](https://doi.org/10.1007/978-3-662-49387-8_10),
with the exception that the "fix by Xi et al." discussed in Section 5.2 is NOT used
when creating TPM-enabled signatures (the current TPM2.0 specification doesn't allow
such signatures to be created).

# Testing and Analysis

The unit-tests are contained in the `test` directory.
Test code coverage is measured using `gcov`, and monitored via `coveralls`.

## Valgrind

The Valgrind tool `memcheck` is used for heap memory checking.
Every build on `travis-ci` runs this test.

To run a `memcheck` test, do the following:

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build . -- -j2
# (benchmarks are excluded because they take too long under the Valgrind instrumentation)
ctest -VV -E benchmark -T memcheck
```

## Scan-build

Clang's `scan-build` tool is a general static analyzer, run every build on `travis-ci`.

The `scan-build` tool can be run locally by doing the following:

```bash
mkdir build
cd build
scan-build cmake .. -DCMAKE_BUILD_TYPE=Debug
scan-build --status-bugs cmake --build . -- -j2 #status-bugs means a bug causes a non-zero return code
```

Scan-build has a large number of options for specifying the types of bugs to look for,
so it would be a good idea to study those and tune our usage of this tool.

## cppcheck

The `cppcheck` static analyzer is also available, and is run every build on `travis-ci`.
To run it do the following:

```bash
cppcheck --enable=all -v --std=c99 --error-exitcode=6 include/ src/ test/
```

This tool is generally considered to have a lower false-positive rate than
many other static analyzers, though with that comes a potential loss of strictness.

## Address and Undefined Behavior Sanitizers

Google produced "sanitizer" tools (code instrumenters that check for errors
while running, and thus "dynamically") for checking memory use and
code that may produce undefined behavior.
These sanitizers are now part of both the Clang and GCC compilers.
The address sanitizer and undefined behavior sanitizer
(including the unsigned-int-overflow sanitizer) are run for every build on `travis-ci`.

To run tests using these sanitizers, do the following:

```bash
mkdir build
cmake . -DCMAKE_BUILD_TYPE=RelWithSanitize
cmake --build . -- -j2
# (benchmarks are excluded because they take too long under the sanitizer instrumentation)
ctest -VV -E benchmark
```

## Coverity

Coverity static analysis is run after any push to the `coverity_scan` branch.
Coverity is a static analyzer provided by Synopsys, and the reports
for this project can be found by clicking the Coverity link at the top of this README.

# Pairing-based Cryptography Library

For the elliptic curve bilinear pairing primitives, this project
uses the Milagro Crypto C library.
The fork currently required by this project is available on github [here](https://github.com/zanebeckwith/milagro-crypto-c).
The upstream repository can be found [here](https://github.com/milagro-crypto/milagro-crypto-c).

# License
Copyright 2017 Xaptum, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
