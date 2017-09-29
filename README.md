# ecdaa

A C implementation of elliptic-curve-based Direct Anonymous Attestation signatures.

The project is self-contained, and provides all DAA functionality for Issuers, Members, and Verifiers.

# Project Status

[![Build Status](https://travis-ci.org/xaptum/ecdaa.svg?branch=master)](https://travis-ci.org/xaptum/ecdaa)
[![Coverage Status](https://coveralls.io/repos/github/xaptum/ecdaa/badge.svg?branch=master)](https://coveralls.io/github/xaptum/ecdaa?branch=master)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/13775/badge.svg)](https://scan.coverity.com/projects/xaptum-ecdaa)

# Requirements

- The CMake build system is used for building.
- gcc
- libsodium >= 1.0.11 (optionally, see below)
- For building the AMCL dependency:
  - python3

# Building

```bash
git submodule update --init --recursive
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DECDAA_CURVES=BN254\;BN254CX\;BLS383
cmake --build . -- -j4
```

## Running the tests

```bash
cd build
ctest -V
```

# Usage

The only header that has to be included is `ecdaa.h`.
The name of the library is `libecdaa`.

A CMake file for "finding" this library is included to ease
the work of including this project.
To use this file, add the `contrib` directory to the `CMAKE_MODULE_PATH`
and call `find_package(ECDAA)`.
After that, to use `libecdaa`, just add `ecdaa` to the `target_link_libraries`.

The pairing-friendly curves supported by the library are set using the CMake
variable `ECDAA_CURVES`.
The current options are `BN254`, `BN254CX`, and `BLS383`;
so, to enable all three, pass the following command line parameter when invoking `cmake`:
`-DECDAA_CURVES=BN254\;BN254CX\;BLS383`.
If no `ECDAA_CURVES` is set, the default is to build all three curves: `BN254`, `BN254CX`, and `BLS383`.

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

The example programs use the BN254 curve type.

These programs are built by default, though this can be disabled
by setting the CMake option `ECDAA_BUILD_EXAMPLE_PROGRAMS=OFF`.
The examples require Libsodium, and by default the binaries are placed
in the `${CMAKE_BINARY_DIR}/bin` directory.

### Creating a New DAA Group

When acting as the Issuer, run the `issuer_create_group` command
to define a new DAA Group.
This creates a new Issuer public/secret key pair
(the public/secret key pair is used for adding new members to the group
during the Join process, and the public key also contains the group public key).

```bash
issuer_create_group ipk.bin isk.bin
```

### Join Process

A Member starts the Join process to be granted membership in the DAA group.

The Join process begins with the Member requesting a nonce issuer public key from the Issuer.
This process is outside the scope of this project.

Once the Member obtains a nonce and issuer public key from the Issuer, the Member
first extracts the group public key from the issuer public key.
If the extraction succeeds (indicating the Issuer is honest), the Member saves the
group public key.

```bash
extract_group_public_key ipk.bin gpk.bin
```

Next, the member passes the nonce to the `member_request_join` command to
generate its public/secret key-pair.

```bash
member_request_join nonce-text pk.bin sk.bin
```

The Member sends its public key to the Issuer,
who then passes it (along with its secret key and the nonce
it originally gave to this Member) to the
`issuer_respond_to_join_request` command.
This command checks the validity of the Member's
public key and generates a DAA credential and credential-signature,
which the Issuer sends back to the Member.

```bash
issuer_respond_to_join_request pk.bin isk.bin cred.bin cred_sig.bin nonce-text
```

The member passes the credential and credential-signature
(along with its public key, and the group group public key that it extracted earlier)
to the `member_process_join_response` command.
This command checks the validity of the Issuer's credential-signature.

```bash
member_process_join_response pk.bin gpk.bin cred.bin cred_sig.bin
```

If the credential-signature check succeeds, the Member saves the credential
along with its secret key (its public key is no longer needed).
The credential and the member's secret key will be used to create DAA signatures.

### Signing and Verifying

Any party wishing to verfiy DAA signatures for a DAA group
first obtains the issuer public key for this group, from the pertinent Issuer.
The verifier then extracts the group public key from this issuer public key.
If the extraction succeeds (indicating the Issuer was honest),
the verifier saves the group public key for all later verifications.

Verifiers also maintain a secret key revocation list, which lists
DAA secret keys that are known to have been compromised.
The issuer may be involved in communicating this list to
all verifiers.
This process is outside the scope of this project.

A member creates a DAA signature over a message
by passing its secret key and its credential,
along with the message to be signed,
to the `member_sign` command.
This command outputs a DAA signature, which the Member
sends (along with some indication of the DAA group
it is claiming) to a Verifier.

```bash
member_sign sk.bin cred.bin sig.bin message-text
```

The Verifier looks up the group public key (extracted earlier)
for the DAA group claimed by the Signer.
It passes this group public key and the secret key revocation list for this DAA group,
along with the message and signature,
to the `verify` command.
If the signature is valid, this command returns success.

```bash
verify message-text sig.bin gpk.bin sk_revocation_list.bin num-sks-in-sk_revocation_list
```

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
cppcheck -v --std=c99 --error-exitcode=6 include/ src/ test/
```

This tool is generally considered to have a lower false-positive rate than
many other static analyzers, though with that comes a potential loss of strictness.

TODO: Once we have tests that actually use all the defined functions, we should
use `enable=all` in `cppcheck`.

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
uses Miracl's AMCL library version3.
AMCL is available on github [here](https://github.com/miracl/amcl).

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
