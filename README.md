# ecdaa

A C implementation of elliptic-curve-based Direct Anonymous Attestation signatures.

# Project Status

[![Build Status](https://travis-ci.org/xaptum/ecdaa.svg?branch=master)](https://travis-ci.org/xaptum/ecdaa)

[![codecov](https://codecov.io/gh/xaptum/ecdaa/branch/master/graph/badge.svg)](https://codecov.io/gh/xaptum/ecdaa)

# Requirements

- The CMake build system is used for building.
- For building the AMCL dependency:
  - python3
  - gcc

# Building

`git submodule update --init --recursive`

`mkdir -p build`

`cd build`

`cmake .. -DCMAKE_BUILD_TYPE=Debug`

`cmake --build . -- -j4`

# Running the tests

`cd build`

`ctest -V`

## Testing and Analysis

The unit-tests are contained in the `test` directory.
Test code coverage is measured using `gcov`, and monitored via `codecov`.

### Valgrind

The Valgrind `memcheck` tool can be run on a `CMAKE_BUILD_TYPE=RelWithDebInfo` build,
by using the following command
(benchmarks are excluded because they take too long under the Valgrind instrumentation):

`ctest -E benchmarks -T memcheck`

The following options are passed to the `memcheck` executable:
- `--track-origins=yes` Track the origin of uninitialized values (small Valgrind performance hit)
- `--partial-loads-ok=no` Loads from partially invalid addresses are treated the same as loads from completely invalid addresses
- `--leak-check=full` Search for memory leaks after program completion, and give a full report for each individually.
  - As we're striving for "malloc-free" code, we expect to have zero memory leaks
- `-v` Verbose `memcheck` output
- `--error-exitcode=5` A memory error causes a return code of 5, so memory errors will fail the tests.

In general, the `memcheck` checks are expected to alert us of any accidental memory access issues
(using un-initialized values, accessing beyond the stack pointer, bad pointers to `memcpy`-like functions).
By running randomized tests under `memcheck`, we hope to also discover places where
a malicious user could access unauthorized memory, too.

# Usage

## Random number generator

Many of the functions provided by this library (particularly, those used by an Issuer or a Member)
require a pointer to a pseudo-random number generator (type `csprng`).
The security of these algorithms depends critically on the proper seeding of this prng.

Before using these functions, create and seed the `csprng`:

```c
#include <amcl/amcl.h>
#include <amcl/randapi.h>
csprng rng;
char seed[SEED_LEN];
/* Get cryptographically-secure random bytes of length SEED_LEN into seed */
octet seed_as_octet = {.len=SEED_LEN, .max=SEED_LEN, .val=seed};
CREATE_CSPRNG(rng, &seed_as_octet);
```

The random seed `seed` MUST be generated in a cryptographically-secure manner,
and should be at least 128 bytes long.
Depending on the platform, this seed can be generated, for example, via calls to
`/dev/urandom` (or `getrandom()`), or a hardware random number generator.

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

## Join Process

## Signing and Verifying

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
