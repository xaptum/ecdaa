# ecdaa

A C implementation of elliptic-curve-based Direct Anonymous Attestation signatures.

# Project Status

[![Build Status](https://travis-ci.org/xaptum/ecdaa.svg?branch=master)](https://travis-ci.org/xaptum/ecdaa)
[![codecov](https://codecov.io/gh/xaptum/ecdaa/branch/master/graph/badge.svg)](https://codecov.io/gh/xaptum/ecdaa)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/13775/badge.svg)](https://scan.coverity.com/projects/xaptum-ecdaa)

# Requirements

- The CMake build system is used for building.
- gcc
- For building the AMCL dependency:
  - python3

# Building

```bash
git submodule update --init --recursive
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build . -- -j4
```

# Running the tests

```bash
cd build
ctest -V
```

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

## Testing and Analysis

The unit-tests are contained in the `test` directory.
Test code coverage is measured using `gcov`, and monitored via `codecov`.

### Valgrind

The Valgrind tool `memcheck` is used for heap memory checking.
Every build on `travis-ci` runs this test.

To run a `memcheck` test, do the following:

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo
# (benchmarks are excluded because they take too long under the Valgrind instrumentation)
ctest -VV -E benchmark -T memcheck
```

### Scan-build

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

### cppcheck

The `cppcheck` static analyzer is also available, and is run every build on `travis-ci`.
To run it do the following:

```bash
cppcheck -v --std=c99 --error-exitcode=6 include/ src/ test/
```

This tool is generally considered to have a lower false-positive rate than
many other static analyzers, though with that comes a potential loss of strictness.

TODO: Once we have tests that actually use all the defined functions, we should
use `enable=all` in `cppcheck`.

### Address and Undefined Behavior Sanitizers

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

### Coverity

Coverity static analysis is run after any push to the `coverity_scan` branch.
Coverity is a static analyzer provided by Synopsys, and the reports
for this project can be found by clicking the Coverity link at the top of this README.

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
