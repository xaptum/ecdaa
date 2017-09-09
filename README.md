# xaptum-ecdaa

Xaptum, Inc.'s implementation of elliptic-curve-based Direct Anonymous Attestation signatures.

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
