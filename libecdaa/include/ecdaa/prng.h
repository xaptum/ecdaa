/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#ifndef ECDAA_PRNG_H
#define ECDAA_PRNG_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/randapi.h>

#include <stddef.h>

#define AMCL_SEED_SIZE 128  // As recommended in AMCL's "rand.c"

enum ecdaa_prng_initialized {
    ECDAA_PRNG_INITIALIZED_NO = 0,
    ECDAA_PRNG_INITIALIZED_YES
};

/*
 * Wrapper around AMCL's pseudo-random-number-generator.
 *
 * For the safe operation of this library,
 * all `ecdaa_prng`s MUST first be properly seeded
 * via a call to `ecdaa_prng_init`
 * or `ecdaa_prng_init_custom` before first use.
 */
struct ecdaa_prng {
    enum ecdaa_prng_initialized initialized;
    csprng impl;
};

/*
 * Accessor for the underlying AMCL csprng in a `ecdaa_prng`.
 *
 * Checks that `ecdaa_prng` was initialized before returning.
 * If not, calls `abort()`.
 */
csprng *get_csprng(struct ecdaa_prng *prng);

/*
 * Securely-clears memory used by a `ecdaa_prng`.
 *
 * To be used when finished with a `ecdaa_prng`.
 *
 * Does not do any heap deallocation.
 */
void ecdaa_prng_free(struct ecdaa_prng *prng);

#ifndef DISABLE_LIBSODIUM_RNG_SEED_FUNCTION

/*
 * Properly seeds a `ecdaa_prng`.
 *
 * MUST be called on a `ecdaa_prng` before first use.
 *
 * No dynamic memory allocation is performed.
 *
 * Uses Libsodium's `randombytes_buf` as the source of
 * a cryptographically-strong random seed.
 * Requires the CMake option `DISABLE_LIBSODIUM_RNG_SEED_FUNCTION=OFF`.
 *
 * Returns:
 * 0 on success
 * -1 if unable to obtain seed
 * -2 if entropy is insufficient
 */
int ecdaa_prng_init(struct ecdaa_prng *prng_in);

#endif  // DISABLE_LIBSODIUM_RNG_SEED_FUNCTION

/*
 * Properly seed a `ecdaa_prng`, with a custom cryptographically-strong random seed.
 *
 * MUST be called on a `ecdaa_prng` before first use,
 * unless using `ecdaa_prng_init` instead.
 *
 * No dynamic memory allocation is performed.
 *
 * `seed_size` MUST be at least AMCL_SEED_SIZE.
 *
 * Returns:
 * 0 on success
 * -1 if seed_size < AMCL_SEED_SIZE
 */
int ecdaa_prng_init_custom(struct ecdaa_prng *prng_in, char *seed, size_t seed_size);

#ifdef __cplusplus
}
#endif

#endif

