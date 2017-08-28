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

#include "mpi_utils.h"

#include <assert.h>

static void explicit_bzero(void *const pnt, const size_t len);

static void convert_hash_to_mpi(BIG_256_56 *mpi_out, hash256 *hash);

void hash_into_mpi(BIG_256_56 *mpi_out, uint8_t *msg_in, uint32_t msg_len)
{
    hash256 hash;
    HASH256_init(&hash);

    // Process input one-byte-at-a-time.
    for (uint32_t i=0; i < msg_len; ++i) {
        HASH256_process(&hash, msg_in[i]);
    }

    convert_hash_to_mpi(mpi_out, &hash);
}

void hash_into_mpi_two(BIG_256_56 *mpi_out,
                       uint8_t *msg1_in,
                       uint32_t msg1_len,
                       uint8_t *msg2_in,
                       uint32_t msg2_len)
{
    hash256 hash;
    HASH256_init(&hash);

    // Process msg1 one-byte-at-a-time.
    for (uint32_t i=0; i < msg1_len; ++i) {
        HASH256_process(&hash, msg1_in[i]);
    }

    // Process msg2 one-byte-at-a-time.
    for (uint32_t i=0; i < msg2_len; ++i) {
        HASH256_process(&hash, msg2_in[i]);
    }

    convert_hash_to_mpi(mpi_out, &hash);
}

void mpi_mod_mul_and_add(BIG_256_56 *mpi_out,
                         BIG_256_56 summand,
                         BIG_256_56 multiplicand1,
                         BIG_256_56 multiplicand2,
                         BIG_256_56 modulus)
{
    // Implicitly mod's (and thus normalizes) both inputs, as well as output.
    BIG_256_56_modmul(*mpi_out, multiplicand1, multiplicand2, modulus);

    // I don't know that this is strictly necessary before the call to add.
    // However, without it 'summand' would be the only input that doesn't get normalized.
    // So, at least for consistency in side-effects, let's do it.
    BIG_256_56_norm(summand);

    // Output not normalized.
    BIG_256_56_add(*mpi_out, summand, *mpi_out);

    // Output, of course, normalized.
    BIG_256_56_mod(*mpi_out, modulus);
}

static void explicit_bzero(void *const pnt, const size_t len)
{
    // TODO: Figure out how well this works, and portable solutions.
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;

    size_t i = (size_t) 0U;
    while (i < len) {
        pnt_[i++] = 0U;
    }
}

static void convert_hash_to_mpi(BIG_256_56 *mpi_out, hash256 *hash)
{
    char hash_as_bytes[32] = {0};
    assert(hash->hlen == sizeof(hash_as_bytes));

    // Clears the hash object after output.
    HASH256_hash(hash, hash_as_bytes);

    // Convert byte-string to un-normalized MPI.
    BIG_256_56_fromBytesLen(*mpi_out, hash_as_bytes, hash->hlen);

    explicit_bzero(hash_as_bytes, sizeof(hash_as_bytes));
}
