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

#include "./big_XXX.h"
#include "internal-utilities/explicit_bzero.h"

#include <amcl/ecp_ZZZ.h>
#include <amcl/amcl.h>

#include <assert.h>

static void convert_hash_to_big_XXX(BIG_XXX *big_out, hash256 *hash);

void big_XXX_from_hash(BIG_XXX *big_out,
                       const uint8_t *msg_in,
                       uint32_t msg_len)
{
    hash256 hash;
    HASH256_init(&hash);

    // Process input one-byte-at-a-time.
    for (uint32_t i=0; i < msg_len; ++i) {
        HASH256_process(&hash, msg_in[i]);
    }

    convert_hash_to_big_XXX(big_out, &hash);
}

void big_XXX_from_two_message_hash(BIG_XXX *big_out,
                                   const uint8_t *msg1_in,
                                   uint32_t msg1_len,
                                   const uint8_t *msg2_in,
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

    convert_hash_to_big_XXX(big_out, &hash);
}

void big_XXX_from_three_message_hash(BIG_XXX *big_out,
                                     const uint8_t *msg1_in,
                                     uint32_t msg1_len,
                                     const uint8_t *msg2_in,
                                     uint32_t msg2_len,
                                     const uint8_t *msg3_in,
                                     uint32_t msg3_len)
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

    // Process msg3 one-byte-at-a-time.
    for (uint32_t i=0; i < msg3_len; ++i) {
        HASH256_process(&hash, msg3_in[i]);
    }

    convert_hash_to_big_XXX(big_out, &hash);
}

void big_XXX_mod_mul_and_add(BIG_XXX *big_out,
                             BIG_XXX summand,
                             BIG_XXX multiplicand1,
                             BIG_XXX multiplicand2,
                             BIG_XXX modulus)
{
    // Implicitly mod's (and thus normalizes) both inputs, as well as output.
    BIG_XXX_modmul(*big_out, multiplicand1, multiplicand2, modulus);

    // I don't know that this is strictly necessary before the call to add.
    // However, without it 'summand' would be the only input that doesn't get normalized.
    // So, at least for consistency in side-effects, let's do it.
    BIG_XXX_norm(summand);

    // Output not normalized.
    BIG_XXX_add(*big_out, summand, *big_out);

    // Output, of course, normalized.
    BIG_XXX_mod(*big_out, modulus);
}

static void convert_hash_to_big_XXX(BIG_XXX *big_out, hash256 *hash)
{
    char hash_as_bytes[32] = {0};
    assert(hash->hlen == sizeof(hash_as_bytes));

    // Clears the hash object after output.
    HASH256_hash(hash, hash_as_bytes);

    // Convert byte-string to un-normalized BIG.
    BIG_XXX_fromBytesLen(*big_out, hash_as_bytes, hash->hlen);

    explicit_bzero(hash_as_bytes, sizeof(hash_as_bytes));
}
