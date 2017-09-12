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

#include "./big_256_56.h"
#include "../internal/explicit_bzero.h"

#include <amcl/ecp_BN254.h>

#include <assert.h>

static void convert_hash_to_big(BIG_256_56 *big_out, hash256 *hash);

void big_256_56_from_hash(BIG_256_56 *big_out,
                          const uint8_t *msg_in,
                          uint32_t msg_len)
{
    hash256 hash;
    HASH256_init(&hash);

    // Process input one-byte-at-a-time.
    for (uint32_t i=0; i < msg_len; ++i) {
        HASH256_process(&hash, msg_in[i]);
    }

    convert_hash_to_big(big_out, &hash);
}

void big_256_56_from_two_message_hash(BIG_256_56 *big_out,
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

    convert_hash_to_big(big_out, &hash);
}

void big_256_56_mod_mul_and_add(BIG_256_56 *big_out,
                                BIG_256_56 summand,
                                BIG_256_56 multiplicand1,
                                BIG_256_56 multiplicand2,
                                BIG_256_56 modulus)
{
    // Implicitly mod's (and thus normalizes) both inputs, as well as output.
    BIG_256_56_modmul(*big_out, multiplicand1, multiplicand2, modulus);

    // I don't know that this is strictly necessary before the call to add.
    // However, without it 'summand' would be the only input that doesn't get normalized.
    // So, at least for consistency in side-effects, let's do it.
    BIG_256_56_norm(summand);

    // Output not normalized.
    BIG_256_56_add(*big_out, summand, *big_out);

    // Output, of course, normalized.
    BIG_256_56_mod(*big_out, modulus);
}

void big_256_56_random_mod_order(BIG_256_56 *big_out,
                                 csprng *rng)
{
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);

    BIG_256_56_randomnum(*big_out, curve_order, rng);
}

static void convert_hash_to_big(BIG_256_56 *big_out, hash256 *hash)
{
    char hash_as_bytes[32] = {0};
    assert(hash->hlen == sizeof(hash_as_bytes));

    // Clears the hash object after output.
    HASH256_hash(hash, hash_as_bytes);

    // Convert byte-string to un-normalized BIG.
    BIG_256_56_fromBytesLen(*big_out, hash_as_bytes, hash->hlen);

    explicit_bzero(hash_as_bytes, sizeof(hash_as_bytes));
}
