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

#include "ecdaa-test-utils.h"

#include <ecdaa/prng.h>

#include <amcl/amcl.h>

static void different_rngs_are_different();
static void deterministic_seed_makes_same_rngs();

int main()
{
    different_rngs_are_different();
    deterministic_seed_makes_same_rngs();
}

static void different_rngs_are_different()
{
    struct ecdaa_prng rng1, rng2;
    TEST_ASSERT(0 == ecdaa_prng_init(&rng1));
    TEST_ASSERT(0 == ecdaa_prng_init(&rng2));

    int bytes1[5];
    int bytes2[5];
    for (int i = 0; i < 5; i++) {
        bytes1[i] = RAND_byte(&rng1.impl);
        bytes2[i] = RAND_byte(&rng2.impl);
    }
    TEST_ASSERT(bytes1[0] != bytes2[0]
                || bytes1[1] != bytes2[1]
                || bytes1[2] != bytes2[2]
                || bytes1[3] != bytes2[3]
                || bytes1[4] != bytes2[4]
                );

    ecdaa_prng_free(&rng1);
    ecdaa_prng_free(&rng2);
}

static void deterministic_seed_makes_same_rngs()
{
    struct ecdaa_prng rng1, rng2;
    char seed[AMCL_SEED_SIZE];
    for (size_t i = 0; i < sizeof(seed); i++)
        seed[i] = 5;
    ecdaa_prng_init_custom(&rng1, seed, sizeof(seed));
    ecdaa_prng_init_custom(&rng2, seed, sizeof(seed));

    int bytes1[5];
    int bytes2[5];
    for (int i = 0; i < 5; i++) {
        bytes1[i] = RAND_byte(&rng1.impl);
        bytes2[i] = RAND_byte(&rng2.impl);
    }
    TEST_ASSERT(bytes1[0] == bytes2[0]
                && bytes1[1] == bytes2[1]
                && bytes1[2] == bytes2[2]
                && bytes1[3] == bytes2[3]
                && bytes1[4] == bytes2[4]
                );

    ecdaa_prng_free(&rng1);
    ecdaa_prng_free(&rng2);
}
