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

#include <ecdaa/issuer_keypair_BN254.h>
#include <ecdaa/prng.h>

static void issuer_secrets_are_valid();
static void issuer_proof_checks();

int main()
{
    issuer_secrets_are_valid();
    issuer_proof_checks();
}

void issuer_secrets_are_valid()
{
    printf("Starting context::issuer_secrets_are_valid...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    struct ecdaa_issuer_secret_key_BN254 sk1;
    struct ecdaa_issuer_public_key_BN254 pk1;
    ecdaa_issuer_key_pair_BN254_generate(&pk1, &sk1, &prng);

    TEST_ASSERT(BIG_256_56_comp(sk1.x, sk1.y) != 0);
    TEST_ASSERT(!pk1.gpk.X.inf);
    TEST_ASSERT(!pk1.gpk.Y.inf);

    struct ecdaa_issuer_secret_key_BN254 sk2;
    struct ecdaa_issuer_public_key_BN254 pk2;
    ecdaa_issuer_key_pair_BN254_generate(&pk2, &sk2, &prng);
    TEST_ASSERT(BIG_256_56_comp(sk1.x, sk2.x) != 0);
    TEST_ASSERT(BIG_256_56_comp(sk1.y, sk2.y) != 0);

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void issuer_proof_checks()
{
    // TODO: Check signature (c, sx, sy) in issuer's key
}

