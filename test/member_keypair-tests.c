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

#include "xaptum-test-utils.h"

#include "../src/pairing_curve_utils.h"

#include <ecdaa/member_keypair.h>
#include <ecdaa/issuer_nonce.h>

#include <amcl/randapi.h>

static void member_secret_is_valid();
static void member_public_is_valid();
static void member_proof_checks();

int main()
{
    member_secret_is_valid();
    member_proof_checks();
    member_public_is_valid();
}

void member_secret_is_valid()
{
    printf("Starting context::member_secret_is_valid...\n");

    struct ecdaa_member_secret_key sk1;
    struct ecdaa_member_public_key pk1;
    ecdaa_issuer_nonce_t nonce = {{0}};

    csprng rng;
    create_test_rng(&rng);

    ecdaa_generate_member_key_pair(&pk1, &sk1, &nonce, &rng);

    destroy_test_rng(&rng);

    TEST_ASSERT(!pk1.Q.inf);

    struct ecdaa_member_secret_key sk2;
    struct ecdaa_member_public_key pk2;
    ecdaa_generate_member_key_pair(&pk2, &sk2, &nonce, &rng);

    TEST_ASSERT(BIG_256_56_comp(sk1.sk, sk2.sk) != 0);

    printf("\tsuccess\n");
}

void member_public_is_valid()
{
    printf("Starting context::member_public_is_valid...\n");

    csprng rng;
    create_test_rng(&rng);

    struct ecdaa_member_secret_key sk;
    struct ecdaa_member_public_key pk;
    ecdaa_issuer_nonce_t nonce = {{0}};
    ecdaa_generate_member_key_pair(&pk, &sk, &nonce, &rng);

    TEST_ASSERT(0 == check_point_membership(&pk.Q));

    printf("\tsuccess\n");
}

void member_proof_checks()
{
    // TODO: Check signature (c, s) in member's key
}
