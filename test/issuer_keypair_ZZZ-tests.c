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

#include <ecdaa/issuer_keypair_ZZZ.h>

static void issuer_secrets_are_valid();
static void generated_validates();
static void lengths_same();
static void generate_then_serialize_deserialize();

int main()
{
    issuer_secrets_are_valid();
    generated_validates();
    lengths_same();
    generate_then_serialize_deserialize();
}

void issuer_secrets_are_valid()
{
    printf("Starting issuer_keypair::issuer_secrets_are_valid...\n");

    struct ecdaa_issuer_secret_key_ZZZ sk1;
    struct ecdaa_issuer_public_key_ZZZ pk1;
    ecdaa_issuer_key_pair_ZZZ_generate(&pk1, &sk1, test_randomness);

    TEST_ASSERT(BIG_XXX_comp(sk1.x, sk1.y) != 0);
    TEST_ASSERT(!pk1.gpk.X.inf);
    TEST_ASSERT(!pk1.gpk.Y.inf);

    struct ecdaa_issuer_secret_key_ZZZ sk2;
    struct ecdaa_issuer_public_key_ZZZ pk2;
    ecdaa_issuer_key_pair_ZZZ_generate(&pk2, &sk2, test_randomness);
    TEST_ASSERT(BIG_XXX_comp(sk1.x, sk2.x) != 0);
    TEST_ASSERT(BIG_XXX_comp(sk1.y, sk2.y) != 0);

    printf("\tsuccess\n");
}

static void generated_validates()
{
    printf("Starting issuer_keypair::generated_validates...\n");

    struct ecdaa_issuer_secret_key_ZZZ isk;
    struct ecdaa_issuer_public_key_ZZZ ipk;
    ecdaa_issuer_key_pair_ZZZ_generate(&ipk, &isk, test_randomness);

    TEST_ASSERT(0 == ecdaa_issuer_public_key_ZZZ_validate(&ipk));

    printf("\tsuccess\n");
}

static void lengths_same()
{
    printf("Starting issuer_keypair::lengths_same...\n");

    TEST_ASSERT(ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH == ecdaa_issuer_public_key_ZZZ_length());

    TEST_ASSERT(ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH == ecdaa_issuer_secret_key_ZZZ_length());

    printf("\tsuccess\n");
}

static void generate_then_serialize_deserialize()
{
    printf("Starting issuer_keypair::generate_then_serialize_deserialize...\n");

    struct ecdaa_issuer_secret_key_ZZZ isk;
    struct ecdaa_issuer_public_key_ZZZ ipk;
    ecdaa_issuer_key_pair_ZZZ_generate(&ipk, &isk, test_randomness);

    uint8_t public_buffer[ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH];
    ecdaa_issuer_public_key_ZZZ_serialize(public_buffer, &ipk);
    struct ecdaa_issuer_public_key_ZZZ ipk_deserialized;
    TEST_ASSERT(0 == ecdaa_issuer_public_key_ZZZ_deserialize(&ipk_deserialized, public_buffer));

    uint8_t secret_buffer[ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH];
    struct ecdaa_issuer_secret_key_ZZZ isk_deserialized;
    ecdaa_issuer_secret_key_ZZZ_serialize(secret_buffer, &isk);
    TEST_ASSERT(0 == ecdaa_issuer_secret_key_ZZZ_deserialize(&isk_deserialized, secret_buffer));

    printf("\tsuccess\n");
}
