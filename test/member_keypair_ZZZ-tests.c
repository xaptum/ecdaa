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

#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/big_XXX.h"

#include <ecdaa/member_keypair_ZZZ.h>

static void member_secret_is_valid();
static void member_public_is_valid();
static void generated_validates();
static void zero_nonce_ok();
static void lengths_same();
static void serialize_deserialize_secret();
static void serialize_deserialize_public_no_check();
static void serialize_deserialize_public();
static void serialize_deserialize_secret_file();
static void serialize_deserialize_public_no_check_file();
static void serialize_deserialize_public_file();
static void serialize_deserialize_secret_fp();
static void serialize_deserialize_public_no_check_fp();
static void serialize_deserialize_public_fp();

int main()
{
    member_secret_is_valid();
    member_public_is_valid();
    zero_nonce_ok();
    lengths_same();
    generated_validates();
    serialize_deserialize_secret();
    serialize_deserialize_public_no_check();
    serialize_deserialize_public();
    serialize_deserialize_secret_file();
    serialize_deserialize_public_no_check_file();
    serialize_deserialize_public_file();
    serialize_deserialize_secret_fp();
    serialize_deserialize_public_no_check_fp();
    serialize_deserialize_public_fp();
}

void member_secret_is_valid()
{
    printf("Starting member_keypair::member_secret_is_valid...\n");

    struct ecdaa_member_secret_key_ZZZ sk1;
    struct ecdaa_member_public_key_ZZZ pk1;
    uint8_t nonce[32] = {0};

    TEST_ASSERT(0 == ecdaa_member_key_pair_ZZZ_generate(&pk1, &sk1, nonce, sizeof(nonce), test_randomness));

    TEST_ASSERT(0 == ECP_ZZZ_isinf(&pk1.Q));

    struct ecdaa_member_secret_key_ZZZ sk2;
    struct ecdaa_member_public_key_ZZZ pk2;
    TEST_ASSERT(0 == ecdaa_member_key_pair_ZZZ_generate(&pk2, &sk2, nonce, sizeof(nonce), test_randomness));

    TEST_ASSERT(BIG_XXX_comp(sk1.sk, sk2.sk) != 0);

    printf("\tsuccess\n");
}

void member_public_is_valid()
{
    printf("Starting member_keypair::member_public_is_valid...\n");

    struct ecdaa_member_secret_key_ZZZ sk;
    struct ecdaa_member_public_key_ZZZ pk;
    uint8_t nonce[32] = {0};
    TEST_ASSERT(0 == ecdaa_member_key_pair_ZZZ_generate(&pk, &sk, nonce, sizeof(nonce), test_randomness));

    ECP_ZZZ verify_pub;
    ecp_ZZZ_set_to_generator(&verify_pub);
    ECP_ZZZ_mul(&verify_pub, sk.sk);

    TEST_ASSERT(ECP_ZZZ_equals(&verify_pub, &pk.Q));

    printf("\tsuccess\n");
}

static void generated_validates()
{
    printf("Starting member_keypair::generated_validates...\n");

    struct ecdaa_member_secret_key_ZZZ sk;
    struct ecdaa_member_public_key_ZZZ pk;
    uint8_t nonce[32] = {0};
    TEST_ASSERT(0 == ecdaa_member_key_pair_ZZZ_generate(&pk, &sk, nonce, sizeof(nonce), test_randomness));

    TEST_ASSERT(0 == ecdaa_member_public_key_ZZZ_validate(&pk, nonce, sizeof(nonce)));

    // Test with bad nonces
    TEST_ASSERT(0 != ecdaa_member_public_key_ZZZ_validate(&pk, NULL, 0));
    uint8_t different_nonce[3] = {0x1, 0x2, 0x3};
    TEST_ASSERT(0 != ecdaa_member_public_key_ZZZ_validate(&pk, different_nonce, sizeof(different_nonce)));

    printf("\tsuccess\n");
}

static void zero_nonce_ok()
{
    printf("Starting member_keypair::zero_nonce_ok...\n");

    struct ecdaa_member_secret_key_ZZZ sk;
    struct ecdaa_member_public_key_ZZZ pk;
    TEST_ASSERT(0 == ecdaa_member_key_pair_ZZZ_generate(&pk, &sk, NULL, 0, test_randomness));

    printf("\tsuccess\n");
}

static void lengths_same()
{
    printf("Starting member_keypair::lengths_same...\n");

    TEST_ASSERT(ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH == ecdaa_member_public_key_ZZZ_length());

    TEST_ASSERT(ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH == ecdaa_member_secret_key_ZZZ_length());

    printf("\tsuccess\n");
}

static void serialize_deserialize_secret()
{
    printf("Starting member_keypair::serialize_deserialize_secret...\n");

    struct ecdaa_member_secret_key_ZZZ sk;
    ecp_ZZZ_random_mod_order(&sk.sk, test_randomness);

    uint8_t buffer[ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH];
    ecdaa_member_secret_key_ZZZ_serialize(buffer, &sk);

    struct ecdaa_member_secret_key_ZZZ sk_deserialized;
    TEST_ASSERT(0 == ecdaa_member_secret_key_ZZZ_deserialize(&sk_deserialized, buffer));

    printf("\tsuccess\n");
}

static void serialize_deserialize_public_no_check()
{
    printf("Starting member_keypair::serialize_deserialize_public_no_check...\n");

    BIG_XXX sk;
    ecp_ZZZ_random_mod_order(&sk, test_randomness);

    struct ecdaa_member_public_key_ZZZ pk;
    ecp_ZZZ_set_to_generator(&pk.Q);
    ECP_ZZZ_mul(&pk.Q, sk);
    BIG_XXX_zero(pk.c);
    BIG_XXX_zero(pk.s);
    BIG_XXX_zero(pk.n);

    uint8_t buffer[ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH];
    ecdaa_member_public_key_ZZZ_serialize(buffer, &pk);

    struct ecdaa_member_public_key_ZZZ pk_deserialized;
    TEST_ASSERT(0 == ecdaa_member_public_key_ZZZ_deserialize_no_check(&pk_deserialized, buffer));

    printf("\tsuccess\n");
}

static void serialize_deserialize_public()
{
    printf("Starting member_keypair::serialize_deserialize_public_no_check...\n");

    struct ecdaa_member_secret_key_ZZZ sk;
    struct ecdaa_member_public_key_ZZZ pk;
    uint8_t nonce[32] = {0};

    TEST_ASSERT(0 == ecdaa_member_key_pair_ZZZ_generate(&pk, &sk, nonce, sizeof(nonce), test_randomness));

    uint8_t buffer[ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH];
    ecdaa_member_public_key_ZZZ_serialize(buffer, &pk);

    struct ecdaa_member_public_key_ZZZ pk_deserialized;
    TEST_ASSERT(0 == ecdaa_member_public_key_ZZZ_deserialize(&pk_deserialized, buffer, nonce, sizeof(nonce)));

    printf("\tsuccess\n");
}

static void serialize_deserialize_secret_file()
{
    printf("Starting member_keypair::serialize_deserialize_secret_file...\n");

    const char *sk_file = "sk.bin";

    struct ecdaa_member_secret_key_ZZZ sk;
    ecp_ZZZ_random_mod_order(&sk.sk, test_randomness);

    TEST_ASSERT(0 == ecdaa_member_secret_key_ZZZ_serialize_file(sk_file, &sk));

    struct ecdaa_member_secret_key_ZZZ sk_deserialized;
    TEST_ASSERT(0 == ecdaa_member_secret_key_ZZZ_deserialize_file(&sk_deserialized, sk_file));

    printf("\tsuccess\n");
}

static void serialize_deserialize_public_no_check_file()
{
    printf("Starting member_keypair::serialize_deserialize_public_no_check_file...\n");

    const char *pk_file = "pk.bin";

    BIG_XXX sk;
    ecp_ZZZ_random_mod_order(&sk, test_randomness);

    struct ecdaa_member_public_key_ZZZ pk;
    ecp_ZZZ_set_to_generator(&pk.Q);
    ECP_ZZZ_mul(&pk.Q, sk);
    BIG_XXX_zero(pk.c);
    BIG_XXX_zero(pk.s);
    BIG_XXX_zero(pk.n);

    TEST_ASSERT(0 == ecdaa_member_public_key_ZZZ_serialize_file(pk_file, &pk));

    struct ecdaa_member_public_key_ZZZ pk_deserialized;
    TEST_ASSERT(0 == ecdaa_member_public_key_ZZZ_deserialize_no_check_file(&pk_deserialized, pk_file));

    printf("\tsuccess\n");
}

static void serialize_deserialize_public_file()
{
    printf("Starting member_keypair::serialize_deserialize_public_no_check_file...\n");

    const char *pk_file = "pk.bin";

    struct ecdaa_member_secret_key_ZZZ sk;
    struct ecdaa_member_public_key_ZZZ pk;
    uint8_t nonce[32] = {0};

    TEST_ASSERT(0 == ecdaa_member_key_pair_ZZZ_generate(&pk, &sk, nonce, sizeof(nonce), test_randomness));

    ecdaa_member_public_key_ZZZ_serialize_file(pk_file, &pk);

    struct ecdaa_member_public_key_ZZZ pk_deserialized;
    TEST_ASSERT(0 == ecdaa_member_public_key_ZZZ_deserialize_file(&pk_deserialized, pk_file, nonce, sizeof(nonce)));

    printf("\tsuccess\n");
}

static void serialize_deserialize_secret_fp()
{
    printf("Starting member_keypair::serialize_deserialize_secret_fp...\n");

    const char *sk_file = "sk.bin";

    struct ecdaa_member_secret_key_ZZZ sk;
    ecp_ZZZ_random_mod_order(&sk.sk, test_randomness);

    FILE *sk_fp = fopen(sk_file, "wb");
    TEST_ASSERT(NULL != sk_fp);
    TEST_ASSERT(0 == ecdaa_member_secret_key_ZZZ_serialize_fp(sk_fp, &sk));
    fclose(sk_fp);

    sk_fp = fopen(sk_file, "rb");
    TEST_ASSERT(NULL != sk_fp);
    struct ecdaa_member_secret_key_ZZZ sk_deserialized;
    TEST_ASSERT(0 == ecdaa_member_secret_key_ZZZ_deserialize_fp(&sk_deserialized, sk_fp));
    fclose(sk_fp);

    printf("\tsuccess\n");
}

static void serialize_deserialize_public_no_check_fp()
{
    printf("Starting member_keypair::serialize_deserialize_public_no_check_fp...\n");

    const char *pk_file = "pk.bin";

    BIG_XXX sk;
    ecp_ZZZ_random_mod_order(&sk, test_randomness);

    struct ecdaa_member_public_key_ZZZ pk;
    ecp_ZZZ_set_to_generator(&pk.Q);
    ECP_ZZZ_mul(&pk.Q, sk);
    BIG_XXX_zero(pk.c);
    BIG_XXX_zero(pk.s);
    BIG_XXX_zero(pk.n);

    FILE *pk_fp = fopen(pk_file, "wb");
    TEST_ASSERT(NULL != pk_fp);
    TEST_ASSERT(0 == ecdaa_member_public_key_ZZZ_serialize_fp(pk_fp, &pk));
    fclose(pk_fp);

    pk_fp = fopen(pk_file, "rb"); TEST_ASSERT(NULL != pk_fp);
    struct ecdaa_member_public_key_ZZZ pk_deserialized;
    TEST_ASSERT(0 == ecdaa_member_public_key_ZZZ_deserialize_no_check_fp(&pk_deserialized, pk_fp));
    fclose(pk_fp);

    printf("\tsuccess\n");
}

static void serialize_deserialize_public_fp()
{
    printf("Starting member_keypair::serialize_deserialize_public_no_check_fp...\n");

    const char *pk_file = "pk.bin";

    struct ecdaa_member_secret_key_ZZZ sk;
    struct ecdaa_member_public_key_ZZZ pk;
    uint8_t nonce[32] = {0};

    TEST_ASSERT(0 == ecdaa_member_key_pair_ZZZ_generate(&pk, &sk, nonce, sizeof(nonce), test_randomness));

    FILE *pk_fp = fopen(pk_file, "wb");
    TEST_ASSERT(NULL != pk_fp);
    ecdaa_member_public_key_ZZZ_serialize_fp(pk_fp, &pk);
    fclose(pk_fp);

    pk_fp = fopen(pk_file, "rb");
    TEST_ASSERT(NULL != pk_fp);
    struct ecdaa_member_public_key_ZZZ pk_deserialized;
    TEST_ASSERT(0 == ecdaa_member_public_key_ZZZ_deserialize_fp(&pk_deserialized, pk_fp, nonce, sizeof(nonce)));
    fclose(pk_fp);

    printf("\tsuccess\n");
}
