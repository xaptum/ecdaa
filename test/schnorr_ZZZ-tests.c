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

#include "schnorr/schnorr_ZZZ.h"

#include "amcl-extensions/big_XXX.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"

#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/prng.h>

#include <amcl/big_XXX.h>
#include <amcl/ecp_ZZZ.h>

#include <string.h>

static void schnorr_keygen_sane();
static void schnorr_sign_sane();
static void schnorr_verify_wrong_key();
static void schnorr_verify_wrong_msg();
static void schnorr_verify_bad_sig();
static void schnorr_sign_integration();
static void schnorr_sign_integration_other_basepoint();
static void schnorr_basename();
static void schnorr_wrong_basename_fails();
static void schnorr_credential_sign_sane();
static void schnorr_credential_sign_integration();
static void schnorr_issuer_sign_sane();
static void schnorr_issuer_sign_integration();

int main()
{
    schnorr_keygen_sane();
    schnorr_sign_sane();
    schnorr_verify_wrong_key();
    schnorr_verify_wrong_msg();
    schnorr_verify_bad_sig();
    schnorr_sign_integration();
    schnorr_sign_integration_other_basepoint();
    schnorr_basename();
    schnorr_wrong_basename_fails();
    schnorr_credential_sign_sane();
    schnorr_credential_sign_integration();
    schnorr_issuer_sign_sane();
    schnorr_issuer_sign_integration();
}

void schnorr_keygen_sane()
{
    printf("Starting schnorr::schnorr_keygen_sane...\n");

    ECP_ZZZ public_one, public_two;
    BIG_XXX private_one, private_two;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen_ZZZ(&public_one, &private_one, &prng);
    schnorr_keygen_ZZZ(&public_two, &private_two, &prng);

    TEST_ASSERT(0 != BIG_XXX_comp(private_one, private_two));
    TEST_ASSERT(1 != ECP_ZZZ_equals(&public_one, &public_two));

    TEST_ASSERT(!public_one.inf);
    TEST_ASSERT(!public_two.inf);

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_sign_sane()
{
    printf("Starting schnorr::schnorr_sign_sane...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    ECP_ZZZ public;
    BIG_XXX private;

    ecp_ZZZ_random_mod_order(&private, get_csprng(&prng));
    ecp_ZZZ_set_to_generator(&public);

    ECP_ZZZ_mul(&public, private);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_XXX c, s;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign_ZZZ(&c, &s, NULL, msg, msg_len, &basepoint, &public, private, NULL, 0, &prng));

    TEST_ASSERT(0 == BIG_XXX_iszilch(c));
    TEST_ASSERT(0 == BIG_XXX_iszilch(s));
    TEST_ASSERT(0 == BIG_XXX_isunity(c));
    TEST_ASSERT(0 == BIG_XXX_isunity(s));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_verify_wrong_key()
{
    printf("Starting schnorr::schnorr_verify_wrong_key...\n");

    ECP_ZZZ public, public_wrong;
    BIG_XXX private, private_wrong;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen_ZZZ(&public, &private, &prng);
    schnorr_keygen_ZZZ(&public_wrong, &private_wrong, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_XXX c, s;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign_ZZZ(&c, &s, NULL, msg, msg_len, &basepoint, &public, private, NULL, 0, &prng));

    TEST_ASSERT(-1 == schnorr_verify_ZZZ(c, s, NULL, msg, msg_len, &basepoint, &public_wrong, NULL, 0));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_verify_wrong_msg()
{
    printf("Starting schnorr::schnorr_verify_wrong_msg...\n");

    ECP_ZZZ public;
    BIG_XXX private;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen_ZZZ(&public, &private, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);
    uint8_t *msg_wrong = (uint8_t*) "Wrong message";
    uint32_t msg_len_wrong = strlen((char*)msg_wrong);

    BIG_XXX c, s;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign_ZZZ(&c, &s, NULL, msg, msg_len, &basepoint, &public, private, NULL, 0, &prng));

    TEST_ASSERT(-1 == schnorr_verify_ZZZ(c, s, NULL, msg_wrong, msg_len_wrong, &basepoint, &public, NULL, 0));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_verify_bad_sig()
{
    printf("Starting schnorr::schnorr_verify_bad_sig...\n");

    ECP_ZZZ public;
    BIG_XXX private;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen_ZZZ(&public, &private, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_XXX c={314,0}, s={2718,0};   // Just set these to random values

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    TEST_ASSERT(-1 == schnorr_verify_ZZZ(c, s, NULL, msg, msg_len, &basepoint, &public, NULL, 0));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_sign_integration()
{
    printf("Starting schnorr::schnorr_sign_integration...\n");

    ECP_ZZZ public;
    BIG_XXX private;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen_ZZZ(&public, &private, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_XXX c, s;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign_ZZZ(&c, &s, NULL, msg, msg_len, &basepoint, &public, private, NULL, 0, &prng));

    TEST_ASSERT(0 == schnorr_verify_ZZZ(c, s, NULL, msg, msg_len, &basepoint, &public, NULL, 0));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_sign_integration_other_basepoint()
{
    printf("Starting schnorr::schnorr_sign_integration_other_points...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_XXX c, s;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    BIG_XXX rand;
    ecp_ZZZ_random_mod_order(&rand, get_csprng(&prng));
    ECP_ZZZ_mul(&basepoint, rand);

    ECP_ZZZ public;
    BIG_XXX private;
    ecp_ZZZ_random_mod_order(&private, get_csprng(&prng));
    ECP_ZZZ_copy(&public, &basepoint);
    ECP_ZZZ_mul(&public, private);

    TEST_ASSERT(0 == schnorr_sign_ZZZ(&c, &s, NULL, msg, msg_len, &basepoint, &public, private, NULL, 0, &prng));

    TEST_ASSERT(0 == schnorr_verify_ZZZ(c, s, NULL, msg, msg_len, &basepoint, &public, NULL, 0));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

static void schnorr_basename()
{
    printf("Starting schnorr::schnorr_basename...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    ECP_ZZZ public;
    BIG_XXX private;

    schnorr_keygen_ZZZ(&public, &private, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    uint8_t *basename = (uint8_t*) "BASENAME";
    uint32_t basename_len = strlen((char*)basename);

    BIG_XXX c, s;
    ECP_ZZZ K;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign_ZZZ(&c, &s, &K, msg, msg_len, &basepoint, &public, private, basename, basename_len, &prng));

    TEST_ASSERT(0 == schnorr_verify_ZZZ(c, s, &K, msg, msg_len, &basepoint, &public, basename, basename_len));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

static void schnorr_wrong_basename_fails()
{
    printf("Starting schnorr::schnorr_wrong_basename_fails...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    ECP_ZZZ public;
    BIG_XXX private;

    schnorr_keygen_ZZZ(&public, &private, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    uint8_t *basename = (uint8_t*) "BASENAME";
    uint32_t basename_len = strlen((char*)basename);
    uint8_t *wrong_basename = (uint8_t*) "WRONGBASENAME";
    uint32_t wrong_basename_len = strlen((char*)wrong_basename);

    BIG_XXX c, s;
    ECP_ZZZ K;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign_ZZZ(&c, &s, &K, msg, msg_len, &basepoint, &public, private, basename, basename_len, &prng));

    TEST_ASSERT(0 != schnorr_verify_ZZZ(c, s, &K, msg, msg_len, &basepoint, &public, wrong_basename, wrong_basename_len));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_credential_sign_sane()
{
    printf("Starting schnorr::schnorr_credential_sign_sane...\n");

    ECP_ZZZ member_public;
    BIG_XXX member_private;
    BIG_XXX issuer_private;

    ECP_ZZZ B, D;
    ecp_ZZZ_set_to_generator(&B);
    ecp_ZZZ_set_to_generator(&D);

    BIG_XXX credential_random;

    BIG_XXX c, s;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    ecp_ZZZ_random_mod_order(&credential_random, get_csprng(&prng));

    ecp_ZZZ_random_mod_order(&member_private, get_csprng(&prng));
    ecp_ZZZ_random_mod_order(&issuer_private, get_csprng(&prng));
    ecp_ZZZ_set_to_generator(&member_public);
    ECP_ZZZ_mul(&member_public, member_private);

    TEST_ASSERT(0 == credential_schnorr_sign_ZZZ(&c, &s, &B, &member_public, &D, issuer_private, credential_random, &prng));

    TEST_ASSERT(0 == BIG_XXX_iszilch(c));
    TEST_ASSERT(0 == BIG_XXX_iszilch(s));
    TEST_ASSERT(0 == BIG_XXX_isunity(c));
    TEST_ASSERT(0 == BIG_XXX_isunity(s));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_credential_sign_integration()
{
    printf("Starting schnorr::schnorr_credential_sign_integration...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    BIG_XXX member_private = {2718, 0};
    ECP_ZZZ member_public;
    ecp_ZZZ_set_to_generator(&member_public);
    ECP_ZZZ_mul(&member_public, member_private);

    BIG_XXX issuer_private_key_y = {2718, 0};

    BIG_XXX credential_random = {314, 2718, 0};

    ECP_ZZZ B;
    ecp_ZZZ_set_to_generator(&B);
    ECP_ZZZ_mul(&B, credential_random);
    ECP_ZZZ_mul(&B, issuer_private_key_y);

    ECP_ZZZ D;
    ECP_ZZZ_copy(&D, &member_public);
    ECP_ZZZ_mul(&D, credential_random);
    ECP_ZZZ_mul(&D, issuer_private_key_y);

    BIG_XXX c, s;

    TEST_ASSERT(0 == credential_schnorr_sign_ZZZ(&c, &s, &B, &member_public, &D, issuer_private_key_y, credential_random, &prng));

    TEST_ASSERT(0 == credential_schnorr_verify_ZZZ(c, s, &B, &member_public, &D));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_issuer_sign_sane()
{
    printf("Starting schnorr::schnorr_issuer_sign_sane...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    BIG_XXX issuer_private_x;
    ecp_ZZZ_random_mod_order(&issuer_private_x, get_csprng(&prng));
    BIG_XXX issuer_private_y;
    ecp_ZZZ_random_mod_order(&issuer_private_y, get_csprng(&prng));
    ECP2_ZZZ issuer_public_X;
    ECP2_ZZZ issuer_public_Y;
    ecp2_ZZZ_set_to_generator(&issuer_public_X);
    ecp2_ZZZ_set_to_generator(&issuer_public_Y);
    ECP2_ZZZ_mul(&issuer_public_X, issuer_private_x);
    ECP2_ZZZ_mul(&issuer_public_Y, issuer_private_y);

    BIG_XXX c, sx, sy;

    TEST_ASSERT(0 == issuer_schnorr_sign_ZZZ(&c, &sx, &sy, &issuer_public_X, &issuer_public_Y, issuer_private_x, issuer_private_y, &prng));

    TEST_ASSERT(0 == BIG_XXX_iszilch(c));
    TEST_ASSERT(0 == BIG_XXX_iszilch(sx));
    TEST_ASSERT(0 == BIG_XXX_iszilch(sy));
    TEST_ASSERT(0 == BIG_XXX_isunity(c));
    TEST_ASSERT(0 == BIG_XXX_isunity(sx));
    TEST_ASSERT(0 == BIG_XXX_isunity(sy));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_issuer_sign_integration()
{
    printf("Starting schnorr::schnorr_issuer_sign_integration...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    BIG_XXX issuer_private_x;
    ecp_ZZZ_random_mod_order(&issuer_private_x, get_csprng(&prng));
    ECP2_ZZZ issuer_public_X;
    ecp2_ZZZ_set_to_generator(&issuer_public_X);
    ECP2_ZZZ_mul(&issuer_public_X, issuer_private_x);

    BIG_XXX issuer_private_y;
    ecp_ZZZ_random_mod_order(&issuer_private_y, get_csprng(&prng));
    ECP2_ZZZ issuer_public_Y;
    ecp2_ZZZ_set_to_generator(&issuer_public_Y);
    ECP2_ZZZ_mul(&issuer_public_Y, issuer_private_y);

    BIG_XXX c, sx, sy;

    TEST_ASSERT(0 == issuer_schnorr_sign_ZZZ(&c, &sx, &sy, &issuer_public_X, &issuer_public_Y, issuer_private_x, issuer_private_y, &prng));

    TEST_ASSERT(0 == issuer_schnorr_verify_ZZZ(c, sx, sy, &issuer_public_X, &issuer_public_Y));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

