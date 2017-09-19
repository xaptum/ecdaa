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

#include "../src/internal/schnorr.h"

#include "../src/amcl-extensions/big_256_56.h"
#include "../src/amcl-extensions/ecp_BN254.h"
#include "../src/amcl-extensions/ecp2_BN254.h"

#include <ecdaa/credential_BN254.h>
#include <ecdaa/prng.h>

#include <amcl/big_256_56.h>
#include <amcl/ecp_BN254.h>

#include <string.h>

static void schnorr_keygen_sane();
static void schnorr_sign_sane();
static void schnorr_verify_wrong_key();
static void schnorr_verify_wrong_msg();
static void schnorr_verify_bad_sig();
static void schnorr_sign_integration();
static void schnorr_sign_integration_other_basepoint();
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
    schnorr_credential_sign_sane();
    schnorr_credential_sign_integration();
    schnorr_issuer_sign_sane();
    schnorr_issuer_sign_integration();
}

void schnorr_keygen_sane()
{
    printf("Starting schnorr::schnorr_keygen_sane...\n");

    ECP_BN254 public_one, public_two;
    BIG_256_56 private_one, private_two;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen(&public_one, &private_one, &prng);
    schnorr_keygen(&public_two, &private_two, &prng);

    TEST_ASSERT(0 != BIG_256_56_comp(private_one, private_two));
    TEST_ASSERT(1 != ECP_BN254_equals(&public_one, &public_two));

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

    ECP_BN254 public;
    BIG_256_56 private;

    big_256_56_random_mod_order(&private, get_csprng(&prng));
    ecp_BN254_set_to_generator(&public);

    ECP_BN254_mul(&public, private);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    ecp_BN254_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &prng));

    TEST_ASSERT(0 == BIG_256_56_iszilch(c));
    TEST_ASSERT(0 == BIG_256_56_iszilch(s));
    TEST_ASSERT(0 == BIG_256_56_isunity(c));
    TEST_ASSERT(0 == BIG_256_56_isunity(s));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_verify_wrong_key()
{
    printf("Starting schnorr::schnorr_verify_wrong_key...\n");

    ECP_BN254 public, public_wrong;
    BIG_256_56 private, private_wrong;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen(&public, &private, &prng);
    schnorr_keygen(&public_wrong, &private_wrong, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    ecp_BN254_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &prng));

    TEST_ASSERT(-1 == schnorr_verify(c, s, msg, msg_len, &basepoint, &public_wrong));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_verify_wrong_msg()
{
    printf("Starting schnorr::schnorr_verify_wrong_msg...\n");

    ECP_BN254 public;
    BIG_256_56 private;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen(&public, &private, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);
    uint8_t *msg_wrong = (uint8_t*) "Wrong message";
    uint32_t msg_len_wrong = strlen((char*)msg_wrong);

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    ecp_BN254_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &prng));

    TEST_ASSERT(-1 == schnorr_verify(c, s, msg_wrong, msg_len_wrong, &basepoint, &public));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_verify_bad_sig()
{
    printf("Starting schnorr::schnorr_verify_bad_sig...\n");

    ECP_BN254 public;
    BIG_256_56 private;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen(&public, &private, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c={314,0}, s={2718,0};   // Just set these to random values

    ECP_BN254 basepoint;
    ecp_BN254_set_to_generator(&basepoint);
    TEST_ASSERT(-1 == schnorr_verify(c, s, msg, msg_len, &basepoint, &public));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_sign_integration()
{
    printf("Starting schnorr::schnorr_sign_integration...\n");

    ECP_BN254 public;
    BIG_256_56 private;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen(&public, &private, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    ecp_BN254_set_to_generator(&basepoint);
    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &prng));

    TEST_ASSERT(0 == schnorr_verify(c, s, msg, msg_len, &basepoint, &public));

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

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    ecp_BN254_set_to_generator(&basepoint);
    BIG_256_56 rand;
    big_256_56_random_mod_order(&rand, get_csprng(&prng));
    ECP_BN254_mul(&basepoint, rand);

    ECP_BN254 public;
    BIG_256_56 private;
    big_256_56_random_mod_order(&private, get_csprng(&prng));
    ECP_BN254_copy(&public, &basepoint);
    ECP_BN254_mul(&public, private);

    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &prng));

    TEST_ASSERT(0 == schnorr_verify(c, s, msg, msg_len, &basepoint, &public));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_credential_sign_sane()
{
    printf("Starting schnorr::schnorr_credential_sign_sane...\n");

    ECP_BN254 member_public;
    BIG_256_56 member_private;
    BIG_256_56 issuer_private;

    ECP_BN254 B, D;
    ecp_BN254_set_to_generator(&B);
    ecp_BN254_set_to_generator(&D);

    BIG_256_56 credential_random;

    BIG_256_56 c, s;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    big_256_56_random_mod_order(&credential_random, get_csprng(&prng));

    big_256_56_random_mod_order(&member_private, get_csprng(&prng));
    big_256_56_random_mod_order(&issuer_private, get_csprng(&prng));
    ecp_BN254_set_to_generator(&member_public);
    ECP_BN254_mul(&member_public, member_private);

    TEST_ASSERT(0 == credential_schnorr_sign(&c, &s, &B, &member_public, &D, issuer_private, credential_random, &prng));

    TEST_ASSERT(0 == BIG_256_56_iszilch(c));
    TEST_ASSERT(0 == BIG_256_56_iszilch(s));
    TEST_ASSERT(0 == BIG_256_56_isunity(c));
    TEST_ASSERT(0 == BIG_256_56_isunity(s));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_credential_sign_integration()
{
    printf("Starting schnorr::schnorr_credential_sign_integration...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    BIG_256_56 member_private = {2718, 0};
    ECP_BN254 member_public;
    ecp_BN254_set_to_generator(&member_public);
    ECP_BN254_mul(&member_public, member_private);

    BIG_256_56 issuer_private_key_y = {2718, 0};

    BIG_256_56 credential_random = {314, 2718, 0};

    ECP_BN254 B;
    ecp_BN254_set_to_generator(&B);
    ECP_BN254_mul(&B, credential_random);
    ECP_BN254_mul(&B, issuer_private_key_y);

    ECP_BN254 D;
    ECP_BN254_copy(&D, &member_public);
    ECP_BN254_mul(&D, credential_random);
    ECP_BN254_mul(&D, issuer_private_key_y);

    BIG_256_56 c, s;

    TEST_ASSERT(0 == credential_schnorr_sign(&c, &s, &B, &member_public, &D, issuer_private_key_y, credential_random, &prng));

    TEST_ASSERT(0 == credential_schnorr_verify(c, s, &B, &member_public, &D));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_issuer_sign_sane()
{
    printf("Starting schnorr::schnorr_issuer_sign_sane...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    BIG_256_56 issuer_private_x;
    big_256_56_random_mod_order(&issuer_private_x, get_csprng(&prng));
    BIG_256_56 issuer_private_y;
    big_256_56_random_mod_order(&issuer_private_y, get_csprng(&prng));
    ECP2_BN254 issuer_public_X;
    ECP2_BN254 issuer_public_Y;
    ecp2_BN254_set_to_generator(&issuer_public_X);
    ecp2_BN254_set_to_generator(&issuer_public_Y);
    ECP2_BN254_mul(&issuer_public_X, issuer_private_x);
    ECP2_BN254_mul(&issuer_public_Y, issuer_private_y);

    BIG_256_56 c, sx, sy;

    TEST_ASSERT(0 == issuer_schnorr_sign(&c, &sx, &sy, &issuer_public_X, &issuer_public_Y, issuer_private_x, issuer_private_y, &prng));

    TEST_ASSERT(0 == BIG_256_56_iszilch(c));
    TEST_ASSERT(0 == BIG_256_56_iszilch(sx));
    TEST_ASSERT(0 == BIG_256_56_iszilch(sy));
    TEST_ASSERT(0 == BIG_256_56_isunity(c));
    TEST_ASSERT(0 == BIG_256_56_isunity(sx));
    TEST_ASSERT(0 == BIG_256_56_isunity(sy));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}

void schnorr_issuer_sign_integration()
{
    printf("Starting schnorr::schnorr_issuer_sign_integration...\n");

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    BIG_256_56 issuer_private_x;
    big_256_56_random_mod_order(&issuer_private_x, get_csprng(&prng));
    ECP2_BN254 issuer_public_X;
    ecp2_BN254_set_to_generator(&issuer_public_X);
    ECP2_BN254_mul(&issuer_public_X, issuer_private_x);

    BIG_256_56 issuer_private_y;
    big_256_56_random_mod_order(&issuer_private_y, get_csprng(&prng));
    ECP2_BN254 issuer_public_Y;
    ecp2_BN254_set_to_generator(&issuer_public_Y);
    ECP2_BN254_mul(&issuer_public_Y, issuer_private_y);

    BIG_256_56 c, sx, sy;

    TEST_ASSERT(0 == issuer_schnorr_sign(&c, &sx, &sy, &issuer_public_X, &issuer_public_Y, issuer_private_x, issuer_private_y, &prng));

    TEST_ASSERT(0 == issuer_schnorr_verify(c, sx, sy, &issuer_public_X, &issuer_public_Y));

    ecdaa_prng_free(&prng);

    printf("\tsuccess\n");
}
