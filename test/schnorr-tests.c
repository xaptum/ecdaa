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

#include "../src/schnorr.h"

#include "../src/pairing_curve_utils.h"

#include <ecdaa/credential.h>
#include <ecdaa/issuer_keypair.h>
#include <ecdaa/member_keypair.h>
#include <ecdaa/issuer_nonce.h>

#include <amcl/big_256_56.h>
#include <amcl/ecp_BN254.h>

#include <sys/time.h>

#include <string.h>

static void schnorr_keygen_sane();
static void schnorr_keygen_integration();
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

static void schnorr_sign_benchmark();

int main()
{
    schnorr_keygen_sane();
    schnorr_keygen_integration();
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
    schnorr_sign_benchmark();
}

void schnorr_keygen_sane()
{
    printf("Starting schnorr::schnorr_keygen_sane...\n");

    ECP_BN254 public_one, public_two;
    BIG_256_56 private_one, private_two;

    csprng rng;
    create_test_rng(&rng);

    schnorr_keygen(&public_one, &private_one, &rng);
    schnorr_keygen(&public_two, &private_two, &rng);

    TEST_ASSERT(0 != BIG_256_56_comp(private_one, private_two));
    TEST_ASSERT(1 != ECP_BN254_equals(&public_one, &public_two));

    TEST_ASSERT(!public_one.inf);
    TEST_ASSERT(!public_two.inf);

    destroy_test_rng(&rng);

    printf("\tsuccess\n");
}

void schnorr_keygen_integration()
{
    printf("Starting schnorr::schnorr_keygen_integration...\n");

    ECP_BN254 public;
    BIG_256_56 private;

    csprng rng;
    create_test_rng(&rng);

    schnorr_keygen(&public, &private, &rng);

    char as_bytes[32];
    octet serialized = {.len = 0, .max = sizeof(as_bytes), .val = as_bytes};

    convert_schnorr_public_key_to_bytes(&serialized, &public);

    ECP_BN254 de_serialized;
    TEST_ASSERT(0 == convert_schnorr_public_key_from_bytes(&serialized, &de_serialized));

    TEST_ASSERT(1 == ECP_BN254_equals(&de_serialized, &public));

    destroy_test_rng(&rng);

    printf("\tsuccess\n");
}

void schnorr_sign_sane()
{
    printf("Starting schnorr::schnorr_sign_sane...\n");

    ECP_BN254 public;
    BIG_256_56 private;

    csprng rng;
    create_test_rng(&rng);

    ECP_BN254_mul(&public, private);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    set_to_basepoint(&basepoint);
    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &rng));

    TEST_ASSERT(0 == BIG_256_56_iszilch(c));
    TEST_ASSERT(0 == BIG_256_56_iszilch(s));
    TEST_ASSERT(0 == BIG_256_56_isunity(c));
    TEST_ASSERT(0 == BIG_256_56_isunity(s));

    destroy_test_rng(&rng);

    printf("\tsuccess\n");
}

void schnorr_verify_wrong_key()
{
    printf("Starting schnorr::schnorr_verify_wrong_key...\n");

    ECP_BN254 public, public_wrong;
    BIG_256_56 private, private_wrong;

    csprng rng;
    create_test_rng(&rng);

    schnorr_keygen(&public, &private, &rng);
    schnorr_keygen(&public_wrong, &private_wrong, &rng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    set_to_basepoint(&basepoint);
    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &rng));

    TEST_ASSERT(-1 == schnorr_verify(c, s, msg, msg_len, &basepoint, &public_wrong));

    destroy_test_rng(&rng);

    printf("\tsuccess\n");
}

void schnorr_verify_wrong_msg()
{
    printf("Starting schnorr::schnorr_verify_wrong_msg...\n");

    ECP_BN254 public;
    BIG_256_56 private;

    csprng rng;
    create_test_rng(&rng);

    schnorr_keygen(&public, &private, &rng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);
    uint8_t *msg_wrong = (uint8_t*) "Wrong message";
    uint32_t msg_len_wrong = strlen((char*)msg_wrong);

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    set_to_basepoint(&basepoint);
    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &rng));

    TEST_ASSERT(-1 == schnorr_verify(c, s, msg_wrong, msg_len_wrong, &basepoint, &public));

    destroy_test_rng(&rng);

    printf("\tsuccess\n");
}

void schnorr_verify_bad_sig()
{
    printf("Starting schnorr::schnorr_verify_bad_sig...\n");

    ECP_BN254 public;
    BIG_256_56 private;

    csprng rng;
    create_test_rng(&rng);

    schnorr_keygen(&public, &private, &rng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c={314,0}, s={2718,0};   // Just set these to random values

    ECP_BN254 basepoint;
    set_to_basepoint(&basepoint);
    TEST_ASSERT(-1 == schnorr_verify(c, s, msg, msg_len, &basepoint, &public));

    destroy_test_rng(&rng);

    printf("\tsuccess\n");
}

void schnorr_sign_integration()
{
    printf("Starting schnorr::schnorr_sign_integration...\n");

    ECP_BN254 public;
    BIG_256_56 private;

    csprng rng;
    create_test_rng(&rng);

    schnorr_keygen(&public, &private, &rng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    set_to_basepoint(&basepoint);
    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &rng));

    TEST_ASSERT(0 == schnorr_verify(c, s, msg, msg_len, &basepoint, &public));

    destroy_test_rng(&rng);

    printf("\tsuccess\n");
}

void schnorr_sign_integration_other_basepoint()
{
    printf("Starting schnorr::schnorr_sign_integration_other_points...\n");

    csprng rng;
    create_test_rng(&rng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c, s;

    ECP_BN254 basepoint;
    set_to_basepoint(&basepoint);
    BIG_256_56 rand;
    random_num_mod_order(&rand, &rng);
    ECP_BN254_mul(&basepoint, rand);

    ECP_BN254 public;
    BIG_256_56 private;
    random_num_mod_order(&private, &rng);
    ECP_BN254_copy(&public, &basepoint);
    ECP_BN254_mul(&public, private);

    TEST_ASSERT(0 == schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &rng));

    TEST_ASSERT(0 == schnorr_verify(c, s, msg, msg_len, &basepoint, &public));

    destroy_test_rng(&rng);

    printf("\tsuccess\n");
}

void schnorr_credential_sign_sane()
{
    printf("Starting schnorr::schnorr_credential_sign_sane...\n");

    ECP_BN254 member_public;
    BIG_256_56 member_private;
    BIG_256_56 issuer_private;
    ECP_BN254_mul(&member_public, member_private);

    ECP_BN254 B, D;

    BIG_256_56 credential_random;

    BIG_256_56 c, s;

    csprng rng;
    create_test_rng(&rng);

    TEST_ASSERT(0 == credential_schnorr_sign(&c, &s, &B, &member_public, &D, issuer_private, credential_random, &rng));

    destroy_test_rng(&rng);

    TEST_ASSERT(0 == BIG_256_56_iszilch(c));
    TEST_ASSERT(0 == BIG_256_56_iszilch(s));
    TEST_ASSERT(0 == BIG_256_56_isunity(c));
    TEST_ASSERT(0 == BIG_256_56_isunity(s));

    printf("\tsuccess\n");
}

void schnorr_credential_sign_integration()
{
    printf("Starting schnorr::schnorr_credential_sign_integration...\n");

    csprng rng;
    create_test_rng(&rng);

    BIG_256_56 member_private = {2718, 0};
    ECP_BN254 member_public;
    set_to_basepoint(&member_public);
    ECP_BN254_mul(&member_public, member_private);

    BIG_256_56 issuer_private_key_y = {2718, 0};

    BIG_256_56 credential_random = {314, 2718, 0};

    ECP_BN254 B;
    set_to_basepoint(&B);
    ECP_BN254_mul(&B, credential_random);
    ECP_BN254_mul(&B, issuer_private_key_y);

    ECP_BN254 D;
    ECP_BN254_copy(&D, &member_public);
    ECP_BN254_mul(&D, credential_random);
    ECP_BN254_mul(&D, issuer_private_key_y);

    BIG_256_56 c, s;

    TEST_ASSERT(0 == credential_schnorr_sign(&c, &s, &B, &member_public, &D, issuer_private_key_y, credential_random, &rng));

    TEST_ASSERT(0 == credential_schnorr_verify(c, s, &B, &member_public, &D));

    destroy_test_rng(&rng);

    printf("\tsuccess\n");
}

void schnorr_issuer_sign_sane()
{
    printf("Starting schnorr::schnorr_issuer_sign_sane...\n");

    BIG_256_56 issuer_private_x;
    BIG_256_56 issuer_private_y;
    ECP2_BN254 issuer_public_X;
    ECP2_BN254 issuer_public_Y;
    ECP2_BN254_mul(&issuer_public_X, issuer_private_x);
    ECP2_BN254_mul(&issuer_public_Y, issuer_private_y);

    BIG_256_56 c, sx, sy;

    csprng rng;
    create_test_rng(&rng);

    TEST_ASSERT(0 == issuer_schnorr_sign(&c, &sx, &sy, &issuer_public_X, &issuer_public_Y, issuer_private_x, issuer_private_y, &rng));

    destroy_test_rng(&rng);

    TEST_ASSERT(0 == BIG_256_56_iszilch(c));
    TEST_ASSERT(0 == BIG_256_56_iszilch(sx));
    TEST_ASSERT(0 == BIG_256_56_iszilch(sy));
    TEST_ASSERT(0 == BIG_256_56_isunity(c));
    TEST_ASSERT(0 == BIG_256_56_isunity(sx));
    TEST_ASSERT(0 == BIG_256_56_isunity(sy));

    printf("\tsuccess\n");
}

void schnorr_issuer_sign_integration()
{
    printf("Starting schnorr::schnorr_issuer_sign_integration...\n");

    csprng rng;
    create_test_rng(&rng);

    BIG_256_56 issuer_private_x;
    random_num_mod_order(&issuer_private_x, &rng);
    ECP2_BN254 issuer_public_X;
    set_to_basepoint2(&issuer_public_X);
    ECP2_BN254_mul(&issuer_public_X, issuer_private_x);

    BIG_256_56 issuer_private_y;
    random_num_mod_order(&issuer_private_y, &rng);
    ECP2_BN254 issuer_public_Y;
    set_to_basepoint2(&issuer_public_Y);
    ECP2_BN254_mul(&issuer_public_Y, issuer_private_y);

    BIG_256_56 c, sx, sy;

    TEST_ASSERT(0 == issuer_schnorr_sign(&c, &sx, &sy, &issuer_public_X, &issuer_public_Y, issuer_private_x, issuer_private_y, &rng));

    destroy_test_rng(&rng);

    TEST_ASSERT(0 == issuer_schnorr_verify(c, sx, sy, &issuer_public_X, &issuer_public_Y));

    printf("\tsuccess\n");
}

void schnorr_sign_benchmark()
{
    unsigned rounds = 2500;

    printf("Starting schnorr::schnorr_sign_benchmark (%d iterations)...\n", rounds);

    ECP_BN254 public;
    BIG_256_56 private;

    csprng rng;
    create_test_rng(&rng);

    schnorr_keygen(&public, &private, &rng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c, s;

    struct timeval tv1;
    gettimeofday(&tv1, NULL);

    ECP_BN254 basepoint;
    set_to_basepoint(&basepoint);
    for (unsigned i = 0; i < rounds; i++) {
        schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &rng);
    }

    struct timeval tv2;
    gettimeofday(&tv2, NULL);
    unsigned long long elapsed = (tv2.tv_usec + tv2.tv_sec * 1000000) -
        (tv1.tv_usec + tv1.tv_sec * 1000000);

    printf("%llu usec (%6llu signs/s)\n",
            elapsed,
            rounds * 1000000ULL / elapsed);

    TEST_ASSERT (elapsed < 2000 * rounds); // If we're taking more than 2ms per signature, something's wrong.

    destroy_test_rng(&rng);
}

