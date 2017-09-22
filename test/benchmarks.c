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
#include <ecdaa/member_keypair_BN254.h>
#include <ecdaa/credential_BN254.h>
#include <ecdaa/issuer_keypair_BN254.h>
#include <ecdaa/signature_BN254.h>
#include <ecdaa/group_public_key_BN254.h>
#include <ecdaa/revocation_list_BN254.h>
#include <ecdaa/prng.h>

#include <sys/time.h>
#include <string.h>

static void schnorr_sign_benchmark();

static void sign_benchmark();
static void verify_benchmark();

typedef struct sign_and_verify_fixture {
    struct ecdaa_prng prng;
    uint8_t *msg;
    uint32_t msg_len;
    struct ecdaa_revocation_list_BN254 sk_rev_list;
    struct ecdaa_member_public_key_BN254 pk;
    struct ecdaa_member_secret_key_BN254 sk;
    struct ecdaa_issuer_public_key_BN254 ipk;
    struct ecdaa_issuer_secret_key_BN254 isk;
    struct ecdaa_credential_BN254 cred;
} sign_and_verify_fixture;

static void setup(sign_and_verify_fixture* fixture);
static void teardown(sign_and_verify_fixture* fixture);

int main()
{
    schnorr_sign_benchmark();

    sign_benchmark();
    verify_benchmark();
}

static void setup(sign_and_verify_fixture* fixture)
{
    TEST_ASSERT(0 == ecdaa_prng_init(&fixture->prng));

    big_256_56_random_mod_order(&fixture->isk.x, get_csprng(&fixture->prng));
    ecp2_BN254_set_to_generator(&fixture->ipk.gpk.X);
    ECP2_BN254_mul(&fixture->ipk.gpk.X, fixture->isk.x);

    big_256_56_random_mod_order(&fixture->isk.y, get_csprng(&fixture->prng));
    ecp2_BN254_set_to_generator(&fixture->ipk.gpk.Y);
    ECP2_BN254_mul(&fixture->ipk.gpk.Y, fixture->isk.y);

    ecp_BN254_set_to_generator(&fixture->pk.Q);
    big_256_56_random_mod_order(&fixture->sk.sk, get_csprng(&fixture->prng));
    ECP_BN254_mul(&fixture->pk.Q, fixture->sk.sk);

    struct ecdaa_credential_BN254_signature cred_sig;
    ecdaa_credential_BN254_generate(&fixture->cred, &cred_sig, &fixture->isk, &fixture->pk, &fixture->prng);

    fixture->msg = (uint8_t*) "Test message";
    fixture->msg_len = strlen((char*)fixture->msg);

    fixture->sk_rev_list.length=0;
    fixture->sk_rev_list.list=NULL;
}

static void teardown(sign_and_verify_fixture* fixture)
{
    ecdaa_prng_free(&fixture->prng);
}

void schnorr_sign_benchmark()
{
    unsigned rounds = 2500;

    printf("Starting schnorr::schnorr_sign_benchmark (%d iterations)...\n", rounds);

    ECP_BN254 public;
    BIG_256_56 private;

    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));

    schnorr_keygen(&public, &private, &prng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    BIG_256_56 c, s;

    struct timeval tv1;
    gettimeofday(&tv1, NULL);

    ECP_BN254 basepoint;
    ecp_BN254_set_to_generator(&basepoint);
    for (unsigned i = 0; i < rounds; i++) {
        schnorr_sign(&c, &s, msg, msg_len, &basepoint, &public, private, &prng);
    }

    struct timeval tv2;
    gettimeofday(&tv2, NULL);
    unsigned long long elapsed = (tv2.tv_usec + tv2.tv_sec * 1000000) -
        (tv1.tv_usec + tv1.tv_sec * 1000000);

    printf("%llu usec (%6llu signs/s)\n",
            elapsed,
            rounds * 1000000ULL / elapsed);

    ecdaa_prng_free(&prng);

}

static void sign_benchmark()
{
    unsigned rounds = 250;

    printf("Starting sign-and-verify::sign_benchmark (%d iterations)...\n", rounds);

    sign_and_verify_fixture fixture;
    setup(&fixture);

    struct ecdaa_signature_BN254 sig;

    struct timeval tv1;
    gettimeofday(&tv1, NULL);

    for (unsigned i = 0; i < rounds; i++) {
        TEST_ASSERT(0 == ecdaa_signature_BN254_sign(&sig, fixture.msg, fixture.msg_len, &fixture.sk, &fixture.cred, &fixture.prng));
    }

    struct timeval tv2;
    gettimeofday(&tv2, NULL);
    unsigned long long elapsed = (tv2.tv_usec + tv2.tv_sec * 1000000) -
        (tv1.tv_usec + tv1.tv_sec * 1000000);

    teardown(&fixture);

    printf("%llu usec (%6llu signs/s)\n",
            elapsed,
            rounds * 1000000ULL / elapsed);
}

static void verify_benchmark()
{
    unsigned rounds = 250;

    printf("Starting sign-and-verify::verify_benchmark (%d iterations)...\n", rounds);

    sign_and_verify_fixture fixture;
    setup(&fixture);

    struct ecdaa_signature_BN254 sig;

    TEST_ASSERT(0 == ecdaa_signature_BN254_sign(&sig, fixture.msg, fixture.msg_len, &fixture.sk, &fixture.cred, &fixture.prng));

    struct timeval tv1;
    gettimeofday(&tv1, NULL);

    for (unsigned i = 0; i < rounds; i++) {
        TEST_ASSERT(0 == ecdaa_signature_BN254_verify(&sig, &fixture.ipk.gpk, &fixture.sk_rev_list, fixture.msg, fixture.msg_len));
    }

    struct timeval tv2;
    gettimeofday(&tv2, NULL);
    unsigned long long elapsed = (tv2.tv_usec + tv2.tv_sec * 1000000) -
        (tv1.tv_usec + tv1.tv_sec * 1000000);

    teardown(&fixture);

    printf("%llu usec (%6llu verifications/s)\n",
            elapsed,
            rounds * 1000000ULL / elapsed);
}
