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

#include <xaptum-ecdaa/credential.h>
#include <xaptum-ecdaa/member_keypair.h>
#include <xaptum-ecdaa/issuer_keypair.h>

#include "../src/pairing_curve_utils.h"

#include <amcl/ecp_BN254.h>
#include <amcl/ecp2_BN254.h>

#include <string.h>

typedef struct credential_test_fixture {
    csprng rng;

    ecdaa_member_public_key_t pk;
    ecdaa_member_secret_key_t sk;

    ecdaa_issuer_public_key_t ipk;
    ecdaa_issuer_secret_key_t isk;
} credential_test_fixture;

static void setup(credential_test_fixture* fixture);

static void cred_generate_then_validate();

int main()
{
    cred_generate_then_validate();
}

static void setup(credential_test_fixture* fixture)
{
    create_test_rng(&fixture->rng);

    random_num_mod_order(&fixture->isk.x, &fixture->rng);
    set_to_basepoint2(&fixture->ipk.gpk.X);
    ECP2_BN254_mul(&fixture->ipk.gpk.X, fixture->isk.x);

    random_num_mod_order(&fixture->isk.y, &fixture->rng);
    set_to_basepoint2(&fixture->ipk.gpk.Y);
    ECP2_BN254_mul(&fixture->ipk.gpk.Y, fixture->isk.y);

    set_to_basepoint(&fixture->pk.Q);
    random_num_mod_order(&fixture->sk.sk, &fixture->rng);
    ECP_BN254_mul(&fixture->pk.Q, fixture->sk.sk);
}

static void cred_generate_then_validate()
{
    printf("Starting join-tests::cred_generate_validate...\n");

    credential_test_fixture fixture;
    setup(&fixture);

    ecdaa_credential_t cred;
    ecdaa_credential_signature_t cred_sig;
    TEST_ASSERT(0 == ecdaa_generate_credential(&cred, &cred_sig, &fixture.isk, &fixture.pk, &fixture.rng));

    TEST_ASSERT(0 == ecdaa_validate_credential(&cred, &cred_sig, &fixture.pk, &fixture.ipk.gpk));

    printf("\tsuccess\n");
}
