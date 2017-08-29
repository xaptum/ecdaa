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
#include <xaptum-ecdaa/member.h>
#include <xaptum-ecdaa/issuer.h>

#include "../src/pairing_curve_utils.h"

#include <amcl/ecp_BN254.h>
#include <amcl/ecp2_BN254.h>

#include <string.h>

typedef struct credential_test_fixture {
    ecdaa_member_t member;
    ecdaa_issuer_t issuer;
} credential_test_fixture;

static void setup(credential_test_fixture* fixture);

static void cred_generate_then_validate();

int main()
{
    cred_generate_then_validate();
}

credential_test_fixture fixture_s;

static void setup(credential_test_fixture* fixture)
{
    create_test_rng(&fixture->issuer.rng);
    random_num_mod_order(&fixture->issuer.sk.x, &fixture->issuer.rng);
    set_to_basepoint2(&fixture->issuer.pk.gpk.X);
    ECP2_BN254_mul(&fixture->issuer.pk.gpk.X, fixture->issuer.sk.x);
    random_num_mod_order(&fixture->issuer.sk.y, &fixture->issuer.rng);
    set_to_basepoint2(&fixture->issuer.pk.gpk.Y);
    ECP2_BN254_mul(&fixture->issuer.pk.gpk.Y, fixture->issuer.sk.y);

    create_test_rng(&fixture->member.rng);

    set_to_basepoint(&fixture->member.pk.Q);
    random_num_mod_order(&fixture->member.sk.sk, &fixture->member.rng);
    ECP_BN254_mul(&fixture->member.pk.Q, fixture->member.sk.sk);

    memcpy(&fixture->member.gpk, &fixture->issuer.pk.gpk, sizeof(ecdaa_group_public_key_t));
}

static void cred_generate_then_validate()
{
    printf("Starting join-tests::cred_generate_validate...\n");

    // credential_test_fixture fixture;
    setup(&fixture_s);

    ecdaa_credential_t cred;
    ecdaa_credential_signature_t cred_sig;
    TEST_ASSERT(0 == ecdaa_generate_credential(&cred, &cred_sig, &fixture_s.issuer, &fixture_s.member.pk));

    TEST_ASSERT(0 == ecdaa_validate_credential(&cred, &cred_sig, &fixture_s.member));

    printf("\tsuccess\n");
}
