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

#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/member_keypair_ZZZ.h>
#include <ecdaa/issuer_keypair_ZZZ.h>
#include <ecdaa/prng.h>

#include "src/amcl-extensions/big_XXX.h"
#include "src/amcl-extensions/ecp_ZZZ.h"
#include "src/amcl-extensions/ecp2_ZZZ.h"

#include <amcl/ecp_ZZZ.h>
#include <amcl/ecp2_ZZZ.h>

#include <string.h>

typedef struct credential_test_fixture {
    struct ecdaa_prng prng;

    struct ecdaa_member_public_key_ZZZ pk;
    struct ecdaa_member_secret_key_ZZZ sk;

    struct ecdaa_issuer_public_key_ZZZ ipk;
    struct ecdaa_issuer_secret_key_ZZZ isk;
} credential_test_fixture;

static void setup(credential_test_fixture* fixture);
static void teardown(credential_test_fixture* fixture);

static void cred_generate_then_validate();
static void lengths_same();
static void cred_generate_then_serialize_deserialize();

int main()
{
    cred_generate_then_validate();
    lengths_same();
    cred_generate_then_serialize_deserialize();
}

static void setup(credential_test_fixture* fixture)
{
    TEST_ASSERT(0 == ecdaa_prng_init(&fixture->prng));

    big_XXX_random_mod_order(&fixture->isk.x, get_csprng(&fixture->prng));
    ecp2_ZZZ_set_to_generator(&fixture->ipk.gpk.X);
    ECP2_ZZZ_mul(&fixture->ipk.gpk.X, fixture->isk.x);

    big_XXX_random_mod_order(&fixture->isk.y, get_csprng(&fixture->prng));
    ecp2_ZZZ_set_to_generator(&fixture->ipk.gpk.Y);
    ECP2_ZZZ_mul(&fixture->ipk.gpk.Y, fixture->isk.y);

    ecp_ZZZ_set_to_generator(&fixture->pk.Q);
    big_XXX_random_mod_order(&fixture->sk.sk, get_csprng(&fixture->prng));
    ECP_ZZZ_mul(&fixture->pk.Q, fixture->sk.sk);
}

static void teardown(credential_test_fixture* fixture)
{
    ecdaa_prng_free(&fixture->prng);
}

static void cred_generate_then_validate()
{
    printf("Starting credential::cred_generate_validate...\n");

    credential_test_fixture fixture;
    setup(&fixture);

    struct ecdaa_credential_ZZZ cred;
    struct ecdaa_credential_ZZZ_signature cred_sig;
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_generate(&cred, &cred_sig, &fixture.isk, &fixture.pk, &fixture.prng));

    TEST_ASSERT(0 == ecdaa_credential_ZZZ_validate(&cred, &cred_sig, &fixture.pk, &fixture.ipk.gpk));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void lengths_same()
{
    printf("Starting credential::lengths_same...\n");

    TEST_ASSERT(ECDAA_CREDENTIAL_ZZZ_LENGTH == ecdaa_credential_ZZZ_length());

    TEST_ASSERT(ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH == ecdaa_credential_ZZZ_signature_length());

    printf("\tsuccess\n");
}

static void cred_generate_then_serialize_deserialize()
{
    printf("Starting credential::cred_generate_then_serialize_deserialize...\n");

    credential_test_fixture fixture;
    setup(&fixture);

    struct ecdaa_credential_ZZZ cred;
    struct ecdaa_credential_ZZZ_signature cred_sig;
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_generate(&cred, &cred_sig, &fixture.isk, &fixture.pk, &fixture.prng));

    uint8_t cred_buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH];
    uint8_t sig_buffer[ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH];

    ecdaa_credential_ZZZ_serialize(cred_buffer, &cred);
    ecdaa_credential_ZZZ_signature_serialize(sig_buffer, &cred_sig);

    struct ecdaa_credential_ZZZ cred_deserialized;
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_deserialize(&cred_deserialized, cred_buffer));
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_deserialize_with_signature(&cred_deserialized, &fixture.pk, &fixture.ipk.gpk, cred_buffer, sig_buffer));

    teardown(&fixture);

    printf("\tsuccess\n");
}
