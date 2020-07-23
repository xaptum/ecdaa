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

#include "amcl-extensions/big_XXX.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"

#include <amcl/include/ecp_ZZZ.h>
#include <amcl/include/ecp2_ZZZ.h>

#include <string.h>

typedef struct credential_test_fixture {
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
static void cred_generate_then_serialize_deserialize_file();
static void cred_generate_then_serialize_deserialize_fp();

int main()
{
    cred_generate_then_validate();
    lengths_same();
    cred_generate_then_serialize_deserialize();
    cred_generate_then_serialize_deserialize_file();
    cred_generate_then_serialize_deserialize_fp();
}

static void setup(credential_test_fixture* fixture)
{
    ecp_ZZZ_random_mod_order(&fixture->isk.x, test_randomness);
    ecp2_ZZZ_set_to_generator(&fixture->ipk.gpk.X);
    ECP2_ZZZ_mul(&fixture->ipk.gpk.X, fixture->isk.x);

    ecp_ZZZ_random_mod_order(&fixture->isk.y, test_randomness);
    ecp2_ZZZ_set_to_generator(&fixture->ipk.gpk.Y);
    ECP2_ZZZ_mul(&fixture->ipk.gpk.Y, fixture->isk.y);

    ecp_ZZZ_set_to_generator(&fixture->pk.Q);
    ecp_ZZZ_random_mod_order(&fixture->sk.sk, test_randomness);
    ECP_ZZZ_mul(&fixture->pk.Q, fixture->sk.sk);
}

static void teardown(credential_test_fixture* fixture)
{
    (void)fixture;
}

static void cred_generate_then_validate()
{
    printf("Starting credential::cred_generate_validate...\n");

    credential_test_fixture fixture;
    setup(&fixture);

    struct ecdaa_credential_ZZZ cred;
    struct ecdaa_credential_ZZZ_signature cred_sig;
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_generate(&cred, &cred_sig, &fixture.isk, &fixture.pk, test_randomness));

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
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_generate(&cred, &cred_sig, &fixture.isk, &fixture.pk, test_randomness));

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

static void cred_generate_then_serialize_deserialize_file()
{
    printf("Starting credential::cred_generate_then_serialize_deserialize_file...\n");

    const char *cred_file = "cred.bin";
    const char *cred_sig_file = "cred_sig.bin";

    credential_test_fixture fixture;
    setup(&fixture);

    struct ecdaa_credential_ZZZ cred;
    struct ecdaa_credential_ZZZ_signature cred_sig;
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_generate(&cred, &cred_sig, &fixture.isk, &fixture.pk, test_randomness));

    TEST_ASSERT(0 == ecdaa_credential_ZZZ_serialize_file(cred_file, &cred));
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_signature_serialize_file(cred_sig_file, &cred_sig));

    struct ecdaa_credential_ZZZ cred_deserialized;
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_deserialize_file(&cred_deserialized, cred_file));
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_deserialize_with_signature_file(&cred_deserialized, &fixture.pk, &fixture.ipk.gpk, cred_file, cred_sig_file));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void cred_generate_then_serialize_deserialize_fp()
{
    printf("Starting credential::cred_generate_then_serialize_deserialize_fp...\n");

    const char *cred_file = "cred.bin";
    const char *cred_sig_file = "cred_sig.bin";

    credential_test_fixture fixture;
    setup(&fixture);

    struct ecdaa_credential_ZZZ cred;
    struct ecdaa_credential_ZZZ_signature cred_sig;
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_generate(&cred, &cred_sig, &fixture.isk, &fixture.pk, test_randomness));

    FILE *cred_fp = fopen(cred_file, "wb");
    TEST_ASSERT(NULL != cred_fp);
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_serialize_fp(cred_fp, &cred));
    fclose(cred_fp);
    FILE *cred_sig_fp = fopen(cred_sig_file, "wb");
    TEST_ASSERT(NULL != cred_sig_fp);
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_signature_serialize_fp(cred_sig_fp, &cred_sig));
    fclose(cred_sig_fp);

    struct ecdaa_credential_ZZZ cred_deserialized;
    cred_fp = fopen(cred_file, "rb");
    TEST_ASSERT(NULL != cred_fp);
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_deserialize_fp(&cred_deserialized, cred_fp));
    fclose(cred_fp);
    cred_fp = fopen(cred_file, "rb");
    TEST_ASSERT(NULL != cred_fp);
    cred_sig_fp = fopen(cred_sig_file, "rb");
    TEST_ASSERT(NULL != cred_sig_fp);
    TEST_ASSERT(0 == ecdaa_credential_ZZZ_deserialize_with_signature_fp(&cred_deserialized, &fixture.pk, &fixture.ipk.gpk, cred_fp, cred_sig_fp));
    fclose(cred_fp);
    fclose(cred_sig_fp);

    teardown(&fixture);

    printf("\tsuccess\n");
}
