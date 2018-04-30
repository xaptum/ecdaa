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

#include "../ecdaa-test-utils.h"
#include "tpm_ZZZ-test-utils.h"

#include "amcl-extensions/big_XXX.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"
#include "schnorr-tpm/schnorr_TPM_ZZZ.h"
#include "schnorr/schnorr_ZZZ.h"

#include <ecdaa-tpm/member_keypair_TPM_ZZZ.h>
#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/issuer_keypair_ZZZ.h>
#include <ecdaa-tpm/signature_TPM_ZZZ.h>
#include <ecdaa/group_public_key_ZZZ.h>
#include <ecdaa/revocations_ZZZ.h>
#include <ecdaa-tpm/tpm_context.h>

#include <string.h>

#include <sys/time.h>

static void sign_then_verify_good();
static void sign_then_verify_bad_basename_fails();
static void sign_then_verify_no_basename();

typedef struct sign_and_verify_fixture {
    uint8_t *msg;
    uint32_t msg_len;
    uint8_t *basename;
    uint32_t basename_len;
    struct ecdaa_revocations_ZZZ revocations;
    struct ecdaa_member_public_key_ZZZ pk;
    struct ecdaa_member_secret_key_ZZZ sk;
    struct ecdaa_issuer_public_key_ZZZ ipk;
    struct ecdaa_issuer_secret_key_ZZZ isk;
    struct ecdaa_credential_ZZZ cred;
    struct tpm_test_context tpm_ctx;
} sign_and_verify_fixture;

static void setup(sign_and_verify_fixture* fixture);
static void teardown(sign_and_verify_fixture *fixture);

int main()
{
    sign_then_verify_good();
    sign_then_verify_bad_basename_fails();
    sign_then_verify_no_basename();
}

static void setup(sign_and_verify_fixture* fixture)
{
    TEST_ASSERT(0 == tpm_initialize(&fixture->tpm_ctx));

    ecp_ZZZ_random_mod_order(&fixture->isk.x, test_randomness);
    ecp2_ZZZ_set_to_generator(&fixture->ipk.gpk.X);
    ECP2_ZZZ_mul(&fixture->ipk.gpk.X, fixture->isk.x);

    ecp_ZZZ_random_mod_order(&fixture->isk.y, test_randomness);
    ecp2_ZZZ_set_to_generator(&fixture->ipk.gpk.Y);
    ECP2_ZZZ_mul(&fixture->ipk.gpk.Y, fixture->isk.y);

    uint8_t *nonce = (uint8_t*)"nonce";
    uint32_t nonce_len = 5;
    TEST_ASSERT(0 == ecdaa_member_key_pair_TPM_ZZZ_generate(&fixture->pk, fixture->tpm_ctx.serialized_public_key, nonce, nonce_len, &fixture->tpm_ctx.tpm_ctx));

    struct ecdaa_credential_ZZZ_signature cred_sig;
    ecdaa_credential_ZZZ_generate(&fixture->cred, &cred_sig, &fixture->isk, &fixture->pk, test_randomness);

    fixture->msg = (uint8_t*) "Test message";
    fixture->msg_len = (uint32_t)strlen((char*)fixture->msg);

    fixture->basename = (uint8_t*) "BASENAME";
    fixture->basename_len = (uint32_t)strlen((char*)fixture->basename);

    fixture->revocations.sk_length=0;
    fixture->revocations.sk_list=NULL;
    fixture->revocations.bsn_length=0;
    fixture->revocations.bsn_list=NULL;
}

static void teardown(sign_and_verify_fixture *fixture)
{
    (void)fixture;
    tpm_cleanup(&fixture->tpm_ctx);
}

static void sign_then_verify_good()
{
    printf("Starting signature_TPM_ZZZ::sign_then_verify_good...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_TPM_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.cred, test_randomness, &fixture.tpm_ctx.tpm_ctx));

    TEST_ASSERT(0 == ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &fixture.revocations, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void sign_then_verify_bad_basename_fails()
{
    printf("Starting signature_TPM_ZZZ::sign_then_verify_bad_basename_fails...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    uint8_t *wrong_basename = (uint8_t*) "WRONGBASENAME";
    uint32_t wrong_basename_len = strlen((char*)wrong_basename);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_TPM_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.cred, test_randomness, &fixture.tpm_ctx.tpm_ctx));

    TEST_ASSERT(0 != ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &fixture.revocations, fixture.msg, fixture.msg_len, wrong_basename, wrong_basename_len));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void sign_then_verify_no_basename()
{
    printf("Starting signature_TPM_ZZZ::sign_then_verify_no_basename...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_TPM_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, NULL, 0, &fixture.cred, test_randomness, &fixture.tpm_ctx.tpm_ctx));

    TEST_ASSERT(0 == ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &fixture.revocations, fixture.msg, fixture.msg_len, NULL, 0));

    teardown(&fixture);

    printf("\tsuccess\n");
}
