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

#include "amcl-extensions/big_XXX.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"

#include <ecdaa/member_keypair_ZZZ.h>
#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/issuer_keypair_ZZZ.h>
#include <ecdaa/signature_ZZZ.h>
#include <ecdaa/group_public_key_ZZZ.h>
#include <ecdaa/revocations_ZZZ.h>

#include <string.h>

#include <sys/time.h>

static void sign_then_verify_good();
static void sign_then_verify_on_rev_list();
static void sign_then_verify_bad_basename_fails();
static void sign_then_verify_no_basename();
static void sign_then_verify_on_bsn_rev_list();
static void lengths_same();
static void serialize_deserialize();
static void pseudonym();
static void deserialize_garbage_fails();
static void trivial_credential_fails();

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
} sign_and_verify_fixture;

static void setup(sign_and_verify_fixture* fixture);
static void teardown(sign_and_verify_fixture *fixture);

int main()
{
    sign_then_verify_good();
    sign_then_verify_on_rev_list();
    sign_then_verify_bad_basename_fails();
    sign_then_verify_no_basename();
    sign_then_verify_on_bsn_rev_list();
    lengths_same();
    serialize_deserialize();
    pseudonym();
    deserialize_garbage_fails();
    trivial_credential_fails();
}

static void setup(sign_and_verify_fixture* fixture)
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
}

static void sign_then_verify_good()
{
    printf("Starting signature::sign_then_verify_good...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.sk, &fixture.cred, test_randomness));

    TEST_ASSERT(0 == ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &fixture.revocations, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void sign_then_verify_on_rev_list()
{
    printf("Starting signature::sign_then_verify_on_rev_list...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    // Put self on a secret-key revocation list, to be used in verify.
    struct ecdaa_member_secret_key_ZZZ sk_rev_list_bad_raw[1];
    BIG_XXX_copy(sk_rev_list_bad_raw[0].sk, fixture.sk.sk);
    struct ecdaa_revocations_ZZZ rev_list_bad = {.sk_length=1, .sk_list=sk_rev_list_bad_raw, .bsn_length=0, .bsn_list=NULL};

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.sk, &fixture.cred, test_randomness));

    TEST_ASSERT(0 != ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &rev_list_bad, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void sign_then_verify_on_bsn_rev_list()
{
    printf("Starting signature::sign_then_verify_on_bsn_rev_list...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.sk, &fixture.cred, test_randomness));

    // Put self on a basename revocation list, to be used in verify.
    ECP_ZZZ bsn_rev_list_bad_raw[1];
    ECP_ZZZ_copy(&bsn_rev_list_bad_raw[0], &sig.K);
    struct ecdaa_revocations_ZZZ rev_list_bad = {.bsn_length=1, .bsn_list=bsn_rev_list_bad_raw, .sk_length=0, .sk_list=NULL};

    TEST_ASSERT(0 != ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &rev_list_bad, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void sign_then_verify_bad_basename_fails()
{
    printf("Starting signature::sign_then_verify_bad_basename_fails...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    uint8_t *wrong_basename = (uint8_t*) "WRONGBASENAME";
    uint32_t wrong_basename_len = strlen((char*)wrong_basename);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.sk, &fixture.cred, test_randomness));

    TEST_ASSERT(0 != ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &fixture.revocations, fixture.msg, fixture.msg_len, wrong_basename, wrong_basename_len));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void sign_then_verify_no_basename()
{
    printf("Starting signature::sign_then_verify_no_basename...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.sk, &fixture.cred, test_randomness));

    TEST_ASSERT(0 != ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &fixture.revocations, fixture.msg, fixture.msg_len, NULL, 0));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void lengths_same()
{
    printf("Starting signature::lengths_same...\n");

    TEST_ASSERT(ECDAA_SIGNATURE_ZZZ_LENGTH == ecdaa_signature_ZZZ_length());

    printf("\tsuccess\n");
}

static void serialize_deserialize()
{
    printf("Starting signature::serialize_deserialize...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.sk, &fixture.cred, test_randomness));

    TEST_ASSERT(0 == ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &fixture.revocations, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len));

    uint8_t buffer[ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH];
    ecdaa_signature_ZZZ_serialize(buffer, &sig, 1);
    struct ecdaa_signature_ZZZ sig_deserialized;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_deserialize(&sig_deserialized, buffer, 1));
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_deserialize_and_verify(&sig_deserialized, &fixture.ipk.gpk, &fixture.revocations, buffer, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, 1));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void pseudonym()
{
    printf("Starting signature::pseudonym...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.sk, &fixture.cred, test_randomness));

    ECP_ZZZ pseudonym;
    ecdaa_signature_ZZZ_get_pseudonym(&pseudonym, &sig);

    // Serialize, then ensure we get same pseudonym whether from the original sig or the serialized one
    uint8_t buffer[ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH];
    ecdaa_signature_ZZZ_serialize(buffer, &sig, 1);

    uint8_t *serialized_pseudonym;
    uint32_t serialized_pseudonym_length;
    ecdaa_signature_ZZZ_access_pseudonym_in_serialized(&serialized_pseudonym, &serialized_pseudonym_length, buffer);
    TEST_ASSERT(ECP_ZZZ_LENGTH == serialized_pseudonym_length);
    ECP_ZZZ pseudonym_from_serialized;
    int deserial_ret = ecp_ZZZ_deserialize(&pseudonym_from_serialized, serialized_pseudonym);
    TEST_ASSERT(0 == deserial_ret);

    TEST_ASSERT(1 == ECP_ZZZ_equals(&pseudonym, &pseudonym_from_serialized));

    // Create another signature, and ensure it has the same pseudonym
    struct ecdaa_signature_ZZZ sig2;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig2, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.sk, &fixture.cred, test_randomness));
    ECP_ZZZ pseudonym2;
    ecdaa_signature_ZZZ_get_pseudonym(&pseudonym2, &sig2);
    TEST_ASSERT(1 == ECP_ZZZ_equals(&pseudonym, &pseudonym2));

    // Create a third signature, with a different basename, and ensure it has a DIFFERENT pseudonym
    uint8_t *new_basename = (uint8_t*)"LWKEJFLJWEFL:WEJ";
    uint32_t new_basename_len = strlen((char*)new_basename);
    struct ecdaa_signature_ZZZ sig3;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig3, fixture.msg, fixture.msg_len, new_basename, new_basename_len, &fixture.sk, &fixture.cred, test_randomness));
    ECP_ZZZ pseudonym3;
    ecdaa_signature_ZZZ_get_pseudonym(&pseudonym3, &sig3);
    TEST_ASSERT(1 != ECP_ZZZ_equals(&pseudonym, &pseudonym3));

    teardown(&fixture);

    printf("\tsuccess\n");
}

static void deserialize_garbage_fails()
{
    printf("Starting signature::serialize_deserialize...\n");

    uint8_t buffer[ECDAA_SIGNATURE_ZZZ_LENGTH] = {0};
    struct ecdaa_signature_ZZZ sig_deserialized;
    TEST_ASSERT(0 != ecdaa_signature_ZZZ_deserialize(&sig_deserialized, buffer, 0));

    printf("\tsuccess\n");
}

static void trivial_credential_fails()
{
    printf("Starting signature::trivial_credential_fails...\n");

    sign_and_verify_fixture fixture;
    setup(&fixture);

    // Make the issuer malicious, by using y=0
    BIG_XXX_zero(fixture.isk.y);
    ecp2_ZZZ_set_to_generator(&fixture.ipk.gpk.Y);
    ECP2_ZZZ_mul(&fixture.ipk.gpk.Y, fixture.isk.y);
    struct ecdaa_credential_ZZZ_signature cred_sig;
    ecdaa_credential_ZZZ_generate(&fixture.cred, &cred_sig, &fixture.isk, &fixture.pk, test_randomness);

    struct ecdaa_signature_ZZZ sig;
    TEST_ASSERT(0 == ecdaa_signature_ZZZ_sign(&sig, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, &fixture.sk, &fixture.cred, test_randomness));

    TEST_ASSERT(0 != ecdaa_signature_ZZZ_verify(&sig, &fixture.ipk.gpk, &fixture.revocations, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len));

    uint8_t buffer[ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH];
    ecdaa_signature_ZZZ_serialize(buffer, &sig, 1);
    struct ecdaa_signature_ZZZ sig_deserialized;
    TEST_ASSERT(0 != ecdaa_signature_ZZZ_deserialize_and_verify(&sig_deserialized, &fixture.ipk.gpk, &fixture.revocations, buffer, fixture.msg, fixture.msg_len, fixture.basename, fixture.basename_len, 1));

    teardown(&fixture);

    printf("\tsuccess\n");
}

