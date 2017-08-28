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

#include "xaptum_test.h"

#include <sign.h>
#include <verify.h>
#include <context.h>

#include <sodium.h>

#include <string.h>

static void sign_then_verify();

int main()
{
    sign_then_verify();
}

static void sign_then_verify()
{
    printf("Starting integration::sign_then_verify...\n");

    csprng rng;
#define SEED_LEN 256
    char seed_as_bytes[SEED_LEN];
    randombytes_buf(seed_as_bytes, SEED_LEN);
    octet seed = {.len=SEED_LEN, .max=SEED_LEN, .val=seed_as_bytes};
    CREATE_CSPRNG(&rng, &seed);

    issuer_public_key_t ipk;
    issuer_secret_key_t isk;
    nonce_t nonce = {{0}};
    generate_issuer_key_pair(&ipk, &isk, &rng);

    member_join_public_key_t pk;
    member_join_secret_key_t sk;
    generate_member_join_key_pair(&pk, &sk, nonce, &rng);

    credential_t cred;
    BIG_256_56 c_ignore, s_ignore;
    generate_credential(&cred, &c_ignore, &s_ignore, &isk, &pk, &rng);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    ecdaa_signature_t sig;
    TEST_ASSERT(0 == sign(&sig, &sk, &cred, msg, msg_len, &rng));

    TEST_ASSERT(0 == verify(&sig, &ipk, msg, msg_len));

    printf("\tsuccess\n");
}
