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

#ifndef XAPTUM_ECDAA_MEMBER_KEYPAIR_H
#define XAPTUM_ECDAA_MEMBER_KEYPAIR_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct ecdaa_issuer_nonce_t;

#include <amcl/big_256_56.h>
#include <amcl/ecp_BN254.h>
#include <amcl/randapi.h>

/*
 * Member's public key.
 */
typedef struct ecdaa_member_public_key_t {
    ECP_BN254 Q;
    BIG_256_56 c;
    BIG_256_56 s;
} ecdaa_member_public_key_t;

/*
 * Member's secret key.
 */
typedef struct ecdaa_member_secret_key_t {
    BIG_256_56 sk;
} ecdaa_member_secret_key_t;

/*
 * Generate a fresh keypair.
 */
int ecdaa_generate_member_key_pair(ecdaa_member_public_key_t *pk,
                                   ecdaa_member_secret_key_t *sk,
                                   struct ecdaa_issuer_nonce_t *nonce,
                                   csprng *rng);

#ifdef __cplusplus
}
#endif

#endif

