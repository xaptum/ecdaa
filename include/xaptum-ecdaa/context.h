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

#include <amcl/randapi.h>
#include <amcl/ecp_BN254.h>
#include <amcl/ecp2_BN254.h>
#include <amcl/big_256_56.h>

#ifndef XAPTUM_ECDAA_CONTEXT_H
#define XAPTUM_ECDAA_CONTEXT_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {uint8_t data[32];} nonce_t;

typedef struct {
    ECP2_BN254 X;
    ECP2_BN254 Y;
    BIG_256_56 c;
    BIG_256_56 sx;
    BIG_256_56 sy;
} issuer_public_key_t;

typedef struct {
    BIG_256_56 x;
    BIG_256_56 y;
} issuer_secret_key_t;

int generate_issuer_key_pair(issuer_public_key_t *pk,
                             issuer_secret_key_t *sk,
                             csprng *rng);

typedef struct {
    BIG_256_56 sk;
} member_join_secret_key_t;

typedef struct {
    ECP_BN254 Q;
    BIG_256_56 c;
    BIG_256_56 s;
} member_join_public_key_t;

int generate_member_join_key_pair(member_join_public_key_t *pk,
                                  member_join_secret_key_t *sk,
                                  nonce_t nonce,
                                  csprng *rng);

#ifdef __cplusplus
}
#endif

#endif

