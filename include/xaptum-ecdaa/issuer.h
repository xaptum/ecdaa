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

#ifndef XAPTUM_ECDAA_ISSUER_H
#define XAPTUM_ECDAA_ISSUER_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <xaptum-ecdaa/issuer_keypair.h>

#include <amcl/randapi.h>

struct ecdaa_member_public_key_t;
struct ecdaa_credential_signature_t;
struct ecdaa_credential_t;
struct ecdaa_issuer_nonce_t;

/*
 * Context for an Issuer, for a single DAA group.
 */
typedef struct ecdaa_issuer_t {
    ecdaa_issuer_public_key_t pk;
    ecdaa_issuer_secret_key_t sk;
    csprng rng;
} ecdaa_issuer_t;

/*
 * Constructor for `ecdaa_issuer_t`.
 */
int ecdaa_construct_issuer(ecdaa_issuer_t *issuer_out,
                           uint8_t *seed,
                           uint32_t seed_length);

/*
 * Respond to an incoming Join request from a Member.
 *
 * Returns:
 * 0 on success
 * -1 if Join request is invalid
 */
int ecdaa_process_join_request(struct ecdaa_credential_t *credential_out,
                               struct ecdaa_credential_signature_t *credential_signature_out,
                               struct ecdaa_member_public_key_t *member_pk,
                               ecdaa_issuer_t *issuer);

/*
 * Generate a signing nonce to be used by a Member requesting to Join.
 */
void ecdaa_generate_issuer_nonce(struct ecdaa_issuer_nonce_t *nonce_out,
                                 ecdaa_issuer_t *issuer);

#ifdef __cplusplus
}
#endif

#endif

