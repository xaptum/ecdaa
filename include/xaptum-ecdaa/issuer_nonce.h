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

#ifndef XAPTUM_ECDAA_ISSUER_NONCE_H
#define XAPTUM_ECDAA_ISSUER_NONCE_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/randapi.h>

#include <stdint.h>

/*
 * Signing nonce provided by Issuer to Member, at the begining of the Join process.
 */
typedef struct ecdaa_issuer_nonce_t {
    uint8_t data[32];
} ecdaa_issuer_nonce_t;

/*
 * Generate a signing nonce to be used by a Member requesting to Join.
 */
void ecdaa_generate_issuer_nonce(struct ecdaa_issuer_nonce_t *nonce_out,
                                 csprng *rng);

#ifdef __cplusplus
}
#endif

#endif

