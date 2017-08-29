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

#ifndef XAPTUM_ECDAA_SIGN_H
#define XAPTUM_ECDAA_SIGN_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/randapi.h>

#include <stdint.h>

struct ecdaa_signature_t;
struct ecdaa_credential_t;
struct ecdaa_member_secret_key_t;

/*
 * Create an ECDAA signature.
 *
 * Returns:
 * 0 on success
 * -1 if unable to create signature
 */
int ecdaa_sign(struct ecdaa_signature_t *signature_out,
               const uint8_t* message,
               uint32_t message_len,
               struct ecdaa_member_secret_key_t *sk,
               struct ecdaa_credential_t *cred,
               csprng *rng);

#ifdef __cplusplus
}
#endif

#endif

