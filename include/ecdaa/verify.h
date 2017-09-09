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

#ifndef XAPTUM_ECDAA_VERIFY_H
#define XAPTUM_ECDAA_VERIFY_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct ecdaa_signature_t;
struct ecdaa_group_public_key_t;
struct ecdaa_sk_revocation_list_t;

#include <stdint.h>

/*
 * Verify an ECDAA signature.
 *
 * Returns:
 * 0 on success
 * -1 if signature is invalid
 */
int ecdaa_verify(struct ecdaa_signature_t *signature,
                 struct ecdaa_group_public_key_t *gpk,
                 struct ecdaa_sk_revocation_list_t *sk_rev_list,
                 uint8_t* message,
                 uint32_t message_len);

#ifdef __cplusplus
}
#endif

#endif
