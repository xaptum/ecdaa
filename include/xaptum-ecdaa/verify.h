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

#include <sign.h>
#include <context.h>

#ifdef __cplusplus
extern "C" {
#endif

int verify(ecdaa_signature_t *signature,
           issuer_public_key_t *issuer_pk,
           sk_revocation_list_t *sk_rev_list,
           uint8_t* message,
           uint32_t message_len);

#ifdef __cplusplus
}
#endif

#endif
