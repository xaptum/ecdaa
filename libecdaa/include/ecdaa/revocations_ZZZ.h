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

#ifndef ECDAA_REVOCATIONS_ZZZ_H
#define ECDAA_REVOCATIONS_ZZZ_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct ecdaa_member_secret_key_ZZZ;

#include <amcl/include/ecp_ZZZ.h>

#include <stddef.h>

/*
 * Secret-key revocation list and
 * basename-signature revocation list.
 *
 * `list` is an array of `ecdaa_member_secret_key_ZZZ`s.
 * `length` is the size of `list`.
 */
struct ecdaa_revocations_ZZZ {
    size_t sk_length;
    struct ecdaa_member_secret_key_ZZZ *sk_list;
    size_t bsn_length;
    ECP_ZZZ *bsn_list;
};

#ifdef __cplusplus
}
#endif

#endif
