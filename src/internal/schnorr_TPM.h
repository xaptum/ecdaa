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

#ifndef ECDAA_SCHNORR_TPM_H
#define ECDAA_SCHNORR_TPM_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct ecdaa_prng;

#include <ecdaa/tpm_context.h>

#include <amcl/big_XXX.h>
#include <amcl/ecp_FP256BN.h>
#include <amcl/ecp2_FP256BN.h>

#include <stdint.h>

/*
 * Perform TPM2_Commit/TPM2_Sign signature of msg_in, allowing for a non-standard basepoint.
 *
 * if basename:
 *  c_out = Hash ( RAND(Z_p)*basepoint | basepoint | public_key | RAND(Z_p)*P2 | P2 | [private_key]P2 | basename | msg_in )
 *      where P2 = the curve point hashed from basename (cf. `ecp_ZZZ_fromhash`)
 * else:
 *  c_out = Hash ( RAND(Z_p)*basepoint | basepoint | public_key | msg_in )
 * s_out = RAND(Z_p) + c_out * private_key,
 *
 * Note: All random numbers are chosen by the TPM.
 *
 * public_key = private_key * basepoint
 *
 * c_out and s_out will be reduced modulo the group order (and thus normalized) upon return
 *
 *  Returns:
 *   0 on success
 *   -1 if basepoint is not valid
 */
int schnorr_sign_TPM(BIG_XXX *c_out,
                     BIG_XXX *s_out,
                     ECP_FP256BN *K_out,
                     const uint8_t *msg_in,
                     uint32_t msg_len,
                     ECP_FP256BN *basepoint,
                     ECP_FP256BN *public_key,
                     const uint8_t *basename,
                     uint32_t basename_length,
                     struct ecdaa_tpm_context *tpm_ctx);

#ifdef __cplusplus
}
#endif

#endif
