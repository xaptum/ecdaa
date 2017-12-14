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

#include "commit.h"

#include "../amcl-extensions/big_256_56.h"
#include "../internal/explicit_bzero.h"

#include <tss2/tss2_sys.h>

#include <string.h>

static
void ecp_to_tpm_format(TPM2B_ECC_POINT *tpm_out, ECP_FP256BN *point_in);

static
int ecp_to_amcl_format(ECP_FP256BN *point_out, TPM2B_ECC_POINT *tpm_in);

static
int32_t g2_hash(ECP_FP256BN *point_out, uint8_t *message, uint32_t message_length);

int tpm_commit(struct ecdaa_tpm_context *tpm_ctx,
               ECP_FP256BN *P1,
               uint8_t *s2,
               uint32_t s2_length,
               ECP_FP256BN *K,
               ECP_FP256BN *L,
               ECP_FP256BN *E)
{
    TPM2B_ECC_POINT P1_tpm = {.size=0};
    TPM2B_SENSITIVE_DATA s2_tpm = {.size=0};
    ECP_FP256BN y2;
    TPM2B_ECC_POINT y2_tpm = {.size=0};
    TPM2B_ECC_POINT K_tpm = {.size=0};
    TPM2B_ECC_POINT L_tpm = {.size=0};
    TPM2B_ECC_POINT E_tpm = {.size=0};

    if (NULL != P1) {
        ecp_to_tpm_format(&P1_tpm, P1);
    }

    int ret = 0;

    do {
        if (NULL != s2 || 0 != s2_length) {
            // If either of these is non-zero, BOTH must be non-zero.
            if (NULL == s2 || 0 == s2_length) {
                ret = -3;
                break;
            }

            if (s2_length > sizeof(s2_tpm.buffer)) {
                ret = -3;
                break;
            }

            int32_t g2_hash_ret = g2_hash(&y2, s2, s2_length);
            if (g2_hash_ret < 0) {
                ret = -3;
                break;
            }
            ecp_to_tpm_format(&y2_tpm, &y2);

            // Concatenate (g2_hash_ret | s2) (cf. g2_hash below)
            s2_tpm.size = s2_length + sizeof(g2_hash_ret);
            memcpy(s2_tpm.buffer, &g2_hash_ret, sizeof(g2_hash_ret));
            memcpy(s2_tpm.buffer + sizeof(g2_hash_ret), s2, s2_length);
        }

        tpm_ctx->last_return_code = Tss2_Sys_Commit(tpm_ctx->sapi_context,
                                                    tpm_ctx->key_handle,
                                                    &tpm_ctx->key_authentication_cmd,
                                                    &P1_tpm,
                                                    &s2_tpm,
                                                    &y2_tpm.point.y,
                                                    &K_tpm,
                                                    &L_tpm,
                                                    &E_tpm,
                                                    &tpm_ctx->commit_counter,
                                                    &tpm_ctx->last_auth_response_cmd);

        if (TSS2_RC_SUCCESS != tpm_ctx->last_return_code) {
            ret = -1;
            break;
        }

        if (K_tpm.size > 4) {
            if (0 != ecp_to_amcl_format(K, &K_tpm)) {
                ret = -2;
                break;
            }
        }
        if (L_tpm.size > 4) {
            if (0 != ecp_to_amcl_format(L, &L_tpm)) {
                ret = -2;
                break;
            }
        }
        if (E_tpm.size > 4) {
            if (0 != ecp_to_amcl_format(E, &E_tpm)) {
                ret = -2;
                break;
            }
        }
    } while(0);

    explicit_bzero(&y2, sizeof(y2));
    explicit_bzero(&P1_tpm, sizeof(P1_tpm));
    explicit_bzero(&s2_tpm, sizeof(s2_tpm));
    explicit_bzero(&y2_tpm, sizeof(y2_tpm));
    explicit_bzero(&K_tpm, sizeof(K_tpm));
    explicit_bzero(&L_tpm, sizeof(L_tpm));
    explicit_bzero(&E_tpm, sizeof(E_tpm));

    return ret;
}

void ecp_to_tpm_format(TPM2B_ECC_POINT *tpm_out, ECP_FP256BN *point_in)
{
    tpm_out->size = 4 + 2*ECP_FP256BN_LENGTH;  // 4 bytes for 2 UINT16 sizes

    tpm_out->point.x.size = MODBYTES_256_56;
    BIG_256_56 x;
    FP_FP256BN_redc(x, &point_in->x);
    BIG_256_56_toBytes((char*)tpm_out->point.x.buffer, x);

    tpm_out->point.y.size = MODBYTES_256_56;
    BIG_256_56 y;
    FP_FP256BN_redc(y, &point_in->y);
    BIG_256_56_toBytes((char*)tpm_out->point.y.buffer, y);
}

int ecp_to_amcl_format(ECP_FP256BN *point_out, TPM2B_ECC_POINT *tpm_in)
{
    if (tpm_in->point.x.size==0 || tpm_in->point.y.size==0)
        return -2;

    BIG_256_56 x;
    BIG_256_56_fromBytes(x, (char*)tpm_in->point.x.buffer);

    BIG_256_56 y;
    BIG_256_56_fromBytes(y, (char*)tpm_in->point.y.buffer);

    if (1 == ECP_FP256BN_set(point_out, x, y)) {
        return 0;
    } else {
        return -1;
    }
}

int32_t g2_hash(ECP_FP256BN *point_out, uint8_t *message, uint32_t message_length)
{
    // Following the Appendix of Chen and Li, 2013

    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_FP256BN);

    for (int32_t i=0; i < 232; i++) {
        BIG_256_56 x;
        big_256_56_from_two_message_hash(&x, (uint8_t*)&i, sizeof(i), message, message_length);
        BIG_256_56_mod(x, curve_order);
        if (ECP_FP256BN_setx(point_out, x, 0))
            return i;
    }

    // If we reach here, we ran out of tries, so return error.
    return -1;
}
