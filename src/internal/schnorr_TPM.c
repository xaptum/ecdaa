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

#include "schnorr_TPM.h"

#include "../amcl-extensions/big_XXX.h"
#include "../amcl-extensions/ecp_FP256BN.h"
#include "../amcl-extensions/ecp2_FP256BN.h"
#include "../tpm-utils/commit.h"
#include "../tpm-utils/sign.h"

#include <assert.h>

enum {
    THREE_ECP_LENGTH = 3*ECP_FP256BN_LENGTH,
    SIX_ECP_LENGTH = 6*ECP_FP256BN_LENGTH
};

int schnorr_sign_TPM(BIG_XXX *c_out,
                     BIG_XXX *s_out,
                     ECP_FP256BN *K_out,
                     const uint8_t *msg_in,
                     uint32_t msg_len,
                     ECP_FP256BN *basepoint,
                     ECP_FP256BN *public_key,
                     const uint8_t *basename,
                     uint32_t basename_len,
                     struct ecdaa_tpm_context *tpm_ctx)
{
    int ret = 0;

    // 1) (Commit) (call TPM2_Commit)
    ECP_FP256BN L, R;
    ret = tpm_commit(tpm_ctx, basepoint, basename, basename_len, K_out, &L, &R);
    if (0 != ret)
        return -1;

    // If we're not creating a basename-signature, but K_out != NULL,
    //  set K_out:=g1_generator (so it de-serializes OK).
    if (0 == basename_len && NULL != K_out) {
        ecp_FP256BN_set_to_generator(K_out);
    }
    
    // 2) (Sign 1) Compute hash
    if (basename_len != 0) {
        // 2i) Find P2 by hashing basename
        ECP_FP256BN P2;
        int32_t hash_ret = ecp_FP256BN_fromhash(&P2, basename, basename_len);
        if (hash_ret < 0)
            return -1;

        // 2ii) Compute c = Hash( R | basepoint | public_key | L | P2 | K_out | basename | msg_in )
        uint8_t hash_input_begin[SIX_ECP_LENGTH];
        assert(6*ECP_FP256BN_LENGTH == sizeof(hash_input_begin));
        ecp_FP256BN_serialize(hash_input_begin, &R);
        ecp_FP256BN_serialize(hash_input_begin+ECP_FP256BN_LENGTH, basepoint);
        ecp_FP256BN_serialize(hash_input_begin+2*ECP_FP256BN_LENGTH, public_key);
        ecp_FP256BN_serialize(hash_input_begin+3*ECP_FP256BN_LENGTH, &L);
        ecp_FP256BN_serialize(hash_input_begin+4*ECP_FP256BN_LENGTH, &P2);
        ecp_FP256BN_serialize(hash_input_begin+5*ECP_FP256BN_LENGTH, K_out);
        big_XXX_from_three_message_hash(c_out, hash_input_begin, sizeof(hash_input_begin), basename, basename_len, msg_in, msg_len);
    } else {
        // Compute c = Hash( R | basepoint | public_key | msg_in )
        uint8_t hash_input_begin[THREE_ECP_LENGTH];
        assert(3*ECP_FP256BN_LENGTH == sizeof(hash_input_begin));
        ecp_FP256BN_serialize(hash_input_begin, &R);
        ecp_FP256BN_serialize(hash_input_begin+ECP_FP256BN_LENGTH, basepoint);
        ecp_FP256BN_serialize(hash_input_begin+2*ECP_FP256BN_LENGTH, public_key);
        big_XXX_from_two_message_hash(c_out, hash_input_begin, sizeof(hash_input_begin), msg_in, msg_len);
    }

    // 3) (Sign 2) Modular-reduce c
    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_FP256BN);
    BIG_XXX_mod(*c_out, curve_order);

    // 4) (Sign 3) (Call TPM2_Sign)
    // TODO: Don't double-copy the hash (first into a BIG, then back out of a BIG)
    TPMT_SIGNATURE signature;
    TPM2B_DIGEST digest = {.size=MODBYTES_XXX, .buffer={0}};
    BIG_XXX_toBytes((char*)digest.buffer, *c_out);
    ret = tpm_sign(tpm_ctx, &digest, &signature);
    if (0 != ret)
        return -2;

    // 5) (Output) Convert TPMS_SIGNATURE_ECC.signatureS into BIG_XXX
    assert(MODBYTES_XXX == signature.signature.ecdaa.signatureS.size);
    BIG_XXX_fromBytes(*s_out, (char*)signature.signature.ecdaa.signatureS.buffer);

    return 0;
}
