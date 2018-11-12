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

#include "schnorr_TPM_ZZZ.h"

#include "amcl-extensions/big_XXX.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"
#include "../tpm/commit_ZZZ.h"
#include "../tpm/sign.h"

#include <assert.h>

static
int try_tpm_sign(TPMT_SIGNATURE *signature_out,
                 TPM2B_DIGEST *digest,
                 ECP_ZZZ *K_out,
                 const uint8_t *msg_in,
                 uint32_t msg_len,
                 ECP_ZZZ *basepoint,
                 ECP_ZZZ *public_key,
                 const uint8_t *basename,
                 uint32_t basename_len,
                 BIG_XXX *curve_order,
                 struct ecdaa_tpm_context *tpm_ctx);

enum {
    THREE_ECP_LENGTH = 3*ECP_ZZZ_LENGTH,
    SIX_ECP_LENGTH = 6*ECP_ZZZ_LENGTH
};

int schnorr_sign_TPM_ZZZ(BIG_XXX *c_out,
                         BIG_XXX *s_out,
                         BIG_XXX *n_out,
                         ECP_ZZZ *K_out,
                         const uint8_t *msg_in,
                         uint32_t msg_len,
                         ECP_ZZZ *basepoint,
                         ECP_ZZZ *public_key,
                         const uint8_t *basename,
                         uint32_t basename_len,
                         struct ecdaa_tpm_context *tpm_ctx)
{
    // If we're not creating a basename-signature, but K_out != NULL,
    //  set K_out:=g1_generator (so it de-serializes OK).
    if (0 == basename_len && NULL != K_out) {
        ecp_ZZZ_set_to_generator(K_out);
    }

    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);

    int attempts = 1;
    TPMT_SIGNATURE signature;
    TPM2B_DIGEST digest = {.size=MODBYTES_XXX, .buffer={0}};
    while (attempts < MAX_TPM_SIGN_ATTEMPTS) {
        int ret = try_tpm_sign(&signature,
                               &digest,
                               K_out,
                               msg_in,
                               msg_len,
                               basepoint,
                               public_key,
                               basename,
                               basename_len,
                               &curve_order,
                               tpm_ctx);
        if (0 != ret)
            return ret;

        // The TPM spec appears to specify that a nonce with fewer than MODBYTES_XXX significant bytes
        // should have leading 0's trimmed before getting put into the hash for the DAA signature.
        // This is problematic, so we demand that the nonce always be MODBYTES_XX bytes in length.
        if (MODBYTES_XXX == signature.signature.ecdaa.signatureR.size)
            break;

        ++attempts;
    }
    if (attempts >= MAX_TPM_SIGN_ATTEMPTS)
        return -4;

    // 4) (Output) Convert TPMS_SIGNATURE_ECC.signatureS into BIG_XXX
    BIG_XXX_fromBytesLen(*s_out,
                         (char*)signature.signature.ecdaa.signatureS.buffer,
                         signature.signature.ecdaa.signatureS.size);

    // 5) (Output) Convert TPMS_SIGNATURE_ECC.signatureR into BIG_XXX
    BIG_XXX_fromBytesLen(*n_out,
                         (char*)signature.signature.ecdaa.signatureR.buffer,
                         signature.signature.ecdaa.signatureR.size);

    // 6) (Output) Compute final hash
    //      c_out = Hash(n | c')
    //      Mod-reduce final hash, too
    big_XXX_from_two_message_hash(c_out,
                                  signature.signature.ecdaa.signatureR.buffer,
                                  signature.signature.ecdaa.signatureR.size,
                                  digest.buffer,
                                  digest.size);
    BIG_XXX_mod(*c_out, curve_order);

    return 0;
}

int try_tpm_sign(TPMT_SIGNATURE *signature_out,
                 TPM2B_DIGEST *digest,
                 ECP_ZZZ *K_out,
                 const uint8_t *msg_in,
                 uint32_t msg_len,
                 ECP_ZZZ *basepoint,
                 ECP_ZZZ *public_key,
                 const uint8_t *basename,
                 uint32_t basename_len,
                 BIG_XXX *curve_order,
                 struct ecdaa_tpm_context *tpm_ctx)
{
    int ret = 0;

    // 1) (Commit) (call TPM2_Commit)
    ECP_ZZZ L, R;
    ret = tpm_commit_ZZZ(tpm_ctx, basepoint, basename, basename_len, K_out, &L, &R);
    if (0 != ret)
        return -1;

    // 2) (Sign 1) Compute first hash
    //      (modular-reduce c', too).
    BIG_XXX c_prime;
    if (basename_len != 0) {
        // 2i) Find P2 by hashing basename
        ECP_ZZZ P2;
        int32_t hash_ret = ecp_ZZZ_fromhash(&P2, basename, basename_len);
        if (hash_ret < 0)
            return -3;

        // 2ii) Compute c' = Hash( R | basepoint | public_key | L | P2 | K_out | basename | msg_in )
        uint8_t hash_input_begin[SIX_ECP_LENGTH];
        assert(6*ECP_ZZZ_LENGTH == sizeof(hash_input_begin));
        ecp_ZZZ_serialize(hash_input_begin, &R);
        ecp_ZZZ_serialize(hash_input_begin+ECP_ZZZ_LENGTH, basepoint);
        ecp_ZZZ_serialize(hash_input_begin+2*ECP_ZZZ_LENGTH, public_key);
        ecp_ZZZ_serialize(hash_input_begin+3*ECP_ZZZ_LENGTH, &L);
        ecp_ZZZ_serialize(hash_input_begin+4*ECP_ZZZ_LENGTH, &P2);
        ecp_ZZZ_serialize(hash_input_begin+5*ECP_ZZZ_LENGTH, K_out);
        big_XXX_from_three_message_hash(&c_prime, hash_input_begin, sizeof(hash_input_begin), basename, basename_len, msg_in, msg_len);
    } else {
        // Compute c' = Hash( R | basepoint | public_key | msg_in )
        uint8_t hash_input_begin[THREE_ECP_LENGTH];
        assert(3*ECP_ZZZ_LENGTH == sizeof(hash_input_begin));
        ecp_ZZZ_serialize(hash_input_begin, &R);
        ecp_ZZZ_serialize(hash_input_begin+ECP_ZZZ_LENGTH, basepoint);
        ecp_ZZZ_serialize(hash_input_begin+2*ECP_ZZZ_LENGTH, public_key);
        big_XXX_from_two_message_hash(&c_prime, hash_input_begin, sizeof(hash_input_begin), msg_in, msg_len);
    }
    BIG_XXX_mod(c_prime, *curve_order);

    // 3) (Sign 2) (Call TPM2_Sign)
    BIG_XXX_toBytes((char*)digest->buffer, c_prime);
    ret = tpm_sign(tpm_ctx, digest, signature_out);
    if (0 != ret)
        return -2;

    return 0;
}
