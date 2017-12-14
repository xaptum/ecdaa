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

#include "../amcl-extensions/big_256_56.h"
#include "../amcl-extensions/ecp_FP256BN.h"
#include "../amcl-extensions/ecp2_FP256BN.h"
#include "../tpm-utils/commit.h"
#include "../tpm-utils/sign.h"

#include <assert.h>

enum {
    THREE_ECP_LENGTH = 3*ECP_FP256BN_LENGTH
};

int schnorr_sign_TPM(BIG_256_56 *c_out,
                     BIG_256_56 *s_out,
                     const uint8_t *msg_in,
                     uint32_t msg_len,
                     ECP_FP256BN *basepoint,
                     ECP_FP256BN *public_key,
                     struct ecdaa_tpm_context *tpm_ctx)
{
    int ret = 0;

    // 1) (Commit) (call TPM2_Commit)
    ECP_FP256BN K, L, R;
    ret = tpm_commit(tpm_ctx, basepoint, NULL, 0, &K, &L, &R);
    if (0 != ret)
        return -1;

    // 2) (Sign 1) Compute c = Hash( R | basepoint | public_key | msg_in )
    //      (modular-reduce c, too).
    uint8_t hash_input_begin[THREE_ECP_LENGTH];
    assert(3*ECP_FP256BN_LENGTH == sizeof(hash_input_begin));
    ecp_FP256BN_serialize(hash_input_begin, &R);
    ecp_FP256BN_serialize(hash_input_begin+ECP_FP256BN_LENGTH, basepoint);
    ecp_FP256BN_serialize(hash_input_begin+2*ECP_FP256BN_LENGTH, public_key);
    big_256_56_from_two_message_hash(c_out, hash_input_begin, sizeof(hash_input_begin), msg_in, msg_len);
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_FP256BN);
    BIG_256_56_mod(*c_out, curve_order);

    // 3) (Sign 2) (Call TPM2_Sign)
    // TODO: Don't double-copy the hash (first into a BIG, then back out of a BIG)
    TPMT_SIGNATURE signature;
    TPM2B_DIGEST digest = {.size=MODBYTES_256_56, .buffer={0}};
    BIG_256_56_toBytes((char*)digest.buffer, *c_out);
    ret = tpm_sign(tpm_ctx, &digest, &signature);
    if (0 != ret)
        return -2;

    // 4) (Output) Convert TPMS_SIGNATURE_ECC.signatureS into BIG_256_56
    assert(MODBYTES_256_56 == signature.signature.ecdaa.signatureS.size);
    BIG_256_56_fromBytes(*s_out, (char*)signature.signature.ecdaa.signatureS.buffer);

    return 0;
}
