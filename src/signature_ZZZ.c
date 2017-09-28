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

#include <ecdaa/signature_ZZZ.h>

#include <ecdaa/member_keypair_ZZZ.h>
#include <ecdaa/group_public_key_ZZZ.h>
#include <ecdaa/revocation_list_ZZZ.h>
#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/prng.h>

#include "./internal/schnorr_ZZZ.h"
#include "./amcl-extensions/big_XXX.h"
#include "./amcl-extensions/ecp_ZZZ.h"
#include "./amcl-extensions/ecp2_ZZZ.h"
#include "./amcl-extensions/pairing_ZZZ.h"

#include <amcl/pair_ZZZ.h>
#include <amcl/fp12_ZZZ.h>

size_t ecdaa_signature_ZZZ_length(void)
{
    return ECDAA_SIGNATURE_ZZZ_LENGTH;
}

int ecdaa_signature_ZZZ_sign(struct ecdaa_signature_ZZZ *signature_out,
                             const uint8_t* message,
                             uint32_t message_len,
                             struct ecdaa_member_secret_key_ZZZ *sk,
                             struct ecdaa_credential_ZZZ *cred,
                             struct ecdaa_prng *prng)
{
    // 1) Choose random l <- Z_p
    BIG_XXX l;
    big_XXX_random_mod_order(&l, get_csprng(prng));

    // 2) Multiply the four points in the credential by l,
    //  and save to the four points in the signature

    // 2i) Multiply cred->A by l and save to sig->R (R = l*A)
    ECP_ZZZ_copy(&signature_out->R, &cred->A);
    ECP_ZZZ_mul(&signature_out->R, l);

    // 2ii) Multiply cred->B by l and save to sig->S (S = l*B)
    ECP_ZZZ_copy(&signature_out->S, &cred->B);
    ECP_ZZZ_mul(&signature_out->S, l);

    // 2iii) Multiply cred->C by l and save to sig->T (T = l*C)
    ECP_ZZZ_copy(&signature_out->T, &cred->C);
    ECP_ZZZ_mul(&signature_out->T, l);

    // 2iv) Multiply cred->D by l and save to sig->W (W = l*D)
    ECP_ZZZ_copy(&signature_out->W, &cred->D);
    ECP_ZZZ_mul(&signature_out->W, l);

    // 3) Create a Schnorr-like signature on W concatenated with the message,
    //  where the basepoint is S.
    int sign_ret = schnorr_sign_ZZZ(&signature_out->c,
                                    &signature_out->s,
                                    message,
                                    message_len,
                                    &signature_out->S,
                                    &signature_out->W,
                                    sk->sk,
                                    prng);
    
    // Clear sensitive intermediate memory.
    BIG_XXX_zero(l);

    return sign_ret;
}

int ecdaa_signature_ZZZ_verify(struct ecdaa_signature_ZZZ *signature,
                               struct ecdaa_group_public_key_ZZZ *gpk,
                               struct ecdaa_revocation_list_ZZZ *sk_rev_list,
                               uint8_t* message,
                               uint32_t message_len)
{
    int ret = 0;

    // 1) Check R,S,T,W for membership in group, and R and S for !=inf
    // NOTE: We assume the signature was obtained from a call to `deserialize`,
    //  which already checked the validity of the points R,S,T,W
    
    // 2) Check Schnorr-type signature
    int schnorr_ret = schnorr_verify_ZZZ(signature->c,
                                         signature->s,
                                         message,
                                         message_len,
                                         &signature->S,
                                         &signature->W);
    if (0 != schnorr_ret)
        ret = -1;

    ECP2_ZZZ basepoint2;
    ecp2_ZZZ_set_to_generator(&basepoint2);

    // 3) Check e(R, Y) == e(S, P_2)
    FP12_YYY pairing_one;
    FP12_YYY pairing_one_prime;
    compute_pairing_ZZZ(&pairing_one, &signature->R, &gpk->Y);
    compute_pairing_ZZZ(&pairing_one_prime, &signature->S, &basepoint2);
    if (!FP12_YYY_equals(&pairing_one, &pairing_one_prime))
        ret = -1;

    // 4) Compute R+W
    //      Nb. Add doesn't convert to affine, so do that explicitly
    ECP_ZZZ RW;
    ECP_ZZZ_copy(&RW, &signature->R);
    ECP_ZZZ_add(&RW, &signature->W);
    ECP_ZZZ_affine(&RW);

    // 5) Check e(T, P_2) == e(R+W, X)
    FP12_YYY pairing_two;
    FP12_YYY pairing_two_prime;
    compute_pairing_ZZZ(&pairing_two, &signature->T, &basepoint2);
    compute_pairing_ZZZ(&pairing_two_prime, &RW, &gpk->X);
    if (!FP12_YYY_equals(&pairing_two, &pairing_two_prime))
        ret = -1;

    // 6) Check W against sk_revocation_list
    ECP_ZZZ Wcheck;
    for (size_t i = 0; i < sk_rev_list->length; ++i) {
        ECP_ZZZ_copy(&Wcheck, &signature->S);
        ECP_ZZZ_mul(&Wcheck, sk_rev_list->list[i].sk);
        if (ECP_ZZZ_equals(&Wcheck, &signature->W))
            ret = -1;
    }

    return ret;
}
void ecdaa_signature_ZZZ_serialize(uint8_t *buffer_out,
                                   struct ecdaa_signature_ZZZ *signature)
{
    BIG_XXX_toBytes((char*)buffer_out, signature->c);
    BIG_XXX_toBytes((char*)(buffer_out + MODBYTES_XXX), signature->s);

    ecp_ZZZ_serialize(buffer_out + 2*MODBYTES_XXX, &signature->R);
    ecp_ZZZ_serialize(buffer_out + 2*MODBYTES_XXX + ECP_ZZZ_LENGTH, &signature->S);
    ecp_ZZZ_serialize(buffer_out + 2*MODBYTES_XXX + 2*ECP_ZZZ_LENGTH, &signature->T);
    ecp_ZZZ_serialize(buffer_out + 2*MODBYTES_XXX + 3*ECP_ZZZ_LENGTH, &signature->W);
}

int ecdaa_signature_ZZZ_deserialize(struct ecdaa_signature_ZZZ *signature_out,
                                    uint8_t *buffer_in)
{
    int ret = 0;

    BIG_XXX_fromBytes(signature_out->c, (char*)buffer_in);
    BIG_XXX_fromBytes(signature_out->s, (char*)(buffer_in + MODBYTES_XXX));

    if (0 != ecp_ZZZ_deserialize(&signature_out->R, buffer_in + 2*MODBYTES_XXX))
        ret = -1;

    if (0 != ecp_ZZZ_deserialize(&signature_out->S, buffer_in + 2*MODBYTES_XXX + ECP_ZZZ_LENGTH))
        ret = -1;

    if (0 != ecp_ZZZ_deserialize(&signature_out->T, buffer_in + 2*MODBYTES_XXX + 2*ECP_ZZZ_LENGTH))
        ret = -1;

    if (0 != ecp_ZZZ_deserialize(&signature_out->W, buffer_in + 2*MODBYTES_XXX + 3*ECP_ZZZ_LENGTH))
        ret = -1;

    return ret;
}

int ecdaa_signature_ZZZ_deserialize_and_verify(struct ecdaa_signature_ZZZ *signature_out,
                                               struct ecdaa_group_public_key_ZZZ *gpk,
                                               struct ecdaa_revocation_list_ZZZ *sk_rev_list,
                                               uint8_t *signature_buffer,
                                               uint8_t* message_buffer,
                                               uint32_t message_len)
{
    int ret = 0;

    // 1) De-serialize the signature
    ret = ecdaa_signature_ZZZ_deserialize(signature_out, signature_buffer);

    // 2) Verify the signature
    if (0 == ret) {
        int valid_ret = ecdaa_signature_ZZZ_verify(signature_out, gpk, sk_rev_list, message_buffer, message_len);
        if (0 != valid_ret)
            ret = -2;
    }

    return ret;
}
