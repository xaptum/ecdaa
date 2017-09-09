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

#include <ecdaa/signature.h>

#include <ecdaa/member_keypair.h>
#include <ecdaa/group_public_key.h>
#include <ecdaa/sk_revocation_list.h>
#include <ecdaa/credential.h>

#include "schnorr.h"
#include "pairing_curve_utils.h"

#include <amcl/pair_BN254.h>
#include <amcl/fp12_BN254.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t serialized_signature_length()
{
    return SERIALIZED_SIGNATURE_LENGTH;
}

void ecdaa_serialize_signature(uint8_t *buffer_out,
                               ecdaa_signature_t *signature)
{
    BIG_256_56_toBytes((char*)buffer_out, signature->c);
    BIG_256_56_toBytes((char*)(buffer_out + MODBYTES_256_56), signature->s);

    serialize_point(buffer_out + 2*MODBYTES_256_56, &signature->R);
    serialize_point(buffer_out + 2*MODBYTES_256_56 + serialized_point_length(), &signature->S);
    serialize_point(buffer_out + 2*MODBYTES_256_56 + 2*serialized_point_length(), &signature->T);
    serialize_point(buffer_out + 2*MODBYTES_256_56 + 3*serialized_point_length(), &signature->W);
}

int ecdaa_deserialize_signature(ecdaa_signature_t *signature_out,
                                uint8_t *buffer_in)
{
    int ret = 0;

    BIG_256_56_fromBytes(signature_out->c, (char*)buffer_in);
    BIG_256_56_fromBytes(signature_out->s, (char*)(buffer_in + MODBYTES_256_56));

    if (0 != deserialize_point(&signature_out->R, buffer_in + MODBYTES_256_56))
        ret = -1;

    if (0 != deserialize_point(&signature_out->S, buffer_in + MODBYTES_256_56 + serialized_point_length()))
        ret = -1;

    if (0 != deserialize_point(&signature_out->T, buffer_in + MODBYTES_256_56 + 2*serialized_point_length()))
        ret = -1;

    if (0 != deserialize_point(&signature_out->W, buffer_in + MODBYTES_256_56 + 3*serialized_point_length()))
        ret = -1;

    return ret;
}

int ecdaa_sign(struct ecdaa_signature_t *signature_out,
               const uint8_t* message,
               uint32_t message_len,
               struct ecdaa_member_secret_key_t *sk,
               struct ecdaa_credential_t *cred,
               csprng *rng)
{
    // 1) Choose random l <- Z_p
    BIG_256_56 l;
    random_num_mod_order(&l, rng);

    // 2) Multiply the four points in the credential by l,
    //  and save to the four points in the signature

    // 2i) Multiply cred->A by l and save to sig->R (R = l*A)
    ECP_BN254_copy(&signature_out->R, &cred->A);
    ECP_BN254_mul(&signature_out->R, l);

    // 2ii) Multiply cred->B by l and save to sig->S (S = l*B)
    ECP_BN254_copy(&signature_out->S, &cred->B);
    ECP_BN254_mul(&signature_out->S, l);

    // 2iii) Multiply cred->C by l and save to sig->T (T = l*C)
    ECP_BN254_copy(&signature_out->T, &cred->C);
    ECP_BN254_mul(&signature_out->T, l);

    // 2iv) Multiply cred->D by l and save to sig->W (W = l*D)
    ECP_BN254_copy(&signature_out->W, &cred->D);
    ECP_BN254_mul(&signature_out->W, l);

    // 3) Create a Schnorr-like signature on W concatenated with the message,
    //  where the basepoint is S.
    int sign_ret = schnorr_sign(&signature_out->c,
                                &signature_out->s,
                                message,
                                message_len,
                                &signature_out->S,
                                &signature_out->W,
                                sk->sk,
                                rng);
    
    // Clear sensitive intermediate memory.
    BIG_256_56_zero(l);

    return sign_ret;
}

int ecdaa_verify(struct ecdaa_signature_t *signature,
                 struct ecdaa_group_public_key_t *gpk,
                 struct ecdaa_sk_revocation_list_t *sk_rev_list,
                 uint8_t* message,
                 uint32_t message_len)
{
    int ret = 0;

    // 1) Check R,S,T,W for membership in group, and R and S for !=inf
    if (0 != check_point_membership(&signature->R)
            || 0 != check_point_membership(&signature->S)
            || 0 != check_point_membership(&signature->T)
            || 0 != check_point_membership(&signature->W))
        ret = -1;
    if (ECP_BN254_isinf(&signature->R) || ECP_BN254_isinf(&signature->S))
        ret = -1;
    
    // 2) Check Schnorr-type signature
    int schnorr_ret = schnorr_verify(signature->c,
                                     signature->s,
                                     message,
                                     message_len,
                                     &signature->S,
                                     &signature->W);
    if (0 != schnorr_ret)
        ret = -1;

    ECP2_BN254 basepoint2;
    set_to_basepoint2(&basepoint2);

    // 3) Check e(R, Y) == e(S, P_2)
    FP12_BN254 pairing_one;
    FP12_BN254 pairing_one_prime;
    compute_pairing(&pairing_one, &signature->R, &gpk->Y);
    compute_pairing(&pairing_one_prime, &signature->S, &basepoint2);
    if (!FP12_BN254_equals(&pairing_one, &pairing_one_prime))
        ret = -1;

    // 4) Compute R+W
    ECP_BN254 RW;
    ECP_BN254_copy(&RW, &signature->R);
    ECP_BN254_add(&RW, &signature->W);

    // 5) Check e(T, P_2) == e(R+W, X)
    FP12_BN254 pairing_two;
    FP12_BN254 pairing_two_prime;
    compute_pairing(&pairing_two, &signature->T, &basepoint2);
    compute_pairing(&pairing_two_prime, &RW, &gpk->X);
    if (!FP12_BN254_equals(&pairing_two, &pairing_two_prime))
        ret = -1;

    // 6) Check W against sk_revocation_list
    ECP_BN254 Wcheck;
    for (size_t i = 0; i < sk_rev_list->length; ++i) {
        ECP_BN254_copy(&Wcheck, &signature->S);
        ECP_BN254_mul(&Wcheck, sk_rev_list->list[i].sk);
        if (ECP_BN254_equals(&Wcheck, &signature->W))
            ret = -1;
    }

    return ret;
}
