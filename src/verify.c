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

#include <xaptum-ecdaa/verify.h>
#include <xaptum-ecdaa/signature.h>
#include <xaptum-ecdaa/group_public_key.h>
#include <xaptum-ecdaa/issuer_keypair.h>
#include <xaptum-ecdaa/sk_revocation_list.h>
#include <xaptum-ecdaa/member_keypair.h>

#include "schnorr.h"
#include "pairing_curve_utils.h"

#include <amcl/pair_BN254.h>
#include <amcl/fp12_BN254.h>

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