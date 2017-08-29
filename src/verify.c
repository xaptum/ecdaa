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

#include "schnorr.h"

#include "pairing_curve_utils.h"

#include <verify.h>

#include <amcl/pair_BN254.h>
#include <amcl/fp12_BN254.h>

int verify(ecdaa_signature_t *signature,
           issuer_public_key_t *issuer_pk,
           uint8_t* message,
           uint32_t message_len)
{
    // NOTE: Assumes issuer_pk has already been checked for validity

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
    compute_pairing(&pairing_one, &signature->R, &issuer_pk->Y);
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
    compute_pairing(&pairing_two_prime, &RW, &issuer_pk->X);
    if (!FP12_BN254_equals(&pairing_two, &pairing_two_prime))
        ret = -1;

    return ret;
}
