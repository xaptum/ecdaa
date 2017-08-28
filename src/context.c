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

#include <xaptum-ecdaa/context.h>

#include "pairing_curve_utils.h" 
#include "schnorr.h" 

#include <amcl/amcl.h>

#include <string.h>
#include <assert.h>

#define SERIALIZED_POINT_SIZE2 128 // (32 + 32 + 32 + 32)
#define ISSUER_HASH_INPUT_LENGTH 641 // 1 + 5 * SERIALIZED_POINT_SIZE2 (extra 1 for 0x04, to match FIDO)

int generate_issuer_key_pair(issuer_public_key_t *pk,
                             issuer_secret_key_t *sk,
                             csprng *rng)
{
    // Secret key is
    // two random Bignums.
    random_num_mod_order(&sk->x, rng);
    random_num_mod_order(&sk->y, rng);

    // Public key is
    // 1) G2 generator raised to the two private key random Bignums...
    set_to_basepoint2(&pk->X);
    set_to_basepoint2(&pk->Y);
    ECP2_BN254_mul(&pk->X, sk->x);
    ECP2_BN254_mul(&pk->Y, sk->y);

    // 2) and a Schnorr-type signature to prove our knowledge of those two random Bignums.
    // HEADS-UP: toOctet adds 0x04, so need to do this manually? (to fit FIDO)
    // TODO: Do a 'double-Schnorr'

    return 0;
}

int generate_member_join_key_pair(member_join_public_key_t *pk,
                                  member_join_secret_key_t *sk,
                                  nonce_t nonce,
                                  csprng *rng)
{
    // 1) Generate Schnorr-type keypair,
    schnorr_keygen(&pk->Q, &sk->sk, rng);

    // 2) and a Schnorr-type signature on the Schnorr-type public_key itself concatenated with the nonce.
    //  (Sign 1) Build message buffer to be signed (serialized_public_key | msg)
    ECP_BN254 basepoint;
    set_to_basepoint(&basepoint);
    uint8_t msg[97];
    size_t serialized_point_length = 2*MODBYTES_256_56 + 1;
    assert( (serialized_point_length + sizeof(nonce_t)) == sizeof(msg));
    octet pk_as_oct = {.len=0, .max=serialized_point_length, .val=(char*)msg};
    ECP_BN254_toOctet(&pk_as_oct, &pk->Q);
    memcpy(msg + serialized_point_length, nonce.data, sizeof(nonce));

    //  (Sign 2) Sign the message buffer, and save to (pk->c, pk->s).
    int sign_ret = schnorr_sign(&pk->c,
                                &pk->s,
                                msg,
                                sizeof(msg),
                                &basepoint,
                                sk->sk,
                                rng);

    return sign_ret;
}

int generate_credential(credential_t *cred,
                        BIG_256_56 *c_out,
                        BIG_256_56 *s_out,
                        issuer_secret_key_t *issuer_sk,
                        member_join_public_key_t *member_pk,
                        csprng *rng)
{
    if (NULL == c_out || NULL == s_out)
        return -1;  // Currently, just to use these parameters and make compiler happy.

    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);

    // 1) Choose random l <- Z_p
    BIG_256_56 l;
    random_num_mod_order(&l, rng);

    // 2) Multiply generator by l and save to cred->A (A = l*P)
    set_to_basepoint(&cred->A);
    ECP_BN254_mul(&cred->A, l);

    // 3) Multiply A by my secret y and save to cred->B (B = y*A)
    ECP_BN254_copy(&cred->B, &cred->A);
    ECP_BN254_mul(&cred->B, issuer_sk->y);

    // 4) Mod-multiply l and y
    BIG_256_56 ly;
    BIG_256_56_modmul(ly, l, issuer_sk->y, curve_order);

    // 5) Multiply member's public_key by ly and save to cred->D (D = ly*Q)
    ECP_BN254_copy(&cred->D, &member_pk->Q);
    ECP_BN254_mul(&cred->D, ly);

    // 6) Multiply A by my secret x (store in cred->C temporarily)
    ECP_BN254_copy(&cred->C, &cred->A);
    ECP_BN254_mul(&cred->C, issuer_sk->x);

    // 7) Mod-multiply ly (see step 4) by my secret x
    BIG_256_56 xyl;
    BIG_256_56_modmul(xyl, ly, issuer_sk->x, curve_order);

    // 8) Multiply member's public_key by xyl
    ECP_BN254 Qxyl;
    ECP_BN254_copy(&Qxyl, &member_pk->Q);
    ECP_BN254_mul(&Qxyl, xyl);

    // 9) Add Ax and xyl*Q and save to cred->C (C = x*A + xyl*Q)
    ECP_BN254_add(&cred->C, &Qxyl);

    // TODO: Do a 'single-random-double-Schnorr signature, save into c_out, s_out

    return 0;
}
