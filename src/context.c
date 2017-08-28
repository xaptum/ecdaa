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

#include <amcl/amcl.h>

#include <assert.h>

#define SERIALIZED_POINT_SIZE2 128 // (32 + 32 + 32 + 32)
#define ISSUER_HASH_INPUT_LENGTH 641 // 1 + 5 * SERIALIZED_POINT_SIZE2 (extra 1 for 0x04, to match FIDO)

// int generate_issuer_key_pair(issuer_public_key_t *pk,
//                              issuer_secret_key_t *sk,
//                              csprng *rng)
// {
//     assert(SERIALIZED_POINT_SIZE2 == 4*MODBYTES_256_56);
//     assert(ISSUER_HASH_INPUT_LENGTH == 1 + 5*SERIALIZED_POINT_SIZE2);
// 
//     // Secret key is
//     // two random Bignums.
//     random_num_mod_order(&sk->x, rng);
//     random_num_mod_order(&sk->y, rng);
// 
//     // Public key is
//     // 1) G2 generator raised to the two private key random Bignums...
//     set_to_basepoint2(&pk->X);
//     set_to_basepoint2(&pk->Y);
//     ECP2_BN254_mul(&pk->X, sk->x);
//     ECP2_BN254_mul(&pk->Y, sk->y);
// 
//     // 2) and a Schnorr-type signature to prove our knowledge of those two random Bignums.
//     BIG_256_56 rx;
//     random_num_mod_order(&rx, rng);
//     ECP2_BN254 Ux;
//     set_to_basepoint2(&Ux);
//     ECP2_BN254_mul(&Ux, rx);
// 
//     BIG_256_56 ry;
//     random_num_mod_order(&ry, rng);
//     ECP2_BN254 Uy;
//     set_to_basepoint2(&Uy);
//     ECP2_BN254_mul(&Uy, ry);
// 
//     // c = Hash(Ux | Uy | basepoint | X | Y)
//     char hash_input_as_bytes[ISSUER_HASH_INPUT_LENGTH];
//     octet hash_input = {.val = hash_input_as_bytes,
//                         .len = 0,
//                         .max = ISSUER_HASH_INPUT_LENGTH};
// 
//     // TODO: toOctet adds 0x04, so need to do this manually? (to fit FIDO)
//     ECP2_BN254_toOctet(&hash_input, &Ux);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     ECP2_BN254_toOctet(&hash_input, &Uy);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     ECP2_BN254 basepoint;
//     set_to_basepoint2(&basepoint);
//     ECP2_BN254_toOctet(&hash_input, &basepoint);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     ECP2_BN254_toOctet(&hash_input, &pk->X);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     ECP2_BN254_toOctet(&hash_input, &pk->Y);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     hash_input.len = ISSUER_HASH_INPUT_LENGTH;
// 
//     hash256 sh256;
//     HASH256_init(&sh256);
//     char c_as_bytes[MODBYTES_256_56];
//     for (int i=0; i < ISSUER_HASH_INPUT_LENGTH; ++i)
//         HASH256_process(&sh256, hash_input_as_bytes[i]);
//     HASH256_hash(&sh256, c_as_bytes);
// 
//     BIG_256_56_fromBytesLen(pk->c, c_as_bytes, MODBYTES_256_56);
// 
//     BIG_256_56 curve_order;
//     BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
// 
//     // sx = rx + c*x (mod p)
//     BIG_256_56 scratch;
//     BIG_256_56_modmul(scratch, pk->c, sk->x, curve_order);
//     BIG_256_56_add(scratch, rx, scratch);
//     BIG_256_56_mod(scratch, curve_order);
// 
//     // sy = ry + c*y (mod p)
//     BIG_256_56_modmul(scratch, pk->c, sk->y, curve_order);
//     BIG_256_56_add(scratch, ry, scratch);
//     BIG_256_56_mod(scratch, curve_order);
// 
//     return 0;
// }
// 
// int verify_issuer_public_key(issuer_public_key_t *pk)
// {
//     // Ecp stuff
//     ECP2_BN254 my_Ux;
//     ECP2_BN254 my_Uy;
// 
//     // Calculate hash
//     BIG_256_56 my_c;
// 
//     char hash_input_as_bytes[ISSUER_HASH_INPUT_LENGTH];
//     octet hash_input = {.val = hash_input_as_bytes,
//                         .len = 0,
//                         .max = ISSUER_HASH_INPUT_LENGTH};
// 
//     ECP2_BN254_toOctet(&hash_input, &my_Ux);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     ECP2_BN254_toOctet(&hash_input, &my_Uy);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     ECP2_BN254 basepoint;
//     set_to_basepoint2(&basepoint);
//     ECP2_BN254_toOctet(&hash_input, &basepoint);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     ECP2_BN254_toOctet(&hash_input, &pk->X);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     ECP2_BN254_toOctet(&hash_input, &pk->Y);
//     hash_input.val += SERIALIZED_POINT_SIZE2;
//     hash_input.len = ISSUER_HASH_INPUT_LENGTH;
// 
//     hash256 sh256;
//     HASH256_init(&sh256);
//     char c_as_bytes[MODBYTES_256_56];
//     for (int i=0; i < ISSUER_HASH_INPUT_LENGTH; ++i)
//         HASH256_process(&sh256, hash_input_as_bytes[i]);
//     HASH256_hash(&sh256, c_as_bytes);
// 
//     BIG_256_56_fromBytesLen(pk->c, c_as_bytes, MODBYTES_256_56);
// 
//     return BIG_256_56_comp(my_c, pk->c);
// }
// 
// int generate_member_join_key_pair(member_join_public_key_t *pk,
//                                   member_join_secret_key_t *sk,
//                                   csprng *rng)
// {
//     // Secret key is
//     // a random Bignum.
//     random_num_mod_order(&sk->sk, rng);
// 
//     // Public key is
//     // 1) G1 generator raised to sk...
//     set_to_basepoint(&pk->Q);
//     ECP_BN254_mul(&pk->Q, sk->sk);
// 
//     // 2) and a Schnorr-type signature to prove our knowledge of sk.
//     BIG_256_56 r;
//     random_num_mod_order(&r, rng);
//     ECP_BN254 U;
//     set_to_basepoint(&U);
//     ECP_BN254_mul(&U, r);
// 
//     // TODO: Finish this (construct the hash-input, do the hash, output to 'c')
//     // c = Hash(U | basepoint | Q | nonce)
//     // sx = rx + c*x (mod p)
//     // sy = ry + c*y (mod p)
// 
//     return 0;
// }
