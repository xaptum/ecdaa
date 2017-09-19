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

#ifndef ECDAA_SIGNATURE_BN254_H
#define ECDAA_SIGNATURE_BN254_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/big_256_56.h>
#include <amcl/ecp_BN254.h>

struct ecdaa_credential_BN254;
struct ecdaa_member_secret_key_BN254;
struct ecdaa_revocation_list_BN254;
struct ecdaa_group_public_key_BN254;

/*
 * ECDAA signature.
 */
struct ecdaa_signature_BN254 {
    BIG_256_56 c;
    BIG_256_56 s;
    ECP_BN254 R;
    ECP_BN254 S;
    ECP_BN254 T;
    ECP_BN254 W;
};

#define ECDAA_SIGNATURE_BN254_LENGTH (2*MODBYTES_256_56 + 4*(2*MODBYTES_256_56 + 1))
size_t ecdaa_signature_BN254_length(void);
/*
 * Create an ECDAA signature.
 *
 * Returns:
 * 0 on success
 * -1 if unable to create signature
 */
int ecdaa_signature_BN254_sign(struct ecdaa_signature_BN254 *signature_out,
                               const uint8_t* message,
                               uint32_t message_len,
                               struct ecdaa_member_secret_key_BN254 *sk,
                               struct ecdaa_credential_BN254 *cred,
                               csprng *rng);

/*
 * Verify an ECDAA signature.
 *
 * Returns:
 * 0 on success
 * -1 if signature is invalid
 */
int ecdaa_signature_BN254_verify(struct ecdaa_signature_BN254 *signature,
                                 struct ecdaa_group_public_key_BN254 *gpk,
                                 struct ecdaa_revocation_list_BN254 *sk_rev_list,
                                 uint8_t* message,
                                 uint32_t message_len);


/*
 * Serialize an `ecdaa_signature_BN254`
 *
 * The serialized format is:
 *  ( c | s |
 *    0x04 | R.x-coord | R.y-coord |
 *    0x04 | S.x-coord | S.y-coord |
 *    0x04 | T.x-coord | T.y-coord |
 *    0x04 | W.x-coord | W.y-coord )
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_signature_BN254_serialize(uint8_t *buffer_out,
                                     struct ecdaa_signature_BN254 *signature);

/*
 * De-serialize an `ecdaa_signature_BN254`, but _don't_ verify it.
 *
 * The serialized format is expected to be:
 *  ( c | s |
 *    0x04 | R.x-coord | R.y-coord |
 *    0x04 | S.x-coord | S.y-coord |
 *    0x04 | T.x-coord | T.y-coord |
 *    0x04 | W.x-coord | W.y-coord )
 *
 *  NOTE: The four G1 points are checked as being on the curve,
 *      but not for membership in the group.
 *
 * Returns:
 * 0 on success
 * -1 if signature is mal-formed
 */
int ecdaa_signature_BN254_deserialize(struct ecdaa_signature_BN254 *signature_out,
                                      uint8_t *buffer_in);

/*
 * De-serialize an `ecdaa_signature_BN254`, and the message it's over, and verify the signature.
 *
 * The serialized format is expected to be:
 *  ( c | s |
 *    0x04 | R.x-coord | R.y-coord |
 *    0x04 | S.x-coord | S.y-coord |
 *    0x04 | T.x-coord | T.y-coord |
 *    0x04 | W.x-coord | W.y-coord )
 *
 * Returns:
 * 0 on success
 * -1 if signature is mal-formed
 *  -2 if signature is not valid
 */
int ecdaa_signature_BN254_deserialize_and_verify(struct ecdaa_signature_BN254 *signature_out,
                                                 struct ecdaa_group_public_key_BN254 *gpk,
                                                 struct ecdaa_revocation_list_BN254 *sk_rev_list,
                                                 uint8_t *signature_buffer,
                                                 uint8_t* message_buffer,
                                                 uint32_t message_len);

#ifdef __cplusplus
}
#endif

#endif
