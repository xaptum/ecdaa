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

#include <xaptum-ecdaa/issuer.h>

#include <xaptum-ecdaa/issuer_nonce.h>

#include <amcl/amcl.h>

int ecdaa_construct_issuer(ecdaa_issuer_t *issuer_out,
                           uint8_t *seed,
                           uint32_t seed_length)
{
    // TODO
    if (NULL == issuer_out || NULL == seed || 0 == seed_length)
        return -1;

    return 0;
}

int ecdaa_process_join_request(struct ecdaa_credential_t *credential_out,
                               struct ecdaa_credential_signature_t *credential_signature_out,
                               struct ecdaa_member_public_key_t *member_pk,
                               ecdaa_issuer_t *issuer)
{
    // TODO
    if (NULL == credential_out || NULL == credential_signature_out || NULL == member_pk || NULL == issuer)
        return -1;

    return 0;
}

void ecdaa_generate_issuer_nonce(ecdaa_issuer_nonce_t *nonce_out,
                                 ecdaa_issuer_t *issuer)
{
    for (size_t i = 0; i < sizeof(ecdaa_issuer_nonce_t); ++i)
        nonce_out->data[i] = RAND_byte(&issuer->rng);
}
