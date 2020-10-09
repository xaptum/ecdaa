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
#include <ecdaa/revocations_ZZZ.h>
#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/util/errors.h>
#include <ecdaa/util/file_io.h>

#include "schnorr/schnorr_ZZZ.h"
#include "amcl-extensions/big_XXX.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"
#include "amcl-extensions/pairing_ZZZ.h"

#include <amcl/pair_ZZZ.h>
#include <amcl/fp12_ZZZ.h>

static
void randomize_credential_ZZZ(struct ecdaa_credential_ZZZ *cred,
                              ecdaa_rand_func get_random,
                              struct ecdaa_signature_ZZZ *signature_out);

size_t ecdaa_signature_ZZZ_length(void)
{
    return ECDAA_SIGNATURE_ZZZ_LENGTH;
}

size_t ecdaa_signature_ZZZ_with_nym_length(void)
{
    return ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH;
}

int ecdaa_signature_ZZZ_sign(struct ecdaa_signature_ZZZ *signature_out,
                             const uint8_t* message,
                             uint32_t message_len,
                             const uint8_t* basename,
                             uint32_t basename_len,
                             struct ecdaa_member_secret_key_ZZZ *sk,
                             struct ecdaa_credential_ZZZ *cred,
                             ecdaa_rand_func get_random)
{
    // 1) Randomize credential
    randomize_credential_ZZZ(cred, get_random, signature_out);

    // 2) Create a Schnorr-like signature on W concatenated with the message,
    //  where the basepoint is S.
    int sign_ret = schnorr_sign_ZZZ(&signature_out->c,
                                    &signature_out->s,
                                    &signature_out->n,
                                    &signature_out->K,
                                    message,
                                    message_len,
                                    &signature_out->S,
                                    &signature_out->W,
                                    sk->sk,
                                    basename,
                                    basename_len,
                                    get_random);

    return sign_ret;
}

int ecdaa_signature_ZZZ_verify(struct ecdaa_signature_ZZZ *signature,
                               struct ecdaa_group_public_key_ZZZ *gpk,
                               struct ecdaa_revocations_ZZZ *revocations,
                               uint8_t* message,
                               uint32_t message_len,
                               uint8_t *basename,
                               uint32_t basename_len)
{
    int ret = 0;

    // 1) Check R,S,T,W for membership in group, and R and S for !=inf
    // NOTE: We assume the signature was obtained from a call to `deserialize`,
    //  which already checked the validity of the points R,S,T,W

    // 2) Check Schnorr-type signature
    int schnorr_ret = schnorr_verify_ZZZ(signature->c,
                                         signature->s,
                                         signature->n,
                                         &signature->K,
                                         message,
                                         message_len,
                                         &signature->S,
                                         &signature->W,
                                         basename,
                                         basename_len);
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
    for (size_t i = 0; i < revocations->sk_length; ++i) {
        ECP_ZZZ_copy(&Wcheck, &signature->S);
        ECP_ZZZ_mul(&Wcheck, revocations->sk_list[i].sk);
        if (ECP_ZZZ_equals(&Wcheck, &signature->W))
            ret = -1;
    }

    // 7) Check K against bsn_revocation_list
    for (size_t i = 0; i < revocations->bsn_length; ++i) {
        if (ECP_ZZZ_equals(&revocations->bsn_list[i], &signature->K))
            ret = -1;
    }

    return ret;
}

void ecdaa_signature_ZZZ_serialize(uint8_t *buffer_out,
                                   struct ecdaa_signature_ZZZ *signature,
                                   int has_nym)
{
    BIG_XXX_toBytes((char*)buffer_out, signature->c);
    BIG_XXX_toBytes((char*)(buffer_out + MODBYTES_XXX), signature->s);

    ecp_ZZZ_serialize(buffer_out + 2*MODBYTES_XXX, &signature->R);
    ecp_ZZZ_serialize(buffer_out + 2*MODBYTES_XXX + ECP_ZZZ_LENGTH, &signature->S);
    ecp_ZZZ_serialize(buffer_out + 2*MODBYTES_XXX + 2*ECP_ZZZ_LENGTH, &signature->T);
    ecp_ZZZ_serialize(buffer_out + 2*MODBYTES_XXX + 3*ECP_ZZZ_LENGTH, &signature->W);

    BIG_XXX_toBytes((char*)(buffer_out + 2*MODBYTES_XXX + 4*ECP_ZZZ_LENGTH), signature->n);

    if (has_nym) {
        ecp_ZZZ_serialize(buffer_out + 3*MODBYTES_XXX + 4*ECP_ZZZ_LENGTH, &signature->K);
    }
}

int ecdaa_signature_ZZZ_serialize_file(const char* file,
                                   struct ecdaa_signature_ZZZ *signature,
                                   int has_nym)
{
    uint8_t buffer[ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH];
    uint32_t sig_length = 0;
    if (has_nym) {
        sig_length = ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH;
    } else {
        sig_length = ECDAA_SIGNATURE_ZZZ_LENGTH;
    }
    ecdaa_signature_ZZZ_serialize(buffer, signature, has_nym);
    int write_ret = ecdaa_write_buffer_to_file(file, buffer, sig_length);
    if ((int)sig_length != write_ret) {
        return write_ret;
    }

    return SUCCESS;
}

int ecdaa_signature_ZZZ_serialize_fp(FILE* fp,
                                   struct ecdaa_signature_ZZZ *signature,
                                   int has_nym)
{
    uint8_t buffer[ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH];
    uint32_t sig_length = 0;
    if (has_nym) {
        sig_length = ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH;
    } else {
        sig_length = ECDAA_SIGNATURE_ZZZ_LENGTH;
    }
    ecdaa_signature_ZZZ_serialize(buffer, signature, has_nym);
    int write_ret = ecdaa_write_buffer_to_fp(fp, buffer, sig_length);
    if ((int)sig_length != write_ret) {
        return write_ret;
    }

    return SUCCESS;
}

int ecdaa_signature_ZZZ_deserialize(struct ecdaa_signature_ZZZ *signature_out,
                                    uint8_t *buffer_in,
                                    int has_nym)
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

    BIG_XXX_fromBytes(signature_out->n, (char*)(buffer_in + 2*MODBYTES_XXX + 4*ECP_ZZZ_LENGTH));

    if (has_nym) {
        if (0 != ecp_ZZZ_deserialize(&signature_out->K, buffer_in + 3*MODBYTES_XXX + 4*ECP_ZZZ_LENGTH))
            ret = -1;
    } else {
        ecp_ZZZ_set_to_generator(&signature_out->K);
    }

    return ret;
}

int ecdaa_signature_ZZZ_deserialize_file(struct ecdaa_signature_ZZZ *signature_out,
                                        const char *file,
                                        int has_nym)
{
    uint8_t buffer[ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH];
    uint32_t sig_length = 0;
    if (has_nym) {
        sig_length = ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH;
    } else {
        sig_length = ECDAA_SIGNATURE_ZZZ_LENGTH;
    }
    int read_ret = ecdaa_read_from_file(buffer, sig_length, file);
    if ((int)sig_length != read_ret) {
        return read_ret;
    }
    int ret = ecdaa_signature_ZZZ_deserialize(signature_out, buffer, has_nym);
    if (0 != ret) {
        return DESERIALIZE_KEY_ERROR;
    }

    return SUCCESS;
}

int ecdaa_signature_ZZZ_deserialize_fp(struct ecdaa_signature_ZZZ *signature_out,
                                        FILE *fp,
                                        int has_nym)
{
    uint8_t buffer[ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH];
    uint32_t sig_length = 0;
    if (has_nym) {
        sig_length = ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH;
    } else {
        sig_length = ECDAA_SIGNATURE_ZZZ_LENGTH;
    }
    int read_ret = ecdaa_read_from_fp(buffer, sig_length, fp);
    if ((int)sig_length != read_ret) {
        return read_ret;
    }
    int ret = ecdaa_signature_ZZZ_deserialize(signature_out, buffer, has_nym);
    if (0 != ret) {
        return DESERIALIZE_KEY_ERROR;
    }

    return SUCCESS;
}

int ecdaa_signature_ZZZ_deserialize_and_verify(struct ecdaa_signature_ZZZ *signature_out,
                                               struct ecdaa_group_public_key_ZZZ *gpk,
                                               struct ecdaa_revocations_ZZZ *revocations,
                                               uint8_t *signature_buffer,
                                               uint8_t* message_buffer,
                                               uint32_t message_len,
                                               uint8_t *basename,
                                               uint32_t basename_len,
                                               int has_nym)
{
    int ret = 0;

    // 1) De-serialize the signature
    ret = ecdaa_signature_ZZZ_deserialize(signature_out, signature_buffer, has_nym);

    // 2) Verify the signature
    if (0 == ret) {
        int valid_ret = ecdaa_signature_ZZZ_verify(signature_out, gpk, revocations, message_buffer, message_len, basename, basename_len);
        if (0 != valid_ret)
            ret = -2;
    }

    return ret;
}

void ecdaa_signature_ZZZ_get_pseudonym(ECP_ZZZ *pseudonym_out,
                                       struct ecdaa_signature_ZZZ *signature_in)
{
    ECP_ZZZ_copy(pseudonym_out, &signature_in->K);
}

void ecdaa_signature_ZZZ_access_pseudonym_in_serialized(uint8_t **pseudonym_out,
                                                        uint32_t *pseudonym_length_out,
                                                        uint8_t *signature_in)
{
    *pseudonym_out = signature_in + 3*MODBYTES_XXX + 4*ECP_ZZZ_LENGTH;

    *pseudonym_length_out = ECP_ZZZ_LENGTH;
}

void randomize_credential_ZZZ(struct ecdaa_credential_ZZZ *cred,
                              ecdaa_rand_func get_random,
                              struct ecdaa_signature_ZZZ *signature_out)
{
    // 1) Choose random l <- Z_p
    BIG_XXX l;
    ecp_ZZZ_random_mod_order(&l, get_random);

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

    // Clear sensitive intermediate memory.
    BIG_XXX_zero(l);
}
