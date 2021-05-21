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

#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/util/file_io.h>
#include <ecdaa/util/errors.h>

#include "schnorr/schnorr_ZZZ.h"
#include "internal-utilities/explicit_bzero.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"
#include "amcl-extensions/pairing_ZZZ.h"

#include <ecdaa/member_keypair_ZZZ.h>
#include <ecdaa/issuer_keypair_ZZZ.h>
#include <ecdaa/group_public_key_ZZZ.h>

size_t ecdaa_credential_ZZZ_length(void)
{
    return ECDAA_CREDENTIAL_ZZZ_LENGTH;
}

size_t ecdaa_credential_ZZZ_signature_length(void)
{
    return ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH;
}

int ecdaa_credential_ZZZ_generate(struct ecdaa_credential_ZZZ *cred,
                                  struct ecdaa_credential_ZZZ_signature *cred_sig_out,
                                  struct ecdaa_issuer_secret_key_ZZZ *isk,
                                  struct ecdaa_member_public_key_ZZZ *member_pk,
                                  ecdaa_rand_func get_random)
{
    int ret = 0;

    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);

    // 1) Choose random l <- Z_p
    BIG_XXX l;
    ecp_ZZZ_random_mod_order(&l, get_random);

    // 2) Multiply generator by l and save to cred->A (A = l*P)
    ecp_ZZZ_set_to_generator(&cred->A);
    ECP_ZZZ_mul(&cred->A, l);

    // 3) Multiply A by my secret y and save to cred->B (B = y*A)
    ECP_ZZZ_copy(&cred->B, &cred->A);
    ECP_ZZZ_mul(&cred->B, isk->y);

    // 4) Mod-multiply l and y
    BIG_XXX ly;
    BIG_XXX_modmul(ly, l, isk->y, curve_order);

    // 5) Multiply member's public_key by ly and save to cred->D (D = ly*Q)
    ECP_ZZZ_copy(&cred->D, &member_pk->Q);
    ECP_ZZZ_mul(&cred->D, ly);

    // 6) Multiply A by my secret x (store in cred->C temporarily)
    ECP_ZZZ_copy(&cred->C, &cred->A);
    ECP_ZZZ_mul(&cred->C, isk->x);

    // 7) Mod-multiply ly (see step 4) by my secret x
    BIG_XXX xyl;
    BIG_XXX_modmul(xyl, ly, isk->x, curve_order);

    // 8) Multiply member's public_key by xyl
    ECP_ZZZ Qxyl;
    ECP_ZZZ_copy(&Qxyl, &member_pk->Q);
    ECP_ZZZ_mul(&Qxyl, xyl);

    // 9) Add Ax and xyl*Q and save to cred->C (C = x*A + xyl*Q)
    //      Nb. Add doesn't convert to affine, so do that explicitly
    ECP_ZZZ_add(&cred->C, &Qxyl);
    ECP_ZZZ_affine(&cred->C);

    // 10) Perform a Schnorr-like signature,
    //  to prove the credential was properly constructed by someone with knowledge of y.
    int schnorr_ret = credential_schnorr_sign_ZZZ(&cred_sig_out->c,
                                                  &cred_sig_out->s,
                                                  &cred->B,
                                                  &member_pk->Q,
                                                  &cred->D,
                                                  isk->y,
                                                  l,
                                                  get_random);
    if (0 != schnorr_ret)
        ret = -1;

    // Clear sensitive intermediate memory
    explicit_bzero(&l, sizeof(BIG_XXX));

    return ret;
}

int ecdaa_credential_ZZZ_validate(struct ecdaa_credential_ZZZ *credential,
                                  struct ecdaa_credential_ZZZ_signature *credential_signature,
                                  struct ecdaa_member_public_key_ZZZ *member_pk,
                                  struct ecdaa_group_public_key_ZZZ *gpk)
{
    int ret = 0;

    // 1) Check A,B,C,D for membership in group, and A for !=inf
    // NOTE: We assume the credential was obtained from a call to `deserialize`,
    //  which already checked the validity of the points A,B,C,D

    // 2) Verify schnorr-like signature
    int schnorr_ret = credential_schnorr_verify_ZZZ(credential_signature->c,
                                                    credential_signature->s,
                                                    &credential->B,
                                                    &member_pk->Q,
                                                    &credential->D);
    if (0 != schnorr_ret)
        ret = -1;

    ECP2_ZZZ basepoint2;
    ecp2_ZZZ_set_to_generator(&basepoint2);

    // 3) Check e(A, Y) == e(B, P_2)
    FP12_YYY pairing_one;
    FP12_YYY pairing_one_prime;
    compute_pairing_ZZZ(&pairing_one, &credential->A, &gpk->Y);
    compute_pairing_ZZZ(&pairing_one_prime, &credential->B, &basepoint2);
    if (!FP12_YYY_equals(&pairing_one, &pairing_one_prime))
        ret = -1;

    // 4) Compute A+D
    //      Nb. Add doesn't convert to affine, so do that explicitly
    ECP_ZZZ AD;
    ECP_ZZZ_copy(&AD, &credential->A);
    ECP_ZZZ_add(&AD, &credential->D);
    ECP_ZZZ_affine(&AD);

    // 5) Check e(C, P_2) == e(A+D, X)
    FP12_YYY pairing_two;
    FP12_YYY pairing_two_prime;
    compute_pairing_ZZZ(&pairing_two, &credential->C, &basepoint2);
    compute_pairing_ZZZ(&pairing_two_prime, &AD, &gpk->X);
    if (!FP12_YYY_equals(&pairing_two, &pairing_two_prime))
        ret = -1;

    return ret;
}

void ecdaa_credential_ZZZ_serialize(uint8_t *buffer_out,
                                    struct ecdaa_credential_ZZZ *credential)
{
    ecp_ZZZ_serialize(buffer_out, &credential->A);
    ecp_ZZZ_serialize(buffer_out + ECP_ZZZ_LENGTH, &credential->B);
    ecp_ZZZ_serialize(buffer_out + 2*ECP_ZZZ_LENGTH, &credential->C);
    ecp_ZZZ_serialize(buffer_out + 3*ECP_ZZZ_LENGTH, &credential->D);
}

int ecdaa_credential_ZZZ_serialize_file(const char* file,
                                    struct ecdaa_credential_ZZZ *credential)
{
    uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH] = {0};
    ecdaa_credential_ZZZ_serialize(buffer, credential);
    int write_ret = ecdaa_write_buffer_to_file(file, buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH);
    if (ECDAA_CREDENTIAL_ZZZ_LENGTH != write_ret) {
        return write_ret;
    }
    return SUCCESS;
}

int ecdaa_credential_ZZZ_serialize_fp(FILE* fp,
                                    struct ecdaa_credential_ZZZ *credential)
{
    uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH] = {0};
    ecdaa_credential_ZZZ_serialize(buffer, credential);
    int write_ret = ecdaa_write_buffer_to_fp(fp, buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH);
    if (ECDAA_CREDENTIAL_ZZZ_LENGTH != write_ret) {
        return write_ret;
    }
    return SUCCESS;
}

void ecdaa_credential_ZZZ_signature_serialize(uint8_t *buffer_out,
                                              struct ecdaa_credential_ZZZ_signature *cred_sig)
{
    BIG_XXX_toBytes((char*)buffer_out, cred_sig->c);
    BIG_XXX_toBytes((char*)(buffer_out + MODBYTES_XXX), cred_sig->s);
}

int ecdaa_credential_ZZZ_signature_serialize_file(const char* file,
                                              struct ecdaa_credential_ZZZ_signature *cred_sig)
{
    uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH] = {0};
    ecdaa_credential_ZZZ_signature_serialize(buffer, cred_sig);
    int write_ret = ecdaa_write_buffer_to_file(file, buffer, ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH);
    if (ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH != write_ret) {
        return write_ret;
    }
    return SUCCESS;
}

int ecdaa_credential_ZZZ_signature_serialize_fp(FILE* fp,
                                              struct ecdaa_credential_ZZZ_signature *cred_sig)
{
    uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH] = {0};
    ecdaa_credential_ZZZ_signature_serialize(buffer, cred_sig);
    int write_ret = ecdaa_write_buffer_to_fp(fp, buffer, ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH);
    if (ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH != write_ret) {
        return write_ret;
    }
    return SUCCESS;
}

int ecdaa_credential_ZZZ_deserialize_with_signature(struct ecdaa_credential_ZZZ *credential_out,
                                                    struct ecdaa_member_public_key_ZZZ *member_pk,
                                                    struct ecdaa_group_public_key_ZZZ *gpk,
                                                    uint8_t *cred_buffer_in,
                                                    uint8_t *cred_sig_buffer_in)
{
    int ret = 0;

    // 1) De-serialize the credential
    ret = ecdaa_credential_ZZZ_deserialize(credential_out, cred_buffer_in);

    // 2) De-serialize the credential signature
    struct ecdaa_credential_ZZZ_signature cred_sig;
    BIG_XXX_fromBytes(cred_sig.c, (char*)(cred_sig_buffer_in));
    BIG_XXX_fromBytes(cred_sig.s, (char*)(cred_sig_buffer_in + MODBYTES_XXX));

    if (0 == ret) {
        int valid_ret = ecdaa_credential_ZZZ_validate(credential_out, &cred_sig, member_pk, gpk);
        if (0 != valid_ret)
            ret = -2;
    }

    return ret;
}

int ecdaa_credential_ZZZ_deserialize_with_signature_file(struct ecdaa_credential_ZZZ *credential_out,
                                                    struct ecdaa_member_public_key_ZZZ *pk,
                                                    struct ecdaa_group_public_key_ZZZ *gpk,
                                                    const char *credential_file,
                                                    const char *credential_signature_file)
{
    uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH + ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH] = {0};
    int read_ret = ecdaa_read_from_file(buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH, credential_file);
    if (ECDAA_CREDENTIAL_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }
    read_ret = ecdaa_read_from_file(buffer + ECDAA_CREDENTIAL_ZZZ_LENGTH,
                                    ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH,
                                    credential_signature_file);
    if (ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH != read_ret) {
        return read_ret;
    }
    int deserialize_ret = ecdaa_credential_ZZZ_deserialize_with_signature(credential_out, pk, gpk, buffer, buffer + ECDAA_CREDENTIAL_ZZZ_LENGTH);
    if (0 != deserialize_ret) {
        return DESERIALIZE_KEY_ERROR;
    }

    return SUCCESS;
}

int ecdaa_credential_ZZZ_deserialize_with_signature_fp(struct ecdaa_credential_ZZZ *credential_out,
                                                    struct ecdaa_member_public_key_ZZZ *pk,
                                                    struct ecdaa_group_public_key_ZZZ *gpk,
                                                    FILE *credential_file,
                                                    FILE *credential_signature_file)
{
    uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH + ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH] = {0};
    int read_ret = ecdaa_read_from_fp(buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH, credential_file);
    if (ECDAA_CREDENTIAL_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }
    read_ret = ecdaa_read_from_fp(buffer + ECDAA_CREDENTIAL_ZZZ_LENGTH,
                                    ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH,
                                    credential_signature_file);
    if (ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH != read_ret) {
        return read_ret;
    }
    int deserialize_ret = ecdaa_credential_ZZZ_deserialize_with_signature(credential_out, pk, gpk, buffer, buffer + ECDAA_CREDENTIAL_ZZZ_LENGTH);
    if (0 != deserialize_ret) {
        return DESERIALIZE_KEY_ERROR;
    }

    return SUCCESS;
}

int ecdaa_credential_ZZZ_deserialize(struct ecdaa_credential_ZZZ *credential_out,
                                     uint8_t *buffer_in)
{
    int ret = 0;

    if (0 != ecp_ZZZ_deserialize(&credential_out->A, buffer_in))
        ret = -1;

    if (0 != ecp_ZZZ_deserialize(&credential_out->B, buffer_in + ECP_ZZZ_LENGTH))
        ret = -1;

    if (0 != ecp_ZZZ_deserialize(&credential_out->C, buffer_in + 2*ECP_ZZZ_LENGTH))
        ret = -1;

    if (0 != ecp_ZZZ_deserialize(&credential_out->D, buffer_in + 3*ECP_ZZZ_LENGTH))
        ret = -1;

    return ret;
}

int ecdaa_credential_ZZZ_deserialize_file(struct ecdaa_credential_ZZZ *credential_out,
                                     const char* file)
{
    uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH] = {0};
    int read_ret = ecdaa_read_from_file(buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH, file);
    if (ECDAA_CREDENTIAL_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }
    int ret = ecdaa_credential_ZZZ_deserialize(credential_out, buffer);
    if (0 != ret) {
        return DESERIALIZE_KEY_ERROR;
    }
    return SUCCESS;
}

int ecdaa_credential_ZZZ_deserialize_fp(struct ecdaa_credential_ZZZ *credential_out,
                                     FILE* fp)
{
    uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH] = {0};
    int read_ret = ecdaa_read_from_fp(buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH, fp);
    if (ECDAA_CREDENTIAL_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }
    int ret = ecdaa_credential_ZZZ_deserialize(credential_out, buffer);
    if (0 != ret) {
        return DESERIALIZE_KEY_ERROR;
    }
    return SUCCESS;
}
