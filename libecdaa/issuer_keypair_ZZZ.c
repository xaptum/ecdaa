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

#include <ecdaa/issuer_keypair_ZZZ.h>
#include <ecdaa/util/file_io.h>
#include <ecdaa/util/errors.h>

#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"
#include "schnorr/schnorr_ZZZ.h"

#include <ecdaa/group_public_key_ZZZ.h>

size_t ecdaa_issuer_public_key_ZZZ_length(void) {
    return ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH;
}

size_t ecdaa_issuer_secret_key_ZZZ_length(void) {
    return ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH;
}

int ecdaa_issuer_key_pair_ZZZ_generate(struct ecdaa_issuer_public_key_ZZZ *pk,
                                       struct ecdaa_issuer_secret_key_ZZZ *sk,
                                       ecdaa_rand_func get_random)
{
    // Secret key is
    // two random Bignums.
    ecp_ZZZ_random_mod_order(&sk->x, get_random);
    ecp_ZZZ_random_mod_order(&sk->y, get_random);

    // Public key is
    // 1) G2 generator raised to the two private key random Bignums...
    ecp2_ZZZ_set_to_generator(&pk->gpk.X);
    ecp2_ZZZ_set_to_generator(&pk->gpk.Y);
    ECP2_ZZZ_mul(&pk->gpk.X, sk->x);
    ECP2_ZZZ_mul(&pk->gpk.Y, sk->y);

    // 2) and a Schnorr-type signature to prove our knowledge of those two random Bignums.
    int sign_ret = issuer_schnorr_sign_ZZZ(&pk->c, &pk->sx, &pk->sy, &pk->gpk.X, &pk->gpk.Y, sk->x, sk->y, get_random);
    if (0 != sign_ret)
        return -1;

    return 0;
}

int ecdaa_issuer_public_key_ZZZ_validate(struct ecdaa_issuer_public_key_ZZZ *ipk)
{
    int ret = 0;

    int schnorr_ret = issuer_schnorr_verify_ZZZ(ipk->c, ipk->sx, ipk->sy, &ipk->gpk.X, &ipk->gpk.Y);
    if (0 != schnorr_ret)
        ret = -1;

    return ret;
}

void ecdaa_issuer_public_key_ZZZ_serialize(uint8_t *buffer_out,
                                           struct ecdaa_issuer_public_key_ZZZ *ipk)
{
    ecdaa_group_public_key_ZZZ_serialize(buffer_out, &ipk->gpk);

    BIG_XXX_toBytes((char*)(buffer_out + ecdaa_group_public_key_ZZZ_length()), ipk->c);
    BIG_XXX_toBytes((char*)(buffer_out + ecdaa_group_public_key_ZZZ_length() + MODBYTES_XXX), ipk->sx);
    BIG_XXX_toBytes((char*)(buffer_out + ecdaa_group_public_key_ZZZ_length() + 2*MODBYTES_XXX), ipk->sy);
}

int ecdaa_issuer_public_key_ZZZ_serialize_file(const char* file,
                                           struct ecdaa_issuer_public_key_ZZZ *ipk)
{
    FILE *file_ptr = fopen(file, "wb");

    if (NULL == file_ptr){
        return READ_FROM_FILE_ERROR;
    }

    int ret = ecdaa_issuer_public_key_ZZZ_serialize_fp(file_ptr, ipk);

    if (ret >= 0) {
        if (0 != fclose(file_ptr)) {
            return READ_FROM_FILE_ERROR;
        }
    }

    return ret;
}

int ecdaa_issuer_public_key_ZZZ_serialize_fp(FILE* fp,
                                           struct ecdaa_issuer_public_key_ZZZ *ipk)
{
    uint8_t buffer[ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
    ecdaa_issuer_public_key_ZZZ_serialize(buffer, ipk);

    int write_ret = ecdaa_write_buffer_to_fp(fp, buffer, ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH);
    if (ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH != write_ret) {
        return WRITE_TO_FILE_ERROR;
    }

    return SUCCESS;
}

int ecdaa_issuer_public_key_ZZZ_deserialize(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
                                            uint8_t *buffer_in)
{
    int ret = 0;

    // 1) Deserialize the gpk
    //  (This also checks gpk.X and gpk.Y for membership in G2)
    int deserial_ret = ecdaa_group_public_key_ZZZ_deserialize(&ipk_out->gpk, buffer_in);
    if (0 != deserial_ret)
        ret = -1;

    // 2) Deserialize the issuer_schnorr signature
    BIG_XXX_fromBytes(ipk_out->c, (char*)(buffer_in + ecdaa_group_public_key_ZZZ_length()));
    BIG_XXX_fromBytes(ipk_out->sx, (char*)(buffer_in + ecdaa_group_public_key_ZZZ_length() + MODBYTES_XXX));
    BIG_XXX_fromBytes(ipk_out->sy, (char*)(buffer_in + ecdaa_group_public_key_ZZZ_length() + 2*MODBYTES_XXX));

    // 3) Check the signature
    int sign_ret = ecdaa_issuer_public_key_ZZZ_validate(ipk_out);
    if (0 != sign_ret)
        ret = -2;

    return ret;
}

int ecdaa_issuer_public_key_ZZZ_deserialize_file(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
                                            const char* file)
{
    FILE *file_ptr = fopen(file, "rb");

    if (NULL == file_ptr){
        return READ_FROM_FILE_ERROR;
    }

    int ret = ecdaa_issuer_public_key_ZZZ_deserialize_fp(ipk_out, file_ptr);

    if (ret >= 0) {
        if (0 != fclose(file_ptr)) {
            return READ_FROM_FILE_ERROR;
        }
    }

    return ret;
}

int ecdaa_issuer_public_key_ZZZ_deserialize_fp(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
                                            FILE* fp)
{
    uint8_t buffer[ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH] = {0};

    int read_ret = ecdaa_read_from_fp(buffer, ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH, fp);
    if (ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH != read_ret) {
        return READ_FROM_FILE_ERROR;
    }
    int deserialize_ret = ecdaa_issuer_public_key_ZZZ_deserialize(ipk_out, buffer);
    if (0 != deserialize_ret)
        return DESERIALIZE_KEY_ERROR;

    return SUCCESS;
}

void ecdaa_issuer_secret_key_ZZZ_serialize(uint8_t *buffer_out,
                                           struct ecdaa_issuer_secret_key_ZZZ *isk)
{
    BIG_XXX_toBytes((char*)buffer_out, isk->x);
    BIG_XXX_toBytes((char*)(buffer_out + MODBYTES_XXX), isk->y);
}

int ecdaa_issuer_secret_key_ZZZ_serialize_file(const char* file, struct ecdaa_issuer_secret_key_ZZZ *isk)
{
    FILE *file_ptr = fopen(file, "wb");

    if (NULL == file_ptr){
        return READ_FROM_FILE_ERROR;
    }

    int ret = ecdaa_issuer_secret_key_ZZZ_serialize_fp(file_ptr, isk);

    if (ret >= 0) {
        if (0 != fclose(file_ptr)) {
            return READ_FROM_FILE_ERROR;
        }
    }

    return ret;
}

int ecdaa_issuer_secret_key_ZZZ_serialize_fp(FILE* fp, struct ecdaa_issuer_secret_key_ZZZ *isk)
{
    uint8_t buffer[ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH] = {0};
    ecdaa_issuer_secret_key_ZZZ_serialize(buffer, isk);
    int write_ret = ecdaa_write_buffer_to_fp(fp, buffer, ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH);
    if (ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH != write_ret) {
        return WRITE_TO_FILE_ERROR;
    }

    return SUCCESS;
}

int ecdaa_issuer_secret_key_ZZZ_deserialize(struct ecdaa_issuer_secret_key_ZZZ *isk_out,
                                            uint8_t *buffer_in)
{
    BIG_XXX_fromBytes(isk_out->x, (char*)buffer_in);
    BIG_XXX_fromBytes(isk_out->y, (char*)(buffer_in + MODBYTES_XXX));

    return 0;
}

int ecdaa_issuer_secret_key_ZZZ_deserialize_file(struct ecdaa_issuer_secret_key_ZZZ *isk_out,
                                            const char* file)
{
    FILE *file_ptr = fopen(file, "rb");

    if (NULL == file_ptr){
        return READ_FROM_FILE_ERROR;
    }

    int ret = ecdaa_issuer_secret_key_ZZZ_deserialize_fp(isk_out, file_ptr);

    if (ret >= 0) {
        if (0 != fclose(file_ptr)) {
            return READ_FROM_FILE_ERROR;
        }
    }

    return ret;
}

int ecdaa_issuer_secret_key_ZZZ_deserialize_fp(struct ecdaa_issuer_secret_key_ZZZ *isk_out,
                                            FILE* fp)
{
    uint8_t buffer[ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH] = {0};

    int read_ret = ecdaa_read_from_fp(buffer, ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH, fp);
    if (ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH != read_ret) {
        return READ_FROM_FILE_ERROR;
    }

    int deserialize_ret = ecdaa_issuer_secret_key_ZZZ_deserialize(isk_out, buffer);
    if (0 != deserialize_ret) {
        return DESERIALIZE_KEY_ERROR;
    }

    return SUCCESS;
}
