/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
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

#include "verify_ZZZ.h"

#include <ecdaa.h>

#define MAX_MESSAGE_SIZE 1024

static
int parse_sk_rev_list_file(struct ecdaa_revocations_ZZZ *rev_list_out, const char *filename, unsigned num_revs);

static
int parse_bsn_rev_list_file(struct ecdaa_revocations_ZZZ *revocations_out, const char *filename, unsigned num_revs);

int verify_ZZZ(const char *message_file, const char *sig_file, const char *gpk_file, const char *sk_rev_list_file,
                const char *sk_revs, const char *bsn_rev_list_file, const char *bsn_revs, const char *basename_file)
{
    int ret = SUCCESS;

    uint8_t buffer[1024];

    int number_of_sk_revs = atoi(sk_revs);
    int number_of_bsn_revs = atoi(bsn_revs);

    struct ecdaa_revocations_ZZZ revocations;
    revocations.sk_list = NULL;
    revocations.bsn_list = NULL;


    // Read basename file (if requested)
    uint8_t *basename = NULL;
    uint32_t basename_len = 0;
    uint8_t basename_buffer[MAX_MESSAGE_SIZE];
    if (NULL != basename_file) {
        basename = basename_buffer;

        int read_ret = ecdaa_read_from_file(basename_buffer, sizeof(basename_buffer), basename_file);
        if (read_ret < 0) {
            return READ_FROM_FILE_ERROR;
        }
        basename_len = (uint32_t)read_ret;
    }

    // Read signature from disk
    int has_nym = basename_len != 0;
    uint32_t sig_length;
    if (has_nym) {
        sig_length = ECDAA_SIGNATURE_ZZZ_WITH_NYM_LENGTH;
    } else {
        sig_length = ECDAA_SIGNATURE_ZZZ_LENGTH;
    }
    struct ecdaa_signature_ZZZ sig;
    if ((int)sig_length != ecdaa_read_from_file(buffer, sig_length, sig_file)) {
        ret = READ_FROM_FILE_ERROR;
        goto cleanup;
    }
    if (0 != ecdaa_signature_ZZZ_deserialize(&sig, buffer, has_nym)) {
        ret = DESERIALIZE_KEY_ERROR;
        goto cleanup;
    }

    // Read group public key from disk
    struct ecdaa_group_public_key_ZZZ gpk;
    if (ECDAA_GROUP_PUBLIC_KEY_ZZZ_LENGTH != ecdaa_read_from_file(buffer, ECDAA_GROUP_PUBLIC_KEY_ZZZ_LENGTH, gpk_file)) {
        ret = READ_FROM_FILE_ERROR;
        goto cleanup;
    }
    if (0 != ecdaa_group_public_key_ZZZ_deserialize(&gpk, buffer)) {
        ret = DESERIALIZE_KEY_ERROR;
        goto cleanup;
    }

    // Read in sk_rev_list from disk.
    if (0 != parse_sk_rev_list_file(&revocations, sk_rev_list_file, number_of_sk_revs)) {
        ret = PARSE_REVOC_LIST_ERROR;
        goto cleanup;
    }

    // Read in bsn_rev_list from disk.
    if (0 != parse_bsn_rev_list_file(&revocations, bsn_rev_list_file, number_of_bsn_revs)) {
        ret = PARSE_REVOC_LIST_ERROR;
        goto cleanup;
    }

    // Read message from disk.
    uint8_t message[MAX_MESSAGE_SIZE];
    int read_ret = ecdaa_read_from_file(message, sizeof(message), message_file);
    if (read_ret < 0) {
        ret = READ_FROM_FILE_ERROR;
        goto cleanup;
    }
    uint32_t msg_len = (uint32_t)read_ret;

    // Verify signature
    if (0 != ecdaa_signature_ZZZ_verify(&sig, &gpk, &revocations, message, msg_len, basename, basename_len)) {
        ret = VERIFY_ERROR;
        goto cleanup;
    }

cleanup:
    if (NULL != revocations.sk_list) {
        free(revocations.sk_list);
    }
    if (NULL != revocations.bsn_list) {
        free(revocations.bsn_list);
    }

    return ret;
}


int parse_sk_rev_list_file(struct ecdaa_revocations_ZZZ *revocations_out, const char *filename, unsigned num_revs)
{
    int ret = 0;

    revocations_out->sk_list = NULL;
    revocations_out->sk_length = 0;

    if (NULL != filename && num_revs != 0) {
        // Allocate a buffer to hold the full file.
        size_t file_length = num_revs * ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH;
        uint8_t *buffer = malloc(file_length);
        if (NULL == buffer) {
            ret = 1;
            goto cleanup;
        }

        // Allocate the revocation list array.
        revocations_out->sk_list = malloc(num_revs * sizeof(struct ecdaa_member_secret_key_ZZZ));
        if (NULL == revocations_out->sk_list) {
            ret = 1;
            goto cleanup;
        }

        // Read the revocation list in from disk.
        int read_ret = ecdaa_read_from_file(buffer, file_length, filename);
        if (read_ret < 0 || file_length != (size_t)read_ret) {
            ret = 1;
            goto cleanup;
        }

        // Deserialize each secret key and add it to the list.
        for (unsigned i = 0; i < num_revs; i++) {
            int deserial_ret = ecdaa_member_secret_key_ZZZ_deserialize(&revocations_out->sk_list[i],
                                                                         buffer + i*ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH);
            revocations_out->sk_length++;
            if (0 != deserial_ret) {
                ret = 1;
                goto cleanup;
            }
        }

cleanup:
        if (NULL != buffer)
            free(buffer);

        if (0 != ret) {
            if (NULL != revocations_out->sk_list)
                free(revocations_out->sk_list);

            revocations_out->sk_list = NULL;
            revocations_out->sk_length = 0;
        }
    }

    return ret;
}

int parse_bsn_rev_list_file(struct ecdaa_revocations_ZZZ *revocations_out, const char *filename, unsigned num_revs)
{
    int ret = 0;

    revocations_out->bsn_list = NULL;
    revocations_out->bsn_length = 0;

    size_t point_size = (2*MODBYTES_XXX + 1);

    if (NULL != filename && num_revs != 0) {
        // Allocate a buffer to hold the full file.
        size_t file_length = num_revs * point_size;
        uint8_t *buffer = malloc(file_length);
        if (NULL == buffer) {
            ret = 1;
            goto cleanup;
        }

        // Allocate the revocation list array.
        revocations_out->bsn_list = malloc(num_revs * sizeof(ECP_ZZZ));
        if (NULL == revocations_out->bsn_list) {
            ret = 1;
            goto cleanup;
        }

        // Read the revocation list in from disk.
        int read_ret = ecdaa_read_from_file(buffer, file_length, filename);
        if (read_ret < 0 || file_length != (size_t)read_ret) {
            ret = 1;
            goto cleanup;
        }

        // Deserialize each basename signature and add it to the list.
        for (unsigned i = 0; i < num_revs; i++) {
            BIG_XXX wx, wy;
            BIG_XXX_fromBytes(wx, (char*)&(buffer[1 + i*point_size]));
            BIG_XXX_fromBytes(wy, (char*)&(buffer[1 + MODBYTES_XXX + i*point_size]));
            // Nb. This does NOT check that the point is in the proper group.
            if (!ECP_ZZZ_set(&revocations_out->bsn_list[i], wx, wy)) {
                ret = -1;
                goto cleanup;
            }
            revocations_out->bsn_length++;
        }

cleanup:
        if (NULL != buffer)
            free(buffer);

        if (0 != ret) {
            if (NULL != revocations_out->bsn_list)
                free(revocations_out->bsn_list);

            revocations_out->bsn_list = NULL;
            revocations_out->bsn_length = 0;
        }
    }

    return ret;
}
