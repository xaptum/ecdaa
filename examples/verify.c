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

#include "file_utils.h"

#include <ecdaa.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_MESSAGE_SIZE 1024

struct command_line_args {
    char *message_file;
    char *sig_file;
    char *gpk_file;
    char *sk_rev_list_file;
    unsigned number_of_sk_revs;
    char *bsn_rev_list_file;
    unsigned number_of_bsn_revs;
    char *basename_file;
};

void print_usage(const char *my_name);

int parse_args(struct command_line_args *args_out, int argc, char *argv[]);

int parse_sk_rev_list_file(struct ecdaa_revocations_FP256BN *rev_list_out, const char *filename, unsigned num_revs);

int parse_bsn_rev_list_file(struct ecdaa_revocations_FP256BN *revocations_out, const char *filename, unsigned num_revs);

int main(int argc, char *argv[])
{
    int ret = 0;

    uint8_t buffer[1024];

    struct ecdaa_revocations_FP256BN revocations;
    revocations.sk_list = NULL;
    revocations.bsn_list = NULL;

    // Parse command line
    struct command_line_args args;
    if (0 != parse_args(&args, argc, argv)) {
        ret = 1;
        goto cleanup;
    }

    // Read basename file (if requested)
    uint8_t *basename = NULL;
    uint32_t basename_len = 0;
    uint8_t basename_buffer[MAX_MESSAGE_SIZE];
    if (NULL != args.basename_file) {
        basename = basename_buffer;

        int read_ret = read_file_into_buffer(basename_buffer, sizeof(basename_buffer), args.basename_file);
        if (read_ret < 0) {
            fprintf(stderr, "Error reading basename file: \"%s\"\n", args.basename_file);
            return 1;
        }
        basename_len = (uint32_t)read_ret;
    }

    // Read signature from disk
    int has_nym = basename_len != 0;
    uint32_t sig_length;
    if (has_nym) {
        sig_length = ECDAA_SIGNATURE_FP256BN_WITH_NYM_LENGTH;
    } else {
        sig_length = ECDAA_SIGNATURE_FP256BN_LENGTH;
    }
    struct ecdaa_signature_FP256BN sig;
    if ((int)sig_length != read_file_into_buffer(buffer, sig_length, args.sig_file)) {
        fprintf(stderr, "Error reading signature file: \"%s\"\n", args.sig_file);
        ret = 1;
        goto cleanup;
    }
    if (0 != ecdaa_signature_FP256BN_deserialize(&sig, buffer, has_nym)) {
        fputs("Error deserializing signature\n", stderr);
        ret = 1;
        goto cleanup;
    }

    // Read group public key from disk
    struct ecdaa_group_public_key_FP256BN gpk;
    if (ECDAA_GROUP_PUBLIC_KEY_FP256BN_LENGTH != read_file_into_buffer(buffer, ECDAA_GROUP_PUBLIC_KEY_FP256BN_LENGTH, args.gpk_file)) {
        fprintf(stderr, "Error reading group public key file: \"%s\"\n", args.gpk_file);
        ret = 1;
        goto cleanup;
    }
    if (0 != ecdaa_group_public_key_FP256BN_deserialize(&gpk, buffer)) {
        fputs("Error deserializing group public key\n", stderr);
        ret = 1;
        goto cleanup;
    }

    // Read in sk_rev_list from disk.
    if (0 != parse_sk_rev_list_file(&revocations, args.sk_rev_list_file, args.number_of_sk_revs)) {
        fputs("Error parsing secret-key revocation list file\n", stderr);
        ret = 1;
        goto cleanup;
    }

    // Read in bsn_rev_list from disk.
    if (0 != parse_bsn_rev_list_file(&revocations, args.bsn_rev_list_file, args.number_of_bsn_revs)) {
        fputs("Error parsing basename-signature revocation list file\n", stderr);
        ret = 1;
        goto cleanup;
    }

    // Read message from disk.
    uint8_t message[MAX_MESSAGE_SIZE];
    int read_ret = read_file_into_buffer(message, sizeof(message), args.message_file);
    if (read_ret < 0) {
        fprintf(stderr, "Error reading message file: \"%s\"\n", args.message_file);
        ret = 1;
        goto cleanup;
    }
    uint32_t msg_len = (uint32_t)read_ret;

    // Verify signature
    if (0 != ecdaa_signature_FP256BN_verify(&sig, &gpk, &revocations, message, msg_len, basename, basename_len)) {
        fprintf(stderr, "Signature not valid!\n");
        ret = 1;
        goto cleanup;
    }

    printf("Signature successfully verified!\n");

cleanup:
    if (NULL != revocations.sk_list) {
        free(revocations.sk_list);
    }
    if (NULL != revocations.bsn_list) {
        free(revocations.bsn_list);
    }

    return ret;
}

void print_usage(const char *my_name)
{
    printf("usage: %s "
                    "<message-file> "
                    "<signature-input-file> "
                    "<group-public-key-input-file> "
                    "<secret-key-revocation-list-input-file> "
                    "<number-of-secret-key-revocations-in-list> "
                    "<basename-signature-revocation-list-input-file> "
                    "<number-of-basename-signature-revocations-in-list> "
                    "[<basename-file>]\n"
                    "\nNOTE: message must be smaller than %dbytes\n",
           my_name, MAX_MESSAGE_SIZE);
}

int parse_args(struct command_line_args *args_out, int argc, char *argv[])
{
    if (8 == argc || 9 == argc) {
        args_out->message_file = argv[1];
        args_out->sig_file = argv[2];
        args_out->gpk_file = argv[3];

        args_out->sk_rev_list_file = argv[4];
        int num_revs_in = atoi(argv[5]);
        if (0 == num_revs_in) {
            fprintf(stderr, "Warning: Bad value for <number-of-secret-key-revocations-in-list>: %s\nUsing 0\n", argv[5]);
        }
        args_out->number_of_sk_revs = (unsigned)num_revs_in;

        args_out->bsn_rev_list_file = argv[6];
        int num_bsn_revs_in = atoi(argv[7]);
        if (0 == num_revs_in) {
            fprintf(stderr, "Warning: Bad value for <number-of-basename-signature-revocations-in-list>: %s\nUsing 0\n", argv[7]);
        }
        args_out->number_of_bsn_revs = (unsigned)num_bsn_revs_in;

        args_out->basename_file = NULL;
        if (9 == argc) {
            args_out->basename_file = argv[8];
        }
    } else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}

int parse_sk_rev_list_file(struct ecdaa_revocations_FP256BN *revocations_out, const char *filename, unsigned num_revs)
{
    int ret = 0;

    revocations_out->sk_list = NULL;
    revocations_out->sk_length = 0;

    if (NULL != filename && num_revs != 0) {
        // Allocate a buffer to hold the full file.
        size_t file_length = num_revs * ECDAA_MEMBER_SECRET_KEY_FP256BN_LENGTH;
        uint8_t *buffer = malloc(file_length);
        if (NULL == buffer) {
            ret = 1;
            goto cleanup;
        }

        // Allocate the revocation list array.
        revocations_out->sk_list = malloc(num_revs * sizeof(struct ecdaa_member_secret_key_FP256BN));
        if (NULL == revocations_out->sk_list) {
            ret = 1;
            goto cleanup;
        }

        // Read the revocation list in from disk.
        int read_ret = read_file_into_buffer(buffer, file_length, filename);
        if (read_ret < 0 || file_length != (size_t)read_ret) {
            ret = 1;
            goto cleanup;
        }

        // Deserialize each secret key and add it to the list.
        for (unsigned i = 0; i < num_revs; i++) {
            int deserial_ret = ecdaa_member_secret_key_FP256BN_deserialize(&revocations_out->sk_list[i],
                                                                         buffer + i*ECDAA_MEMBER_SECRET_KEY_FP256BN_LENGTH);
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

int parse_bsn_rev_list_file(struct ecdaa_revocations_FP256BN *revocations_out, const char *filename, unsigned num_revs)
{
    int ret = 0;

    revocations_out->bsn_list = NULL;
    revocations_out->bsn_length = 0;

    size_t point_size = (2*MODBYTES_256_56 + 1);

    if (NULL != filename && num_revs != 0) {
        // Allocate a buffer to hold the full file.
        size_t file_length = num_revs * point_size;
        uint8_t *buffer = malloc(file_length);
        if (NULL == buffer) {
            ret = 1;
            goto cleanup;
        }

        // Allocate the revocation list array.
        revocations_out->bsn_list = malloc(num_revs * sizeof(ECP_FP256BN));
        if (NULL == revocations_out->bsn_list) {
            ret = 1;
            goto cleanup;
        }

        // Read the revocation list in from disk.
        int read_ret = read_file_into_buffer(buffer, file_length, filename);
        if (read_ret < 0 || file_length != (size_t)read_ret) {
            ret = 1;
            goto cleanup;
        }

        // Deserialize each basename signature and add it to the list.
        for (unsigned i = 0; i < num_revs; i++) {
            // Nb. This does NOT check that the point is in the proper group.
            octet point_as_octet = {.val=(char*)(buffer+i*point_size), .len=point_size};
            int deserial_ret = ECP_FP256BN_fromOctet(&revocations_out->bsn_list[i], &point_as_octet);
            revocations_out->bsn_length++;
            if (0 != deserial_ret) {
                ret = 1;
                goto cleanup;
            }
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
