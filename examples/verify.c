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

struct command_line_args {
    char *message;
    char *sig_file;
    char *gpk_file;
    char *sk_rev_list_file;
    unsigned number_of_sk_revs;
};

void print_usage(const char *my_name);

int parse_args(struct command_line_args *args_out, int argc, char *argv[]);

int parse_sk_rev_list_file(struct ecdaa_revocation_list_BN254 *rev_list_out, const char *filename, unsigned num_revs);

int main(int argc, char *argv[])
{
    uint8_t buffer[1024];

    // Parse command line
    struct command_line_args args;
    if (0 != parse_args(&args, argc, argv))
        return 1;

    // Read signature from disk
    struct ecdaa_signature_BN254 sig;
    if (0 != read_file_into_buffer(buffer, ECDAA_SIGNATURE_BN254_LENGTH, args.sig_file)) {
        fprintf(stderr, "Error reading signature file: \"%s\"\n", args.sig_file);
        return 1;
    }
    if (0 != ecdaa_signature_BN254_deserialize(&sig, buffer)) {
        fputs("Error deserializing signature\n", stderr);
        return 1;
    }

    // Read group public key from disk
    struct ecdaa_group_public_key_BN254 gpk;
    if (0 != read_file_into_buffer(buffer, ECDAA_GROUP_PUBLIC_KEY_BN254_LENGTH, args.gpk_file)) {
        fprintf(stderr, "Error reading group public key file: \"%s\"\n", args.gpk_file);
        return 1;
    }
    if (0 != ecdaa_group_public_key_BN254_deserialize(&gpk, buffer)) {
        fputs("Error deserializing group public key\n", stderr);
        return 1;
    }

    // Read in sk_rev_list from disk.
    struct ecdaa_revocation_list_BN254 sk_rev_list;
    if (0 != parse_sk_rev_list_file(&sk_rev_list, args.sk_rev_list_file, args.number_of_sk_revs)) {
        fputs("Error parsing revocation list file\n", stderr);
        return 1;
    }

    // Verify signature
    size_t msg_len = strlen(args.message);
    if (msg_len > 1048576) {    // 1MiB
        fprintf(stderr, "Message seems too large (%zu bytes). Quitting\n", msg_len);
        return 1;
    }
    if (0 != ecdaa_signature_BN254_verify(&sig, &gpk, &sk_rev_list, (uint8_t*)args.message, (uint32_t)msg_len)) {
        fprintf(stderr, "Signature not valid!\n");
        return 1;
    }

    if (NULL != sk_rev_list.list)
        free(sk_rev_list.list);

    printf("Signature successfully verified!\n");
}

void print_usage(const char *my_name)
{
    printf("usage: %s "
                    "<message> "
                    "<signature-input-file> "
                    "<group-public-key-input-file> "
                    "[<secret-key-revocation-list-input-file>] "
                    "[<number-of-secret-key-revocations-in-list>]\n",
           my_name);
}

int parse_args(struct command_line_args *args_out, int argc, char *argv[])
{
    if (6 == argc || 4 == argc) {
        args_out->message = argv[1];
        args_out->sig_file = argv[2];
        args_out->gpk_file = argv[3];

        args_out->sk_rev_list_file = NULL;
        args_out->number_of_sk_revs = 0;

        if (6 == argc) {
            args_out->sk_rev_list_file = argv[4];
            int num_revs_in = atoi(argv[5]);
            if (0 >= num_revs_in) {
                fprintf(stderr, "Bad value for <number-of-secret-key-revocations-in-list>: %s\n", argv[4]);
                print_usage(argv[0]);
                return 1;
            }
            args_out->number_of_sk_revs = (unsigned)num_revs_in;
        }
    } else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}

int parse_sk_rev_list_file(struct ecdaa_revocation_list_BN254 *rev_list_out, const char *filename, unsigned num_revs)
{
    int ret = 0;

    rev_list_out->list = NULL;
    rev_list_out->length = 0;

    if (NULL != filename && num_revs != 0) {
        // Allocate a buffer to hold the full file.
        size_t file_length = num_revs * ECDAA_MEMBER_SECRET_KEY_BN254_LENGTH;
        uint8_t *buffer = malloc(file_length);
        if (NULL == buffer) {
            ret = 1;
            goto cleanup;
        }

        // Allocate the revocation list array.
        rev_list_out->list = malloc(num_revs * sizeof(struct ecdaa_member_secret_key_BN254));
        if (NULL == rev_list_out->list) {
            ret = 1;
            goto cleanup;
        }

        // Read the revocation list in from disk.
        if (0 != read_file_into_buffer(buffer, file_length, filename)) {
            ret = 1;
            goto cleanup;
        }

        // Deserialize each secret key and add it to the list.
        for (unsigned i = 0; i < num_revs; i++) {
            int deserial_ret = ecdaa_member_secret_key_BN254_deserialize(&rev_list_out->list[i],
                                                                         buffer + i*ECDAA_MEMBER_SECRET_KEY_BN254_LENGTH);
            rev_list_out->length++;
            if (0 != deserial_ret) {
                ret = 1;
                goto cleanup;
            }
        }

cleanup:
        if (NULL != buffer)
            free(buffer);

        if (0 != ret) {
            if (NULL != rev_list_out->list)
                free(rev_list_out->list);

            rev_list_out->list = NULL;
            rev_list_out->length = 0;
        }
    }

    return ret;
}
