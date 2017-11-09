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
#include <stdint.h>

struct command_line_args {
    char *member_public_key_file;
    char *group_public_key_file;
    char *credential_file;
    char *credential_signature_file;
};

void print_usage(const char *my_name);

int parse_args(struct command_line_args *args_out, int argc, char *argv[]);

int main(int argc, char *argv[])
{
    uint8_t buffer[1024];

    // Parse command line
    struct command_line_args args;
    if (0 != parse_args(&args, argc, argv))
        return 1;

    // Read member public key from disk
    struct ecdaa_member_public_key_BN254 pk;
    if (ECDAA_MEMBER_PUBLIC_KEY_BN254_LENGTH != read_file_into_buffer(buffer, ECDAA_MEMBER_PUBLIC_KEY_BN254_LENGTH, args.member_public_key_file)) {
        fprintf(stderr, "Error reading member public key file: \"%s\"\n", args.member_public_key_file);
        return 1;
    }
    if (0 != ecdaa_member_public_key_BN254_deserialize_no_check(&pk, buffer)) {
        fputs("Error deserializing member public key\n", stderr);
        return 1;
    }

    // Read group public key from disk
    struct ecdaa_group_public_key_BN254 gpk;
    if (ECDAA_GROUP_PUBLIC_KEY_BN254_LENGTH != read_file_into_buffer(buffer, ECDAA_GROUP_PUBLIC_KEY_BN254_LENGTH, args.group_public_key_file)) {
        fprintf(stderr, "Error reading group public key file: \"%s\"\n", args.group_public_key_file);
        return 1;
    }
    if (0 != ecdaa_group_public_key_BN254_deserialize(&gpk, buffer)) {
        fputs("Error deserializing group public key\n", stderr);
        return 1;
    }

    // Read credential and credential signature from disk.
    struct ecdaa_credential_BN254 cred;
    if (ECDAA_CREDENTIAL_BN254_LENGTH != read_file_into_buffer(buffer, ECDAA_CREDENTIAL_BN254_LENGTH, args.credential_file)) {
        fprintf(stderr, "Error reading credential file: \"%s\"\n", args.credential_file);
        return 1;
    }
    if (ECDAA_CREDENTIAL_BN254_SIGNATURE_LENGTH != read_file_into_buffer(buffer + ECDAA_CREDENTIAL_BN254_LENGTH,
                                   ECDAA_CREDENTIAL_BN254_SIGNATURE_LENGTH,
                                   args.credential_signature_file)) {
        fprintf(stderr, "Error reading credential signature file: \"%s\"\n", args.credential_signature_file);
        return 1;
    }
    int deserialize_ret = ecdaa_credential_BN254_deserialize_with_signature(&cred, &pk, &gpk, buffer, buffer + ECDAA_CREDENTIAL_BN254_LENGTH);
    if (-1 == deserialize_ret) {
        fputs("Error: credential or its signature is mal-formed\n", stderr);
        return 1;
    } else if (-2 == deserialize_ret) {
        fputs("Error: credential signature is invalid\n", stderr);
        return 1;
    }

    printf("Credential validated!\n");
}

void print_usage(const char *my_name)
{
    printf("usage: %s "
                    "<public-key-input-file> "
                    "<group-public-key-input-file> "
                    "<credential-input-file> "
                    "<credential-signature-input-file>\n",
           my_name);
}

int parse_args(struct command_line_args *args_out, int argc, char *argv[])
{
    if (5 != argc) {
        print_usage(argv[0]);
        return 1;
    }

    args_out->member_public_key_file = argv[1];
    args_out->group_public_key_file = argv[2];
    args_out->credential_file = argv[3];
    args_out->credential_signature_file = argv[4];

    return 0;
}
