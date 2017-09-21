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
    char *issuer_public_key_file;
    char *group_public_key_file;
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

    // Read issuer public key from disk.
    struct ecdaa_issuer_public_key_BN254 ipk;
    if (0 != read_file_into_buffer(buffer, ECDAA_ISSUER_PUBLIC_KEY_BN254_LENGTH, args.issuer_public_key_file)) {
        fprintf(stderr, "Error reading issuer public key file: \"%s\"\n", args.issuer_public_key_file);
        return 1;
    }
    int deserialize_ret = ecdaa_issuer_public_key_BN254_deserialize(&ipk, buffer);
    if (-1 == deserialize_ret) {
        fputs("Error: issuer public key is mal-formed\n", stderr);
        return 1;
    } else if (-2 == deserialize_ret) {
        fputs("Error: issuer public key signature is invalid\n", stderr);
        return 1;
    }

    // Write group-public-key to file
    ecdaa_group_public_key_BN254_serialize(buffer, &ipk.gpk);
    if (0 != write_buffer_to_file(args.group_public_key_file, buffer, ECDAA_GROUP_PUBLIC_KEY_BN254_LENGTH)) {
        fprintf(stderr, "Error writing group public key to file: \"%s\"\n", args.group_public_key_file);
        return 1;
    }

    printf("Group public key successfully saved!\n");
}

void print_usage(const char *my_name)
{
    printf("usage: %s "
                    "<issuer-public-key-input-file> "
                    "<group-public-key-output-file>\n",
           my_name);
}

int parse_args(struct command_line_args *args_out, int argc, char *argv[])
{
    if (3 != argc) {
        print_usage(argv[0]);
        return 1;
    }

    args_out->issuer_public_key_file = argv[1];
    args_out->group_public_key_file = argv[2];

    return 0;
}
