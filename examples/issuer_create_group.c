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
    char *public_key_file;
    char *secret_key_file;
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

    // Initialize PRNG
    struct ecdaa_prng rng;
    if (0 != ecdaa_prng_init(&rng)) {
        fputs("Error initializing ecdaa_prng\n", stderr);
        return 1;
    }

    // Create issuer key-pair
    struct ecdaa_issuer_public_key_BN254 ipk;
    struct ecdaa_issuer_secret_key_BN254 isk;
    if (0 != ecdaa_issuer_key_pair_BN254_generate(&ipk, &isk, &rng)) {
        fprintf(stderr, "Error generating issuer key-pair\n");
        return 1;
    }

    // Write public-key to file
    ecdaa_issuer_public_key_BN254_serialize(buffer, &ipk);
    if (ECDAA_ISSUER_PUBLIC_KEY_BN254_LENGTH != write_buffer_to_file(args.public_key_file, buffer, ECDAA_ISSUER_PUBLIC_KEY_BN254_LENGTH)) {
        fprintf(stderr, "Error writing public key to file: \"%s\"\n", args.public_key_file);
        return 1;
    }

    // Write secret-key to file
    ecdaa_issuer_secret_key_BN254_serialize(buffer, &isk);
    if (ECDAA_ISSUER_SECRET_KEY_BN254_LENGTH != write_buffer_to_file(args.secret_key_file, buffer, ECDAA_ISSUER_SECRET_KEY_BN254_LENGTH)) {
        fprintf(stderr, "Error writing secret key to file: \"%s\"\n", args.secret_key_file);
        return 1;
    }

    printf("Group successfully created!\n");
}

void print_usage(const char *my_name)
{
    printf("usage: %s "
                    "<public-key-output-file> "
                    "<secret-key-output-file>\n",
           my_name);
}

int parse_args(struct command_line_args *args_out, int argc, char *argv[])
{
    if (3 != argc) {
        print_usage(argv[0]);
        return 1;
    }

    args_out->public_key_file = argv[1];
    args_out->secret_key_file = argv[2];

    return 0;
}
