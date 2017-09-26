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
    char *credential_file;
    char *secret_key_file;
    char *sig_out_file;
    char *message;
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

    // Read member secret key from disk
    struct ecdaa_member_secret_key_BN254 sk;
    if (0 != read_file_into_buffer(buffer, ECDAA_MEMBER_SECRET_KEY_BN254_LENGTH, args.secret_key_file)) {
        fprintf(stderr, "Error reading member secret key file: \"%s\"\n", args.secret_key_file);
        return 1;
    }
    if (0 != ecdaa_member_secret_key_BN254_deserialize(&sk, buffer)) {
        fputs("Error deserializing member secret key\n", stderr);
        return 1;
    }

    // Read member credential from disk
    struct ecdaa_credential_BN254 cred;
    if (0 != read_file_into_buffer(buffer, ECDAA_CREDENTIAL_BN254_LENGTH, args.credential_file)) {
        fprintf(stderr, "Error reading member credential file: \"%s\"\n", args.credential_file);
        return 1;
    }
    if (0 != ecdaa_credential_BN254_deserialize(&cred, buffer)) {
        fputs("Error deserializing member credential\n", stderr);
        return 1;
    }

    // Create signature
    struct ecdaa_signature_BN254 sig;
    size_t msg_len = strlen(args.message);
    if (msg_len > 1048576) {    // 1MiB
        fprintf(stderr, "Message seems too large (%zu bytes). Quitting\n", msg_len);
        return 1;
    }
    if (0 != ecdaa_signature_BN254_sign(&sig, (uint8_t*)args.message, (uint32_t)msg_len, &sk, &cred, &rng)) {
        fprintf(stderr, "Error signing message: \"%s\"\n", args.message);
        return 1;
    }

    // Write signature to file
    ecdaa_signature_BN254_serialize(buffer, &sig);
    if (0 != write_buffer_to_file(args.sig_out_file, buffer, ECDAA_SIGNATURE_BN254_LENGTH)) {
        fprintf(stderr, "Error writing signature to file: \"%s\"\n", args.sig_out_file);
        return 1;
    }

    printf("Signature successfully created!\n");
}

void print_usage(const char *my_name)
{
    printf("usage: %s "
                    "<secret-key-input-file> "
                    "<credential-input-file> "
                    "<signature-output-file> "
                    "<message>\n",
           my_name);
}

int parse_args(struct command_line_args *args_out, int argc, char *argv[])
{
    if (5 != argc) {
        print_usage(argv[0]);
        return 1;
    }

    args_out->secret_key_file = argv[1];
    args_out->credential_file = argv[2];
    args_out->sig_out_file = argv[3];
    args_out->message = argv[4];

    return 0;
}
