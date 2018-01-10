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
    char *credential_file;
    char *secret_key_file;
    char *sig_out_file;
    char *message_file;
    char *basename_file;
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
    struct ecdaa_member_secret_key_FP256BN sk;
    if (ECDAA_MEMBER_SECRET_KEY_FP256BN_LENGTH != read_file_into_buffer(buffer, ECDAA_MEMBER_SECRET_KEY_FP256BN_LENGTH, args.secret_key_file)) {
        fprintf(stderr, "Error reading member secret key file: \"%s\"\n", args.secret_key_file);
        return 1;
    }
    if (0 != ecdaa_member_secret_key_FP256BN_deserialize(&sk, buffer)) {
        fputs("Error deserializing member secret key\n", stderr);
        return 1;
    }

    // Read member credential from disk
    struct ecdaa_credential_FP256BN cred;
    if (ECDAA_CREDENTIAL_FP256BN_LENGTH != read_file_into_buffer(buffer, ECDAA_CREDENTIAL_FP256BN_LENGTH, args.credential_file)) {
        fprintf(stderr, "Error reading member credential file: \"%s\"\n", args.credential_file);
        return 1;
    }
    if (0 != ecdaa_credential_FP256BN_deserialize(&cred, buffer)) {
        fputs("Error deserializing member credential\n", stderr);
        return 1;
    }

    // Read message file
    uint8_t message[MAX_MESSAGE_SIZE];
    int read_ret = read_file_into_buffer(message, sizeof(message), args.message_file);
    if (read_ret < 0) {
        fprintf(stderr, "Error reading message file: \"%s\"\n", args.message_file);
        return 1;
    }
    uint32_t msg_len = (uint32_t)read_ret;

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

    // Create signature
    struct ecdaa_signature_FP256BN sig;
    if (0 != ecdaa_signature_FP256BN_sign(&sig, message, msg_len, basename, basename_len, &sk, &cred, &rng)) {
        fprintf(stderr, "Error signing message: \"%s\"\n", (char*)message);
        return 1;
    }

    // Write signature to file
    ecdaa_signature_FP256BN_serialize(buffer, &sig, basename_len != 0);
    if (ECDAA_SIGNATURE_FP256BN_LENGTH != write_buffer_to_file(args.sig_out_file, buffer, ECDAA_SIGNATURE_FP256BN_LENGTH)) {
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
                    "<message-file> "
                    "[<basename-file>]\n"
                    "\nNOTE: message must be smaller than %dbytes\n",
           my_name, MAX_MESSAGE_SIZE);
}

int parse_args(struct command_line_args *args_out, int argc, char *argv[])
{
    if (5 == argc || 6 == argc) {
        args_out->secret_key_file = argv[1];
        args_out->credential_file = argv[2];
        args_out->sig_out_file = argv[3];
        args_out->message_file = argv[4];
        args_out->basename_file = NULL;
        if (6 == argc) {
            args_out->basename_file = argv[5];
        }
    } else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
