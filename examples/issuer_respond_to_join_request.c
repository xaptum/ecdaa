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
    char *issuer_secret_key_file;
    char *credential_out_file;
    char *credential_signature_out_file;
    char *nonce;
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

    // Read member public key from disk.
    // NOTE: If this Join procedure is being done remotely,
    //  there should be some way of authenticating this member's public key.
    //  For our purposes, we assume this is an "in-factory" join,
    //  and so the authenticity of this member is ensured
    //  via physical means.
    size_t nonce_len = strlen(args.nonce);
    if (nonce_len > 1048576) {    // 1MiB
        fprintf(stderr, "Nonce seems too large (%zu bytes). Quitting\n", nonce_len);
        return 1;
    }
    struct ecdaa_member_public_key_BN254 pk;
    if (0 != read_file_into_buffer(buffer, ECDAA_MEMBER_PUBLIC_KEY_BN254_LENGTH, args.member_public_key_file)) {
        fprintf(stderr, "Error reading member public key file: \"%s\"\n", args.member_public_key_file);
        return 1;
    }
    int deserialize_ret = ecdaa_member_public_key_BN254_deserialize(&pk, buffer, (uint8_t*)args.nonce, (uint32_t)nonce_len);
    if (-1 == deserialize_ret) {
        fputs("Error: member public key is mal-formed\n", stderr);
        return 1;
    } else if (-2 == deserialize_ret) {
        fputs("Error: member public key signature is invalid\n", stderr);
        return 1;
    }

    // Read issuer secret key from disk;
    struct ecdaa_issuer_secret_key_BN254 isk;
    if (0 != read_file_into_buffer(buffer, ECDAA_ISSUER_SECRET_KEY_BN254_LENGTH, args.issuer_secret_key_file)) {
        fprintf(stderr, "Error reading issuer secret key file: \"%s\"\n", args.issuer_secret_key_file);
        return 1;
    }
    if (0 != ecdaa_issuer_secret_key_BN254_deserialize(&isk, buffer)) {
        fputs("Error deserializing issuer secret key\n", stderr);
        return 1;
    }

    // Generate new credential for this member, along with a credential signature.
    struct ecdaa_credential_BN254 cred;
    struct ecdaa_credential_BN254_signature cred_sig;
    if (0 != ecdaa_credential_BN254_generate(&cred, &cred_sig, &isk, &pk, &rng)) {
        fputs("Error generating credential\n", stderr);
        return 1;
    }

    // Write credential to file
    ecdaa_credential_BN254_serialize(buffer, &cred);
    if (0 != write_buffer_to_file(args.credential_out_file, buffer, ECDAA_CREDENTIAL_BN254_LENGTH)) {
        fprintf(stderr, "Error writing credential to file: \"%s\"\n", args.credential_out_file);
        return 1;
    }

    // Write credential signature to file
    ecdaa_credential_BN254_signature_serialize(buffer, &cred_sig);
    if (0 != write_buffer_to_file(args.credential_signature_out_file, buffer, ECDAA_CREDENTIAL_BN254_SIGNATURE_LENGTH)) {
        fprintf(stderr, "Error writing credential signature to file: \"%s\"\n", args.credential_signature_out_file);
        return 1;
    }

    printf("Credential successfully created!\n");
}

void print_usage(const char *my_name)
{
    printf("usage: %s "
                    "<member-public-key-input-file> "
                    "<issuer-secret-key-input-file> "
                    "<credential-output-file> "
                    "<credential-signature-output-file> "
                    "<nonce>\n",
           my_name);
}

int parse_args(struct command_line_args *args_out, int argc, char *argv[])
{
    if (6 != argc) {
        print_usage(argv[0]);
        return 1;
    }

    args_out->member_public_key_file = argv[1];
    args_out->issuer_secret_key_file = argv[2];
    args_out->credential_out_file = argv[3];
    args_out->credential_signature_out_file = argv[4];
    args_out->nonce = argv[5];

    return 0;
}
