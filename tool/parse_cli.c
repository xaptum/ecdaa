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

#include "parse_cli.h"

#include <ecdaa.h>

#include <stdint.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const char *curve_name_strings[] = {
    "ZZZ",
};

static
void parse_curve(curve_name *out, const char *in);

static
void parse_issuer_gen_keys_cli(int argc, char **argv, struct cli_params *params)
{
    params->curve = 0;
    params->ipk = "ipk.bin";
    params->isk = "isk.bin";
    const char *usage_str = "Create issuer public and secret key.\n\n"
        "Usage: %s %s [-h] [-u <curve>] [-p <file>] [-s <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-u --curve             Curve to use [default = %s].\n"
        "\t\t\tZZZ\n"
        "\t\t-p --ipk               Issuer public key output location [default = ipk.bin].\n"
        "\t\t-s --isk               Issuer secret key output location [default = isk.bin].\n"
        ;

    static struct option cli_options[] =
    {
        {"curve", required_argument, NULL, 'u'},
        {"ipk", required_argument, NULL, 'p'},
        {"isk", required_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "u:p:s:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'u':
                parse_curve(&params->curve, optarg);
                break;
            case 'p':
                params->ipk=optarg;
                break;
            case 's':
                params->isk=optarg;
                break;
            case 'h':
            default:
                printf(usage_str, argv[0], argv[1], curve_name_strings[0]);
                exit(1);
        }
    }
}

static
void parse_extract_gpk_cli(int argc, char **argv, struct cli_params *params)
{
    params->curve = 0;
    params->ipk = "ipk.bin";
    params->gpk = "gpk.bin";
    const char *usage_str = "Extract the Group Public Key from an issuer public key.\n\n"
        "Usage: %s %s [-h] [-u] [-p <file>] [-g <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-u --curve             Curve to use [default = %s].\n"
        "\t\t\tZZZ\n"
        "\t\t-p --ipk               Issuer public key location [default = ipk.bin].\n"
        "\t\t-g --gpk               Group public key output location [default = gpk.bin].\n"
        ;

    static struct option cli_options[] =
    {
        {"curve", required_argument, NULL, 'u'},
        {"ipk", required_argument, NULL, 'p'},
        {"gpk", required_argument, NULL, 'g'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "u:p:g:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'u':
                parse_curve(&params->curve, optarg);
                break;
            case 'p':
                params->ipk=optarg;
                break;
            case 'g':
                params->gpk=optarg;
                break;
            case 'h':
            default:
                printf(usage_str, argv[0], argv[1], curve_name_strings[0]);
                exit(1);
        }
    }
}

static
void parse_member_gen_keys_cli(int argc, char **argv, struct cli_params *params)
{
    params->curve = 0;
    params->nonce = "nonce-text";
    params->pk = "pk.bin";
    params->sk = "sk.bin";
    const char *usage_str = "Generate a member keypair, including a signature over the given nonce.\n\n"
        "Usage: %s %s [-h] [-u] [-p <file>] [-s <file>] [-n 'nonce']\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-u --curve             Curve to use [default = %s].\n"
        "\t\t\tZZZ\n"
        "\t\t-n --nonce             Nonce [default = 'nonce-text'].\n"
        "\t\t-p --pk                Public key output location [default = pk.bin].\n"
        "\t\t-s --sk                Secret key output location [default = sk.bin].\n"
        ;

    static struct option cli_options[] =
    {
        {"curve", required_argument, NULL, 'u'},
        {"nonce", required_argument, NULL, 'n'},
        {"pk", required_argument, NULL, 'p'},
        {"sk", required_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "u:n:p:s:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'u':
                parse_curve(&params->curve, optarg);
                break;
            case 'n':
                params->nonce=optarg;
                break;
            case 'p':
                params->pk=optarg;
                break;
            case 's':
                params->sk=optarg;
                break;
            case 'h':
            default:
                printf(usage_str, argv[0], argv[1], curve_name_strings[0]);
                exit(1);
        }
    }
}

static
void parse_issue_credential_cli(int argc, char **argv, struct cli_params *params)
{
    params->curve = 0;
    params->pk = "pk.bin";
    params->isk = "isk.bin";
    params->cred = "cred.bin";
    params->cred_sig = "cred_sig.bin";
    params->nonce = "nonce-text";
    const char *usage_str = "Create a credential, and credential signature, on a member's public key.\n\n"
        "Usage: %s %s [-h] [-u] [-p <file>] [-s <file>] [-c <file>] [-r <file>] [-n 'nonce']\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-u --curve             Curve to use [default = %s].\n"
        "\t\t\tZZZ\n"
        "\t\t-p --pk                Public key location [default = pk.bin].\n"
        "\t\t-s --isk               Issuer secret key location [default = isk.bin].\n"
        "\t\t-n --nonce             Nonce [default = 'nonce-text'].\n"
        "\t\t-c --cred              DAA Credential output location [default = cred.bin].\n"
        "\t\t-r --credsig           DAA Credential Signature output location [default = cred_sig.bin].\n"
        ;

    static struct option cli_options[] =
    {
        {"curve", required_argument, NULL, 'u'},
        {"pk", required_argument, NULL, 'p'},
        {"isk", required_argument, NULL, 's'},
        {"cred", required_argument, NULL, 'c'},
        {"credsig", required_argument, NULL, 'r'},
        {"nonce", required_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "u:p:s:c:r:n:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'u':
                parse_curve(&params->curve, optarg);
                break;
            case 'p':
                params->pk=optarg;
                break;
            case 's':
                params->isk=optarg;
                break;
            case 'c':
                params->cred=optarg;
                break;
            case 'r':
                params->cred_sig=optarg;
                break;
            case 'n':
                params->nonce=optarg;
                break;
            case 'h':
            default:
                printf(usage_str, argv[0], argv[1], curve_name_strings[0]);
                exit(1);
        }
    }
}


static
void parse_process_credential_cli(int argc, char **argv, struct cli_params *params)
{
    params->curve = 0;
    params->pk = "pk.bin";
    params->gpk = "gpk.bin";
    params->cred = "cred.bin";
    params->cred_sig = "cred_sig.bin";

    const char *usage_str = "Validate a credential issued for the given member public key.\n\n"
        "Usage: %s %s [-h] [-u] [-p <file>] [-g <file>] [-c <file>] [-r <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-u --curve             Curve to use [default = %s].\n"
        "\t\t\tZZZ\n"
        "\t\t-p --pk                Public key location [default = pk.bin].\n"
        "\t\t-g --gpk               Group public key location [default = gpk.bin].\n"
        "\t\t-c --cred              DAA Credential location [default = cred.bin].\n"
        "\t\t-r --credsig           DAA Credential Signature location [default = cred_sig.bin].\n"
        ;

    static struct option cli_options[] =
    {
        {"curve", required_argument, NULL, 'u'},
        {"pk", required_argument, NULL, 'p'},
        {"gpk", required_argument, NULL, 'g'},
        {"cred", required_argument, NULL, 'c'},
        {"credsig", required_argument, NULL, 'r'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "u:p:g:c:r:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'u':
                parse_curve(&params->curve, optarg);
                break;
            case 'p':
                params->pk=optarg;
                break;
            case 'g':
                params->gpk=optarg;
                break;
            case 'c':
                params->cred=optarg;
                break;
            case 'r':
                params->cred_sig=optarg;
                break;
            case 'h':
            default:
                printf(usage_str, argv[0], argv[1], curve_name_strings[0]);
                exit(1);
        }
    }
}

static
void parse_sign_cli(int argc, char **argv, struct cli_params *params)
{
    params->curve = 0;
    params->sk = "sk.bin";
    params->cred = "cred.bin";
    params->message = "message.bin";
    params->basename = NULL;
    params->sig = "sig.bin";
    const char *usage_str = "Create a DAA signature over the message.\n\n"
        "Usage: %s %s [-h] [-u] [-s <file>] [-c <file>] [-g <file>] [-m <file>] [-b <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-u --curve             Curve to use [default = %s].\n"
        "\t\t\tZZZ\n"
        "\t\t-s --sk                Secret key location [default = sk.bin].\n"
        "\t\t-c --cred              DAA Credential location [default = cred.bin].\n"
        "\t\t-m --message           Message location [default = message.bin].\n"
        "\t\t-b --basename          Basename location [default = NULL].\n"
        "\t\t-g --sig               Signature output location [default = sig.bin].\n"
        ;

    static struct option cli_options[] =
    {
        {"curve", required_argument, NULL, 'u'},
        {"sk", required_argument, NULL, 's'},
        {"cred", required_argument, NULL, 'c'},
        {"sig", required_argument, NULL, 'g'},
        {"message", required_argument, NULL, 'm'},
        {"basename", required_argument, NULL, 'b'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "u:s:c:g:m:b:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'u':
                parse_curve(&params->curve, optarg);
                break;
            case 's':
                params->sk=optarg;
                break;
            case 'c':
                params->cred=optarg;
                break;
            case 'g':
                params->sig=optarg;
                break;
            case 'm':
                params->message=optarg;
                break;
            case 'b':
                params->basename=optarg;
                break;
            case 'h':
            default:
                printf(usage_str, argv[0], argv[1], curve_name_strings[0]);
                exit(1);
        }
    }
}

static
void parse_verify_cli(int argc, char **argv, struct cli_params *params)
{
    params->curve = 0;
    params->gpk = "gpk.bin";
    params->message = "message.bin";
    params->sig = "sig.bin";
    params->sk_rev_list = NULL;
    params->bsn_rev_list = NULL;
    params->num_sk_revs = "0";
    params->num_bsn_revs = "0";
    params->basename = NULL;


    const char *usage_str = "Verify a signature.\n\n"
        "Usage: %s %s [-h] [-u] [-m <file>] [-s <file>] [-g <file>] [-k <file>] [-n <file>] [-e <file>] [-v <file>] [-b <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-u --curve             Curve to use [default = %s].\n"
        "\t\t\tZZZ\n"
        "\t\t-g --gpk               Group public key location [default = gpk.bin].\n"
        "\t\t-m --message           Message location [default = message.bin].\n"
        "\t\t-s --sig               Signature location [default = sig.bin].\n"
        "\t\t-k --sk_rev_list       Secret key revocation list location [default = NULL].\n"
        "\t\t-e --num_sk_revs       Number of secret key revocations [default = 0].\n"
        "\t\t-b --basename          Basename location [default = NULL].\n"
        "\t\t-n --bsn_rev_list      Basename revocation list location [default = NULL].\n"
        "\t\t-v --num_bsn_revs      Number of basename revocations [default = 0].\n"
        ;

    static struct option cli_options[] =
    {
        {"curve", required_argument, NULL, 'u'},
        {"message", required_argument, NULL, 'm'},
        {"sig", required_argument, NULL, 's'},
        {"gpk", required_argument, NULL, 'g'},
        {"sk_rev_list", required_argument, NULL, 'k'},
        {"bsn_rev_list", required_argument, NULL, 'n'},
        {"num_sk_revs", required_argument, NULL, 'e'},
        {"num_bsn_revs", required_argument, NULL, 'v'},
        {"basename", required_argument, NULL, 'b'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "u:m:s:g:k:n:e:v:b:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'u':
                parse_curve(&params->curve, optarg);
                break;
            case 'm':
                params->message=optarg;
                break;
            case 's':
                params->sig=optarg;
                break;
            case 'g':
                params->gpk=optarg;
                break;
            case 'k':
                params->sk_rev_list=optarg;
                break;
            case 'n':
                params->bsn_rev_list=optarg;
                break;
            case 'e':
                params->num_sk_revs=optarg;
                break;
            case 'v':
                params->num_bsn_revs=optarg;
                break;
            case 'b':
                params->basename=optarg;
                break;
            case 'h':
            default:
                printf(usage_str, argv[0], argv[1], curve_name_strings[0]);
                exit(1);
        }
    }
}


void parse_member_cli(int argc, char** argv, struct cli_params *params)
{
    const char *usage_str =
        "Options:\n"
        "\tgenkeys                       Generate a member keypair.\n"
        "\tprocesscredential             Validate a credential.\n"
        "\tsign                          Create a DAA signature.\n"
        ;

    if (argc <=2 || strcmp(argv[2], "-h")==0 || strcmp(argv[2], "--help")==0) {
        printf("%s", usage_str);
        exit(1);
    }

    if (strcmp(argv[2], "genkeys")==0)
    {
        params->command=action_member_gen_keys;
        parse_member_gen_keys_cli(argc, argv, params);
    } else if (strcmp(argv[2], "processcredential")==0)
    {
        params->command=action_process_credential;
        parse_process_credential_cli(argc, argv, params);
    } else if (strcmp(argv[2], "sign")==0)
    {
        params->command=action_sign;
        parse_sign_cli(argc, argv, params);
    } else
    {
        fprintf(stderr, "'%s' is not an option for member.\n%s", argv[2], usage_str);
        exit(1);
    }
}

void parse_issuer_cli(int argc, char** argv, struct cli_params *params)
{
    const char *usage_str =
        "Options:\n"
        "\tgenkeys                       Create an issuer keypair.\n"
        "\tissuecredential               Create a credential on a member's public key.\n"
        ;

    if (argc <=2 || strcmp(argv[2], "-h")==0 || strcmp(argv[2], "--help")==0) {
        printf("%s", usage_str);
        exit(1);
    }

    if (strcmp(argv[2], "genkeys")==0)
    {
        params->command=action_issuer_gen_keys;
        parse_issuer_gen_keys_cli(argc, argv, params);
    } else if (strcmp(argv[2], "issuecredential")==0)
    {
        params->command=action_issue_credential;
        parse_issue_credential_cli(argc, argv, params);
    } else
    {
        fprintf(stderr, "'%s' is not an option for issuer.\n%s", argv[2], usage_str);
        exit(1);
    }
}

void parse_cli(int argc, char** argv, struct cli_params *params)
{
    const char *usage_str =
        "Options:\n"
        "\tmember [more commands]        Access member functions.\n"
        "\tissuer [more commands]        Access issuer functions.\n"
        "\textractgpk                    Extract the GPK from an issuer public key.\n"
        "\tverify                        Verify a signature.\n"
        ;

    if (argc <=1 || strcmp(argv[1], "-h")==0 || strcmp(argv[1], "--help")==0) {
        printf("%s", usage_str);
        exit(1);
    }

    if (strcmp(argv[1], "member")==0)
    {
        parse_member_cli(argc, argv, params);
    } else if (strcmp(argv[1], "issuer")==0)
    {
        parse_issuer_cli(argc, argv, params);
    } else if (strcmp(argv[1], "extractgpk")==0)
    {
        params->command=action_extract_gpk;
        parse_extract_gpk_cli(argc, argv, params);
    } else if (strcmp(argv[1], "verify")==0)
    {
        params->command = action_verify;
        parse_verify_cli(argc, argv, params);
    } else
    {
        fprintf(stderr, "'%s' is not an option for the ECDAA tool.\n%s", argv[2], usage_str);
        exit(1);
    }
}

void parse_curve(curve_name *out, const char *in)
{
    if (0) {    // required to make the template expansion work
        return;
    } else if (0 == strcmp(in, "ZZZ")) { *out = ZZZ;
    } else {
        fprintf(stderr, "Unknown curve '%s'\n", in);
        exit(1);
    }
}
