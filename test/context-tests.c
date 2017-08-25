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

#include <xaptum-ecdaa/context.h>

#include <amcl/ecdh_BN254.h>

#include <sodium.h>

#include <stdio.h>
#include <assert.h>

static void seed_rng(csprng *rng);

static void issuer_secrets_are_valid();

static void issuer_proof_checks();

static void member_secret_is_valid();

static void member_public_is_valid();

static void member_proof_checks();

int main()
{
    issuer_secrets_are_valid();

    issuer_proof_checks();

    member_secret_is_valid();

    member_proof_checks();

    member_public_is_valid();

    return 0;
}

void issuer_secrets_are_valid()
{
    printf("Starting context::issuer_secrets_are_valid...\n");

    csprng rng;
    seed_rng(&rng);

    issuer_secret_key_t sk1;
    issuer_public_key_t pk1;
    generate_issuer_key_pair(&pk1, &sk1, &rng);

    assert(BIG_256_56_comp(sk1.x, sk1.y) != 0);
    assert(!pk1.X.inf);
    assert(!pk1.Y.inf);

    issuer_secret_key_t sk2;
    issuer_public_key_t pk2;
    generate_issuer_key_pair(&pk2, &sk2, &rng);
    assert(BIG_256_56_comp(sk1.x, sk2.x) != 0);
    assert(BIG_256_56_comp(sk1.y, sk2.y) != 0);
    KILL_CSPRNG(&rng);

    printf("\tsuccess\n");
}

void issuer_proof_checks()
{
    // TODO: Check signature (c, sx, sy) in issuer's key
}

void member_secret_is_valid()
{
    printf("Starting context::member_secret_is_valid...\n");

    csprng rng;
    seed_rng(&rng);

    member_join_secret_key_t sk1;
    member_join_public_key_t pk1;
    generate_member_join_key_pair(&pk1, &sk1, &rng);

    assert(!pk1.Q.inf);

    member_join_secret_key_t sk2;
    member_join_public_key_t pk2;
    generate_member_join_key_pair(&pk2, &sk2, &rng);
    assert(BIG_256_56_comp(sk1.sk, sk2.sk) != 0);

    KILL_CSPRNG(&rng);

    printf("\tsuccess\n");
}

void member_public_is_valid()
{
    printf("Starting context::member_public_is_valid...\n");

    csprng rng;
    seed_rng(&rng);

    member_join_secret_key_t sk;
    member_join_public_key_t pk;
    generate_member_join_key_pair(&pk, &sk, &rng);

#define SERIALIZED_POINT_SIZE 65
    char public_key_as_bytes[65];
    octet public_key_as_oct;
    public_key_as_oct.max = 2*MODBYTES_256_56+1;
    public_key_as_oct.len = 2*MODBYTES_256_56+1;
    assert(public_key_as_oct.len == SERIALIZED_POINT_SIZE);
    public_key_as_oct.val = public_key_as_bytes;

    ECP_BN254_toOctet(&public_key_as_oct, &pk.Q);

    assert(ECP_BN254_PUBLIC_KEY_VALIDATE(&public_key_as_oct) == 0);

    printf("\tsuccess\n");
}

void member_proof_checks()
{
    // TODO: Check signature (c, s) in member's key
}

void seed_rng(csprng *rng)
{
#define SEED_LEN 256
    char seed_as_bytes[SEED_LEN];
    randombytes_buf(seed_as_bytes, SEED_LEN);
    octet seed = {.len=SEED_LEN, .max=SEED_LEN, .val=seed_as_bytes};
    CREATE_CSPRNG(rng, &seed);
}
