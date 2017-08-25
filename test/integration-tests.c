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

#include <xaptum-ecdaa.h>

#include <amcl/pair_BN254.h>
#include <amcl/randapi.h>

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

static void gen_keypair(ECP_BN254 *pub_out, BIG_256_56 *priv_out, csprng *RNG);

static void do_dh(ECP_BN254 *secret_out, ECP_BN254 *other_pub, BIG_256_56 my_priv);

static void basic_test();

int main()
{
    basic_test();

    return 0;
}

void basic_test()
{
    printf("Starting integration::basic_test...\n");

    csprng RNG;
    char seed_as_bytes[] = {0};
    octet seed = {.len=1, .max=1, .val=seed_as_bytes};
    CREATE_CSPRNG(&RNG, &seed);

    ECP_BN254 pub_one;
    BIG_256_56 priv_one;
    gen_keypair(&pub_one, &priv_one, &RNG);

    ECP_BN254 pub_two;
    BIG_256_56 priv_two;
    gen_keypair(&pub_two, &priv_two, &RNG);

    ECP_BN254 secret_one;
    do_dh(&secret_one, &pub_two, priv_one);

    ECP_BN254 secret_two;
    do_dh(&secret_two, &pub_one, priv_two);

    assert(1 == ECP_BN254_equals(&secret_one, &secret_two));
    
    KILL_CSPRNG(&RNG);

    printf("\tsuccess\n");
}

void gen_keypair(ECP_BN254 *pub_out, BIG_256_56 *priv_out, csprng *RNG)
{
    // Set basepoint
    BIG_256_56 gx;
    BIG_256_56 gy;
    BIG_256_56_rcopy(gx, CURVE_Gx_BN254); /* rcopy -> r for "ROM" (i.e. const) */
    BIG_256_56_rcopy(gy, CURVE_Gy_BN254);
    ECP_BN254_set(pub_out, gx, gy);

    // Generate priv key
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    BIG_256_56_randomnum(*priv_out, curve_order, RNG);
    // char priv_as_bytes[1];
    // priv_as_bytes[0] = rand() % 255;
    // BIG_256_56_fromBytesLen(*priv_out, priv_as_bytes, 1);

    // Multiply basepoint by priv_out
    ECP_BN254_mul(pub_out, *priv_out);
}

void do_dh(ECP_BN254 *secret_out, ECP_BN254 *other_pub, BIG_256_56 my_priv)
{
    ECP_BN254_copy(secret_out, other_pub);
    ECP_BN254_mul(secret_out, my_priv);
}
