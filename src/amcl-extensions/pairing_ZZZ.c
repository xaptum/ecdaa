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

#include "./pairing_ZZZ.h"

#include <amcl/fp2_ZZZ.h>
#include <amcl/pair_ZZZ.h>

void compute_pairing_ZZZ(FP12_YYY *pairing_out,
                         ECP_ZZZ *g1_point,
                         ECP2_ZZZ *g2_point)
{
    PAIR_ZZZ_ate(pairing_out, g2_point, g1_point);
    PAIR_ZZZ_fexp(pairing_out);
}
