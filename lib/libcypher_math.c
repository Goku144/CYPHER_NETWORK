/*
 * Copyright (c) 2025 Jebbari Marouane
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../inc/cypher_err.h"
#include "../inc/cypher_rand.h"
#include "../inc/cypher_math.h"

void gcd(mpz_srcptr a, mpz_srcptr b, mpz_ptr out)
{
    mpz_t tmpa, tmpb; mpz_inits(tmpa, tmpb, NULL);
    mpz_set(tmpa, a); mpz_set(tmpb, b);

    if(!mpz_cmp_ui(tmpa, 0)) {mpz_set(out, tmpb); return;}
    if(!mpz_cmp_ui(tmpb, 0)) {mpz_set(out, tmpa); return;}

    mpz_abs(tmpa, tmpa);
    mpz_abs(tmpb, tmpb);

    mpz_t r; mpz_init(r);
    while (mpz_cmp_ui(tmpb, 0))
    {
        mpz_mod(r, tmpa, tmpb);
        mpz_swap(tmpa, tmpb);
        mpz_swap(tmpb, r);
    }
    mpz_set(out, tmpa);
    mpz_clears(tmpa, tmpb, r, NULL);
}

void EEA(mpz_srcptr a, mpz_srcptr n, mpz_ptr out)
{
    gcd(a, n, out);
    if (mpz_cmp_ui(out, 1) != 0) cy_state("EEA: gcd is diffrent than 1", 0);

    mpz_t tmpa, tmpn; mpz_inits(tmpa, tmpn, NULL);
    mpz_set(tmpa, a); mpz_set(tmpn, n);

    // __t represent t-2 and _t represent t-1
    mpz_t __x, _x, mod, x, r; 
    mpz_inits(__x, _x, x, mod, r, NULL);
    mpz_set_ui(__x, 1); mpz_set_ui(_x, 0); mpz_set(mod, tmpn);

    while (mpz_cmp_ui(tmpn, 0))
    {
        mpz_mod(r, tmpa, tmpn);
        mpz_div(out, tmpa, tmpn); 
        mpz_mul(out, _x, out); 
        mpz_sub(x, __x, out);
        mpz_swap(__x, _x); 
        mpz_swap(_x, x);
        mpz_swap(tmpa, tmpn);
        mpz_swap(tmpn, r);
    }

    mpz_mod(out, __x, mod);
    mpz_add(out, out, mod);
    mpz_mod(out, out, mod);
    mpz_clears(tmpa, tmpn, x, _x, __x, mod, r,NULL);
}

void cy_rsa_prime_prob_gen(const mp_bitcnt_t bitsize, mpz_ptr p)
{
    mpz_t limit;
    mpz_init(limit);

    /* limit = 2^bitsize */
    mpz_set_ui(limit, 0);
    mpz_setbit(limit, bitsize);

    do {
        cy_random_mpz(limit, p);

        /* force exact bitsize + odd */
        if (bitsize > 0) mpz_setbit(p, bitsize - 1);
        mpz_setbit(p, 0);

    } while (mpz_probab_prime_p(p, 100) == 0);

    mpz_clear(limit);
}