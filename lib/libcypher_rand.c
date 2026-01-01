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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/random.h>

#include "../inc/cypher_err.h"
#include "../inc/cypher_rand.h"

void cy_getrand(const size_t len, uint8_t **buf)
{
    size_t fs = 0;
    *buf = malloc(len);
    if(!*buf) cy_state(__func__, -1); 
    while (1)
    {
        ssize_t n = getrandom(*buf + fs, len - fs, 0);
        if(n == 0) break;
        if(n < 0) cy_state(__func__, -1);
        fs += n;
    }
}

void cy_rand_bytes(uint8_t *dst, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = getrandom(dst + off, len - off, 0);
        if (n <= 0) cy_state("getrandom", -1);
        off += (size_t)n;
    }
}

/* uniform random: 0 <= out < n (rejection) */
void cy_random_mpz(mpz_srcptr n, mpz_ptr out)
{
    if (!out || mpz_sgn(n) <= 0) cy_state("cy_random_mpz: bad args", 0);

    size_t bits  = mpz_sizeinbase(n, 2);
    size_t bytes = (bits + 7) / 8;
    if (bytes == 0) { mpz_set_ui(out, 0); return; }

    uint8_t *buf = (uint8_t*)malloc(bytes);
    if (!buf) cy_state("malloc", -1);

    for (;;)
    {
        cy_rand_bytes(buf, bytes);

        /* trim top bits so rejection rate is sane */
        if ((bits & 7) != 0)
        {
            uint8_t mask = (uint8_t)((1u << (bits & 7)) - 1u);
            buf[0] &= mask;
        }

        mpz_import(out, bytes, 1, 1, 1, 0, buf); /* big-endian */
        if (mpz_cmp(out, n) < 0) { free(buf); return; }
    }
}