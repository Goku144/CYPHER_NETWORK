#include "cypher.h"

#if !defined(__CY_MATH__)
#define __CY_MATH__

void gcd(mpz_srcptr a, mpz_srcptr b, mpz_ptr out);

void EEA(mpz_srcptr a, mpz_srcptr n, mpz_ptr out);

void cy_rsa_prime_prob_gen(const mp_bitcnt_t bitsize, mpz_ptr p);

#endif // __CY_MATH__
