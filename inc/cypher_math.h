#include <gmp.h>

#if !defined(__CY_MATH__)
#define __CY_MATH__

/**
 * Compute the greatest common divisor gcd(a, b) and store it into `out`.
 */
void gcd(mpz_srcptr a, mpz_srcptr b, mpz_ptr out);

/**
 * Extended Euclidean algorithm: compute the modular inverse of `a` modulo `n` (a^{-1} mod n) into `out`.
 */
void EEA(mpz_srcptr a, mpz_srcptr n, mpz_ptr out);

/**
 * Generate a probable prime `p` of exactly `bitsize` bits using random candidates + primality testing.
 */
void cy_rsa_prime_prob_gen(const mp_bitcnt_t bitsize, mpz_ptr p);

#endif // __CY_MATH__
