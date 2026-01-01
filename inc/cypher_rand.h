#include <stdint.h>
#include <stddef.h>
#include <gmp.h>


#if !defined(__CY_RAND__)
#define __CY_RAND__

/**
 * Allocate `len` bytes into `*buf` and fill them with kernel randomness (getrandom).
 */
void cy_getrand(const size_t len, uint8_t **buf);

/**
 * Fill `dst` with `len` random bytes from the kernel (getrandom).
 */
void cy_rand_bytes(uint8_t *dst, size_t len);

/**
 * Generate a uniform random integer `out` such that 0 <= out < n (rejection sampling).
 */
void cy_random_mpz(mpz_srcptr n, mpz_ptr out);

#endif // __CY_RAND__
