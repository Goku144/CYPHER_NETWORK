#include "cypher.h"

#if !defined(__CY_RAND__)
#define __CY_RAND__

void cy_getrand(const size_t len, uint8_t **buf);

void cy_rand_bytes(uint8_t *dst, size_t len);

void cy_random_mpz(mpz_srcptr n, mpz_ptr out);

#endif // __CY_RAND__
