#include "cypher.h"

#if !defined(__CY_KEY__)
#define __CY_KEY__

void cy_u64_be_exp(uint64_t v, uint8_t out[8]);

uint64_t cy_u64_be_imp(const uint8_t in[8]);

#endif // __CY_KEY__
