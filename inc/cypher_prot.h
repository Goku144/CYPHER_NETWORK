#include "cypher.h"

#if !defined(__CY_PROT__)
#define __CY_PROT__

void cy_pad_add(CY_BUFF *buff);

void cy_pad_rmv(CY_BUFF *buff);

void cy_header_exp(const CY_BUFF buff, uint8_t *newbuff);

void cy_header_imp(const uint8_t *buff, CY_BUFF *newbuff);

#endif // __CY_PROT__