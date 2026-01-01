#include "cypher.h"

#if !defined(__CY_ERR__)
#define __CY_ERR__

/**
 * Print an error message (perror if errno != 0) and terminate the program with `_errnum`.
 */
void cy_state(const char *str, int _errnum);

#endif // __CY_ERR__
