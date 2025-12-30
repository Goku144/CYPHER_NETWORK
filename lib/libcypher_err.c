#include <errno.h>
#include <stdlib.h>
#include "../inc/cypher_const.h"
#include "../inc/cypher_err.h"

void cy_state(const char *str, int _errnum)
{
    if(errno == 0)
        fprintf(stderr, "%s\n", str);
    else
        perror(str);
    exit(_errnum);
}