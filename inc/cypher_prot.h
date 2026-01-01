#include "cypher.h"

#if !defined(__CY_PROT__)
#define __CY_PROT__


/**
 * Apply PKCS#7-style padding to `buff` (AES block size) and update header padding fields.
 */
void cy_pad_add(CY_BUFF *buff);

/**
 * Remove PKCS#7-style padding from `buff` using the padding length stored in the buffer/header.
 */
void cy_pad_rmv(CY_BUFF *buff);

/**
 * Serialize the CY_BUFF header into a network byte-order byte array `out`.
 */
void cy_header_exp(const CY_BUFF buff, uint8_t *out);

/**
 * Parse a network-order header byte array `in` into `*b` (fills b->head fields).
 */
void cy_header_imp(const uint8_t *in, CY_BUFF *b);

/**
 * Create/bind/listen an IPv4 TCP server on `port`, accept one client, and return the connected socket in `*clsd`.
 */
void cy_inet_server(const char *port, int *clsd);

/**
 * Connect as an IPv4 TCP client to `ipv4:port` and return the connected socket in `*servsd`.
 */
void cy_inet_client(const char *ipv4, const char *port, int *servsd);

#endif // __CY_PROT__