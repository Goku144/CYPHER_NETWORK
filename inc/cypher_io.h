#include "cypher.h"

#if !defined(__CY_IO__)
#define __CY_IO__

/**
 * Read all available bytes from `fd` (until EOF) into `buf` (malloc/realloc-managed).
 */
void cy_read(int fd, CY_BUFF *buf);

/**
 * Write the entire payload of `buf` to `fd`, handling partial writes.
 */
void cy_write(int fd, const CY_BUFF buf);

/**
 * Read a single line (up to and including '\n') from `fd` into `buf`.
 */
void cy_read_line(int fd, CY_BUFF *buf);

/**
 * Receive one framed message from socket `fd`: read header, parse it, then read payload into `buf`.
 */
void cy_recv(int fd, CY_BUFF *buf);

/**
 * Send one framed message to socket `fd`: serialize header then send header+payload from `buf`.
 */
void cy_send(int fd, const CY_BUFF buf);

/**
 * Interactive plaintext full-duplex: forward stdin->socket and socket->stdout using the framing layer.
 */
void cy_normal_full_duplex(int fd);

/**
 * Interactive AES full-duplex: encrypt stdin frames with `ekey`, decrypt received frames, then print.
 */
void cy_aes_full_duplex(int fd, const CY_AES_EKEY ekey);

/**
 * Interactive RSA full-duplex: RSA-encrypt outbound frames with `pubkey` and RSA-decrypt inbound with `prvkey`.
 */
void cy_rsa_full_duplex(int fd, const mpz_t *pubkey, const mpz_t *prvkey);

/**
 * Pad + AES-encrypt `buf` in-place (16-byte blocks), set encryption flags, then send as a framed message.
 */
void cy_aes_send_encrypted(int fd, CY_BUFF buf, const CY_AES_EKEY ekey);

/**
 * Receive one framed message, AES-decrypt payload in-place, clear encryption flags, then remove padding.
 */
void cy_aes_recv_decrypted(int fd, CY_BUFF *buf, const CY_AES_EKEY ekey);

/**
 * RSA-pack and encrypt a buffer: RSA-encrypt bytes from `in` with `pubkey` into an encoded `out` buffer.
 */
void cy_rsa_encrypted(const CY_BUFF in, const mpz_t *pubkey, CY_BUFF *out);

/**
 * RSA-unpack and decrypt a buffer: decode RSA-packed ciphertext from `in`, decrypt with `prvkey`, output plaintext in `out`.
 */
void cy_rsa_decrypted(const CY_BUFF in, const mpz_t *prvkey, CY_BUFF *out);

/**
 * RSA-encrypt + send: encrypt `buf` with `pubkey`, set framing/encryption flags, then transmit.
 */
void cy_rsa_send_encrypted(int fd, CY_BUFF buf, const mpz_t *pubkey);

/**
 * RSA-recv + decrypt: receive a framed RSA message, decrypt with `prvkey`, clear flags, and return plaintext in `buf`.
 */
void cy_rsa_recv_decrypted(int fd, CY_BUFF *buf, const mpz_t *prvkey);

#endif // __CY_IO__
