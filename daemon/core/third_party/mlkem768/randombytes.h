#ifndef PQCLEAN_MLKEM768_RANDOMBYTES_H
#define PQCLEAN_MLKEM768_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

/* PQClean's kem.c calls this for key generation and encapsulation coins;
   senko already trusts OpenSSL's RAND_bytes for every other key (see
   reality_handshake.c), so route through the same source here instead of
   pulling in PQClean's own OS-specific randombytes.c */
void randombytes(uint8_t *out, size_t outlen);

#endif
