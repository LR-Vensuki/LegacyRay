#include "randombytes.h"

#include <openssl/rand.h>
#include <stdlib.h>

void randombytes(uint8_t *out, size_t outlen) {
    /* RAND_bytes aborts the process on a PRNG failure path only through the
       caller checking its return; ML-KEM key material must never silently
       fall back to weaker entropy, so treat a failure as fatal here too */
    if (RAND_bytes(out, (int)outlen) != 1) {
        abort();
    }
}
