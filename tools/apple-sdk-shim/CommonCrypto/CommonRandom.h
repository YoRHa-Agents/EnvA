#ifndef ENVA_COMMONRANDOM_H
#define ENVA_COMMONRANDOM_H

#include <stddef.h>
#include <CommonCrypto/CommonCryptoError.h>

#ifdef __cplusplus
extern "C" {
#endif

CCRNGStatus CCRandomGenerateBytes(void *bytes, size_t count);

#ifdef __cplusplus
}
#endif

#endif
