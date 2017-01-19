#include "sha.h"

#define HMAC_BLOCK_SIZE 64

typedef struct tdHMAC_OPad { BYTE pad[HMAC_BLOCK_SIZE]; } HMAC_OPad;

typedef HMAC_OPad HMAC_IPad;

void do_xor(BYTE *in1, BYTE *in2, BYTE *out, UINT32 size);
void pad(BYTE *in, BYTE val, BYTE insize, BYTE outsize);
void hmac_init(const BYTE *key, UINT32 key_size);
void hmac(const void *data, UINT32 dataSize);
TPM_DIGEST hmac_finish(void);
