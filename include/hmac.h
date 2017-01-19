#include "sha.h"

#define HMAC_BLOCK_SIZE 64

#define HMAC_PROTO_GEN(Type) void hmac_##Type(Type val);

typedef struct tdHMAC_OPad { BYTE pad[HMAC_BLOCK_SIZE]; } HMAC_OPad;

typedef HMAC_OPad HMAC_IPad;

void do_xor(BYTE *in1, BYTE *in2, BYTE *out, UINT32 size);
void pad(BYTE *in, BYTE val, BYTE insize, BYTE outsize);
void hmac_init(const void *key_in, UINT32 key_size);
void hmac_ptr(const void *data, UINT32 dataSize);
HMAC_PROTO_GEN(BYTE);
HMAC_PROTO_GEN(UINT16);
HMAC_PROTO_GEN(UINT32);
HMAC_PROTO_GEN(TPM_DIGEST);
TPM_DIGEST hmac_finish(void);
