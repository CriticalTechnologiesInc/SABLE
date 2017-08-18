#include "tpm/sha.h"

#define HMAC_BLOCK_SIZE  64

struct HMAC_Context
{
  struct SHA1_Context ctx;
  BYTE key[HMAC_BLOCK_SIZE];
};

typedef struct tdHMAC_OPad
{
  BYTE pad[HMAC_BLOCK_SIZE];
} HMAC_OPad;

typedef HMAC_OPad HMAC_IPad;

void do_xor(BYTE *in1, BYTE *in2, BYTE *out, UINT32 size);
void pad(BYTE *in, BYTE val, BYTE insize, BYTE outsize);
void hmac_init(struct HMAC_Context *hctx, BYTE *key, UINT32 key_size);
void hmac(struct HMAC_Context *hctx, BYTE *text, BYTE textsize);
void hmac_finish(struct HMAC_Context *hctx);
