#include "sha.h"

#define HMAC_BLOCK_SIZE  64

struct HContext
{
  struct Context ctx;
  BYTE key[HMAC_BLOCK_SIZE];
};

void do_xor(BYTE *in1, BYTE *in2, BYTE *out, UINT32 size);
void pad(BYTE *in, BYTE val, BYTE insize, BYTE outsize);
void hmac_init(struct HContext *hctx, BYTE *key, UINT32 key_size);
void hmac(struct HContext *hctx, BYTE *text, BYTE textsize);
void hmac_finish(struct HContext *hctx);
