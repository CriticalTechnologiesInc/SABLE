#define HMAC_BLOCK_SIZE 64

typedef struct {
  BYTE key[HMAC_BLOCK_SIZE];
  SHA1_Context sctx;
} HMAC_Context;

void hmac_init(HMAC_Context *ctx, const BYTE *key, UINT32 keySize);
void hmac(HMAC_Context *ctx, const void *data, UINT32 dataSize);
void hmac_finish(HMAC_Context *ctx);
