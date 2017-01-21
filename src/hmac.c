#include "hmac.h"
#include "tcg.h"
#include "util.h"

typedef struct HMAC_OPad { BYTE pad[HMAC_BLOCK_SIZE]; } HMAC_OPad;
typedef HMAC_OPad HMAC_IPad;

void hmac_init(HMAC_Context *ctx, const BYTE *key, UINT32 keySize) {
  HMAC_OPad ipad;

  memset(ctx->key, 0, HMAC_BLOCK_SIZE);
  memset(ipad.pad, 0x36, HMAC_BLOCK_SIZE);

  if (keySize <= HMAC_BLOCK_SIZE)
    memcpy(ctx->key, key, keySize);
  else {
    sha1_init(&ctx->sctx);
    sha1(&ctx->sctx, key, keySize);
    sha1_finish(&ctx->sctx);
    memcpy(ctx->key, ctx->sctx.hash.digest, sizeof(TPM_DIGEST));
  }

  do_xor(ipad.pad, ctx->key, ipad.pad, HMAC_BLOCK_SIZE);

  sha1_init(&ctx->sctx);
  sha1(&ctx->sctx, ipad.pad, HMAC_BLOCK_SIZE);
}

void hmac(HMAC_Context *ctx, const void *data, UINT32 dataSize) {
  sha1(&ctx->sctx, data, dataSize);
}

void hmac_finish(HMAC_Context *ctx) {
  HMAC_OPad opad;
  sha1_finish(&ctx->sctx);
  TPM_DIGEST hash = ctx->sctx.hash;

  memset(opad.pad, 0x5c, HMAC_BLOCK_SIZE);
  do_xor(opad.pad, ctx->key, opad.pad, HMAC_BLOCK_SIZE);

  sha1_init(&ctx->sctx);
  sha1(&ctx->sctx, opad.pad, HMAC_BLOCK_SIZE);
  sha1(&ctx->sctx, hash.digest, TPM_SHA1_160_HASH_LEN);
  sha1_finish(&ctx->sctx);
}
