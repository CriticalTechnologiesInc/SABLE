#ifndef __HMAC_H__
#define __HMAC_H__

#define HMAC_BLOCK_SIZE 64

typedef struct {
  BYTE key[HMAC_BLOCK_SIZE];
  SHA1_Context sctx;
} HMAC_Context;

/* EXCEPT: ERROR_SHA1_DATA_SIZE */
RESULT hmac_init(HMAC_Context *ctx, const BYTE *key, UINT32 keySize);
/* EXCEPT: ERROR_SHA1_DATA_SIZE */
RESULT hmac(HMAC_Context *ctx, const void *data, UINT32 dataSize);
/* EXCEPT: ERROR_SHA1_DATA_SIZE */
RESULT hmac_finish(HMAC_Context *ctx);

#endif
