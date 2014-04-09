#include "util.h"
#include "hmac.h"
#include "sable_tpm.h"

void do_xor(BYTE *in1, BYTE *in2, BYTE *out, UINT32 size){
   for(UINT32 i=0;i<size;i++)
      out[i]=in1[i]^in2[i];
}

void pad(BYTE *in, BYTE val, BYTE insize, BYTE outsize){
    memset(in + insize, val, outsize-insize);
}

void
hmac_init(struct HContext *hctx, BYTE *key, UINT32 key_size)
{
    BYTE ipad[HMAC_BLOCK_SIZE];

    memset(hctx->key, 0, HMAC_BLOCK_SIZE);
    memset(ipad, 0x36, HMAC_BLOCK_SIZE);

    if (key_size <= HMAC_BLOCK_SIZE)
        memcpy(hctx->key, key, key_size);
    else
    {
        sha1_init(&hctx->ctx);   
        sha1(&hctx->ctx, key, key_size);
        sha1_finish(&hctx->ctx);
        memcpy(hctx->key, hctx->ctx.hash, TCG_HASH_SIZE);
    }

    do_xor(ipad, hctx->key, ipad, HMAC_BLOCK_SIZE);

    sha1_init(&hctx->ctx);
    sha1(&hctx->ctx, ipad, HMAC_BLOCK_SIZE);
}

void hmac(struct HContext *hctx, BYTE *text, BYTE textsize)
{
    sha1(&hctx->ctx, text, textsize);
}

void hmac_finish(struct HContext *hctx)
{
    BYTE opad[HMAC_BLOCK_SIZE];
    BYTE hash[TCG_HASH_SIZE];

    sha1_finish(&hctx->ctx);

    memset(opad, 0x5c, HMAC_BLOCK_SIZE);
    do_xor(opad, hctx->key, opad, HMAC_BLOCK_SIZE);
    memcpy(hash, hctx->ctx.hash, TCG_HASH_SIZE);

    sha1_init(&hctx->ctx);
    sha1(&hctx->ctx, opad, HMAC_BLOCK_SIZE);
    sha1(&hctx->ctx, hash, TCG_HASH_SIZE);
    sha1_finish(&hctx->ctx);
}
