#include "tpm/hmac.h"
#include "tpm/sable_tpm.h"


void do_xor(BYTE *in1, BYTE *in2, BYTE *out, UINT32 size){
   for(UINT32 i=0;i<size;i++)
      out[i]=in1[i]^in2[i];
}

void pad(BYTE *in, BYTE val, BYTE insize, BYTE outsize){
    grub_memset(in + insize, val, outsize-insize);
}

void
hmac_init(struct HMAC_Context *hctx, BYTE *key, UINT32 key_size)
{
    HMAC_OPad *ipad = grub_malloc(sizeof(HMAC_OPad));
		if (ipad == NULL)
		{
			grub_printf("\nCould not allocate memory for 'ipad'\n");
			return;
		}
		grub_memset(ipad, 0, sizeof(HMAC_OPad));

    grub_memset(hctx->key, 0, HMAC_BLOCK_SIZE);
    grub_memset(ipad->pad, 0x36, HMAC_BLOCK_SIZE);

    if (key_size <= HMAC_BLOCK_SIZE)
        memcpy(hctx->key, key, key_size);
    else
    {
        sha1_init(&hctx->ctx);   
        sha1(&hctx->ctx, key, key_size);
        sha1_finish(&hctx->ctx);
        memcpy(hctx->key, hctx->ctx.hash, TCG_HASH_SIZE);
    }

    do_xor(ipad->pad, hctx->key, ipad->pad, HMAC_BLOCK_SIZE);

    sha1_init(&hctx->ctx);
    sha1(&hctx->ctx, ipad->pad, HMAC_BLOCK_SIZE);

    // cleanup
    grub_free(ipad);
}

void hmac(struct HMAC_Context *hctx, BYTE *text, BYTE textsize)
{
    sha1(&hctx->ctx, text, textsize);
}

void hmac_finish(struct HMAC_Context *hctx)
{
    HMAC_OPad *opad = grub_malloc(sizeof(HMAC_OPad));
		if (opad == NULL)
		{
			grub_printf("\nCould not allocate memory for 'opad'\n");
			return;
		}
    TPM_DIGEST *hash = grub_malloc(sizeof(TPM_DIGEST));
		if (hash == NULL)
		{
			grub_printf("\nCould not allocate memory for 'hash'\n");
			return;
		}

    sha1_finish(&hctx->ctx);

    grub_memset(opad->pad, 0x5c, HMAC_BLOCK_SIZE);
    do_xor(opad->pad, hctx->key, opad->pad, HMAC_BLOCK_SIZE);
    memcpy(hash->digest, hctx->ctx.hash, TCG_HASH_SIZE);

    sha1_init(&hctx->ctx);
    sha1(&hctx->ctx, opad->pad, HMAC_BLOCK_SIZE);
    sha1(&hctx->ctx, hash->digest, TCG_HASH_SIZE);
    sha1_finish(&hctx->ctx);

    // cleanup
    grub_free(opad);
    grub_free(hash);
}
