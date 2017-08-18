/*
 * \brief   TPM commands compiled with the TCG TPM Spec v1.2.
 * \date    2006-03-28
 * \author  Bernhard Kauer <kauer@tudos.org>
 */
/*
 * Copyright (C) 2006,2007,2010  Bernhard Kauer <kauer@tudos.org>
 * Technische Universitaet Dresden, Operating Systems Research Group
 *
 * This file is part of the OSLO package, which is distributed under
 * the  terms  of the  GNU General Public Licence 2.  Please see the
 * COPYING file for details.
 */


#include "tpm/sable_tpm.h"


/**
 * Send a startup to the TPM.
 *
 * Note: We could use the TPM_TRANSMIT_FUNC macro, but this generates smaller code.
 */
TPM_RESULT 
TPM_Start_OIAP(BYTE *in_buffer, SessionCtx *sctx){
    TPM_RESULT res;

		TPM_COMMAND *com = grub_malloc(sizeof(TPM_COMMAND));
		if (com == NULL)
		{
			grub_printf("\nCould not allocate memory for 'com'\n");
			return GRUB_ERR_IO;
		}
		grub_memset(com, 0, sizeof(TPM_COMMAND));

    UINT32 tpm_offset_out = 0;
    UINT32 paramSize = 10;
  	BYTE *out_buffer = grub_malloc(paramSize);
		if (out_buffer == NULL)
		{
			grub_printf("\nCould not allocate memory for 'out_buffer'\n");
			grub_free(com);
			return GRUB_ERR_IO;
		}
		grub_memset(out_buffer, 0, paramSize);
    
    // construct header
    com->tag = ntohs(TPM_TAG_RQU_COMMAND);
    com->paramSize = ntohl(paramSize);
    com->ordinal = ntohl(TPM_ORD_OIAP);

		assert(TCG_BUFFER_SIZE >= tpm_offset_out + paramSize);

		BYTE *dp = (out_buffer + tpm_offset_out);
		const BYTE *sp = com;
		for (UINT32 i = 0; i < 2; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
		sp += 2;
		for (UINT32 i = 0; i < (paramSize-2); i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
	  tpm_offset_out += paramSize;

		tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE);

    res = (TPM_RESULT) ntohl(*(in_buffer+6));
    TPM_COPY_FROM((BYTE *)&sctx->authHandle,0,4);
    TPM_COPY_FROM((BYTE *)&sctx->nonceEven,4,20);
    TPM_GetRandom(in_buffer, sctx->nonceOdd.nonce, sizeof(TPM_NONCE));

    // cleanup
		grub_free(com);
    grub_free(out_buffer);

    return res;
}

TPM_RESULT
TPM_NV_ReadValueAuth(
        BYTE *in_buffer, 
        BYTE *data, 
        UINT32 dataSize, 
        SessionCtx *sctx)
{
    TPM_RESULT res;
    UINT32 tpm_offset_out = 0;

    // designate buffers
    UINT32 paramSize = 67; //sizeof(stTPM_NV_READVALUE) + sizeof(SessionEnd)
    BYTE *out_buffer = grub_malloc(sizeof(stTPM_NV_READVALUE) + sizeof(SessionEnd));
		if (out_buffer == NULL)
		{
			grub_printf("\nCould not allocate memory for 'out_buffer'\n");
			return GRUB_ERR_IO;
		}
		grub_memset(out_buffer, 0, sizeof(stTPM_NV_READVALUE) + sizeof(SessionEnd));

    // declare data structures
    struct SHA1_Context *ctx = grub_malloc(sizeof(struct SHA1_Context));
		if (ctx == NULL)
		{
			grub_printf("\nCould not allocate memory for 'ctx'\n");
			grub_free(out_buffer);
			return GRUB_ERR_IO;
		}
		grub_memset(ctx, 0, sizeof(struct SHA1_Context));

    struct HMAC_Context *hctx = grub_malloc(sizeof(struct HMAC_Context));
		if (hctx == NULL)
		{
			grub_printf("\nCould not allocate memory for 'ctx'\n");
			grub_free(out_buffer);
			grub_free(ctx);
			return GRUB_ERR_IO;
		}
		grub_memset(hctx, 0, sizeof(struct HMAC_Context));

    stTPM_NV_READVALUE *com = grub_malloc(sizeof(stTPM_NV_READVALUE));
		if (com == NULL)
		{
			grub_printf("\nCould not allocate memory for 'com'\n");
			grub_free(out_buffer);
			grub_free(ctx);
			grub_free(hctx);
			return GRUB_ERR_IO;
		}
		grub_memset(com, 0, sizeof(stTPM_NV_READVALUE));
    
		SessionEnd *se = grub_malloc(sizeof(SessionEnd));
		if (se == NULL)
		{
			grub_printf("\nCould not allocate memory for 'se'\n");
			grub_free(out_buffer);
			grub_free(ctx);
			grub_free(hctx);
			grub_free(com);
			return GRUB_ERR_IO;
		}
		grub_memset(se, 0, sizeof(SessionEnd));

    TPM_AUTHDATA *authData = grub_malloc(sizeof(TPM_AUTHDATA));
		if (authData == NULL)
		{
			grub_printf("\nCould not allocate memory for 'authData'\n");
			grub_free(out_buffer);
			grub_free(ctx);
			grub_free(hctx);
			grub_free(com);
			grub_free(se);
			return GRUB_ERR_IO;
		}
		grub_memset(authData, 0, sizeof(TPM_AUTHDATA));

    // populate structures
    com->tag = ntohs(TPM_TAG_RQU_AUTH1_COMMAND);
    com->paramSize = ntohl(paramSize);
    com->ordinal = ntohl(TPM_ORD_NV_ReadValueAuth);
    com->nvIndex = ntohl(0x10000);  // HARDCODED
    com->offset = ntohl(0); // HARDCODED
    com->dataSize = ntohl(dataSize);

    se->authHandle = sctx->authHandle;
    se->nonceOdd = sctx->nonceOdd;
    se->continueAuthSession = FALSE;

    // generate hashes for crypto
    sha1_init(ctx);
    sha1(ctx, (BYTE *)&com->ordinal, sizeof(TPM_COMMAND_CODE));
    sha1(ctx, (BYTE *)&com->nvIndex, sizeof(TPM_NV_INDEX));
    sha1(ctx, (BYTE *)&com->offset, sizeof(UINT32));
    sha1(ctx, (BYTE *)&com->dataSize, sizeof(UINT32));
    sha1_finish(ctx);

    grub_memset(authData->authdata, 0, sizeof(TPM_AUTHDATA));

    hmac_init(hctx, authData->authdata, TCG_HASH_SIZE);
    hmac(hctx, ctx->hash, TCG_HASH_SIZE);
    hmac(hctx, sctx->nonceEven.nonce, sizeof(TPM_NONCE));
    hmac(hctx, se->nonceOdd.nonce, sizeof(TPM_NONCE));
    hmac(hctx, &se->continueAuthSession, sizeof(TPM_BOOL));
    hmac_finish(hctx);

    memcpy(se->pubAuth.authdata, hctx->ctx.hash, sizeof(TPM_AUTHDATA));

    UINT32 receivedDataSize;
    
    // package the entire command into a bytestream
//    SABLE_TPM_COPY_TO(com, sizeof(stTPM_NV_READVALUE));
		
		BYTE *dp = (out_buffer + tpm_offset_out);
		const BYTE *sp = com;
		for (UINT32 i = 0; i < 2; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
		sp += 2;
		for (UINT32 i = 0; i < 20; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
	  tpm_offset_out += 22;

//    SABLE_TPM_COPY_TO(se, sizeof(SessionEnd));

		dp = (out_buffer + tpm_offset_out);
		sp = se;
		for (UINT32 i = 0; i < 45; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
		
	  tpm_offset_out += 45;

    // transmit command to TPM

    tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE);

    res = (TPM_RESULT) ntohl(*((UINT32 *) (in_buffer + 6)));

    if (res == 0) {
	    receivedDataSize = (int) ntohl(*((UINT32 *) (in_buffer + 10)));
	    if (receivedDataSize > TCG_BUFFER_SIZE){

            grub_printf("\nBuffer overflow detected\n");

		    return res;
	    }
	    memcpy(data, in_buffer + 14, receivedDataSize);
    }

    // cleanup
    grub_free(out_buffer);
    grub_free(ctx);
    grub_free(hctx);
    grub_free(com);
    grub_free(se);
    grub_free(authData);

    return res;
}

TPM_RESULT TPM_Unseal(
        BYTE *in_buffer, 
        BYTE *inData, 
        BYTE *secretData,
        UINT32 secretDataBufSize,
        UINT32 *secretDataSize,
        SessionCtx *sctxParent, 
        SessionCtx *sctxEntity,
		TPM_AUTHDATA *dataHash,
		TPM_AUTHDATA *srkHash)
{
    TPM_RESULT res;
    struct SHA1_Context *ctx = grub_malloc(sizeof(struct SHA1_Context));
		if (ctx == NULL)
		{
			grub_printf("\nCould not allocate memory for 'ctx'\n");
			return GRUB_ERR_IO;
		}
		grub_memset(ctx, 0, sizeof(struct SHA1_Context));

    struct HMAC_Context *hctx = grub_malloc(sizeof(struct HMAC_Context));
		if (hctx == NULL)
		{
			grub_printf("\nCould not allocate memory for 'hctx'\n");
			grub_free(ctx);
			return GRUB_ERR_IO;
		}
		grub_memset(hctx, 0, sizeof(struct HMAC_Context));

    stTPM_UNSEAL *com = grub_malloc(sizeof(stTPM_UNSEAL));
		if (com == NULL)
		{
			grub_printf("\nCould not allocate memory for 'com'\n");
			grub_free(ctx);
			grub_free(hctx);
			return GRUB_ERR_IO;
		}
		grub_memset(com, 0, sizeof(stTPM_UNSEAL));

    SessionEnd *endBufParent = grub_malloc(sizeof(SessionEnd));
		if (endBufParent == NULL)
		{
			grub_printf("\nCould not allocate memory for 'endBufParent'\n");
			grub_free(ctx);
			grub_free(hctx);
			grub_free(com);
			return GRUB_ERR_IO;
		}
		grub_memset(endBufParent, 0, sizeof(SessionEnd));

    SessionEnd *endBufEntity = grub_malloc(sizeof(SessionEnd));
		if (endBufEntity == NULL)
		{
			grub_printf("\nCould not allocate memory for 'endBufEntity'\n");
			grub_free(ctx);
			grub_free(hctx);
			grub_free(com);
			grub_free(endBufParent);
			return GRUB_ERR_IO;
		}
		grub_memset(endBufEntity, 0, sizeof(SessionEnd));

    UINT32 sealInfoSize = ntohl(*((UINT32 *)(inData + 4)));
    UINT32 encDataSize= ntohl(*((UINT32 *)(inData + 8 + sealInfoSize)));
    UINT32 inDataSize = 12 + sealInfoSize + encDataSize;

    UINT32 tpm_offset_out = 0; 
    UINT32 paramSize = 14 + inDataSize + 2*45;
    BYTE *out_buffer = grub_malloc(paramSize);
		if (out_buffer == NULL)
		{
			grub_printf("\nCould not allocate memory for 'out_buffer'\n");
			grub_free(ctx);
			grub_free(hctx);
			grub_free(com);
			grub_free(endBufParent);
			grub_free(endBufEntity);
			return GRUB_ERR_IO;
		}
		grub_memset(out_buffer, 0, paramSize);

    com->tag = ntohs(TPM_TAG_RQU_AUTH2_COMMAND);
    com->paramSize = ntohl(paramSize);
    com->ordinal = ntohl(TPM_ORD_Unseal);
    com->parentHandle = ntohl(TPM_KH_SRK);

    endBufParent->authHandle = sctxParent->authHandle;
    endBufParent->nonceOdd = sctxParent->nonceOdd;
    endBufParent->continueAuthSession = FALSE;
	grub_printf("Setting Parent authdata\n");
    grub_memset(endBufParent->pubAuth.authdata, srkHash, sizeof(TPM_AUTHDATA)); // SRK Password
	grub_printf("Set Parent authdata\n");

    sha1_init(ctx);
    sha1(ctx, (BYTE *)&com->ordinal, sizeof(TPM_COMMAND_CODE));
    sha1(ctx, inData, inDataSize);
    sha1_finish(ctx);

    hmac_init(hctx, endBufParent->pubAuth.authdata, sizeof(TPM_AUTHDATA));
    hmac(hctx, ctx->hash, TCG_HASH_SIZE);
    hmac(hctx, sctxParent->nonceEven.nonce, sizeof(TPM_NONCE));
    hmac(hctx, endBufParent->nonceOdd.nonce, sizeof(TPM_NONCE));
    hmac(hctx, &endBufParent->continueAuthSession, sizeof(TPM_BOOL));
    hmac_finish(hctx);

    memcpy(&endBufParent->pubAuth, hctx->ctx.hash, sizeof(TPM_AUTHDATA));

    endBufEntity->authHandle = sctxEntity->authHandle;
    endBufEntity->nonceOdd = sctxEntity->nonceOdd;
    endBufEntity->continueAuthSession = FALSE;
	grub_printf("Setting Entity authdata\n");
    grub_memset(endBufEntity->pubAuth.authdata, dataHash, sizeof(TPM_AUTHDATA)); // Data Password
	grub_printf("Set Entity authdata\n");

    hmac_init(hctx, endBufEntity->pubAuth.authdata, sizeof(TPM_AUTHDATA));
    hmac(hctx, ctx->hash, TCG_HASH_SIZE);
    hmac(hctx, sctxEntity->nonceEven.nonce, sizeof(TPM_NONCE));
    hmac(hctx, endBufEntity->nonceOdd.nonce, sizeof(TPM_NONCE));
    hmac(hctx, &endBufEntity->continueAuthSession, sizeof(TPM_BOOL));
    hmac_finish(hctx);

    memcpy(&endBufEntity->pubAuth, hctx->ctx.hash, sizeof(TPM_AUTHDATA));

//    SABLE_TPM_COPY_TO(com, sizeof(stTPM_UNSEAL));
//    SABLE_TPM_COPY_TO(inData, inDataSize);
//    SABLE_TPM_COPY_TO(endBufParent, sizeof(SessionEnd));
//    SABLE_TPM_COPY_TO(endBufEntity, sizeof(SessionEnd));
	
		BYTE *dp = (out_buffer + tpm_offset_out);
		const BYTE *sp = com;
		for (UINT32 i = 0; i < 2; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
		sp += 2;
		for (UINT32 i = 0; i < 12; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
	  tpm_offset_out += 14;

//    SABLE_TPM_COPY_TO(se, sizeof(SessionEnd));

		sp = inData;
		for (UINT32 i = 0; i < inDataSize; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
		tpm_offset_out += inDataSize;

		sp = endBufParent;
		for (UINT32 i = 0; i < 45; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
		tpm_offset_out += 45;

		sp = endBufEntity;
		for (UINT32 i = 0; i < 45; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
		tpm_offset_out += 45;

    tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE);

    res = (int) ntohl(*((unsigned int *) (in_buffer+6)));
    if(res==0){
        *secretDataSize=ntohl(*((unsigned long*)(in_buffer+10)));
        //this check is necessary to prevent a buffer overflow

        if (*secretDataSize>secretDataBufSize)
				{
					grub_printf("\nsecret data too big for buffer\n");
					//should exit
				}
	
        memcpy((unsigned char *)secretData,in_buffer+14,*secretDataSize);
    }

    // cleanup
    grub_free(ctx);
    grub_free(hctx);
    grub_free(com);
    grub_free(endBufParent);
    grub_free(endBufEntity);
    grub_free(out_buffer);
     
    return res;
}

TPM_RESULT
TPM_GetRandom(
        BYTE *in_buffer, 
        BYTE *dest,
        UINT32 size)
{
    TPM_RESULT res;
    stTPM_GETRANDOM *com = grub_malloc(sizeof(stTPM_GETRANDOM));
		if (com == NULL)
		{
			grub_printf("\nCould not allocate memory for 'com'\n");
			return GRUB_ERR_IO;
		} 


    UINT32 tpm_offset_out = 0;
    UINT32 paramSize = 14;
    BYTE *out_buffer = grub_malloc(paramSize);
		if (out_buffer == NULL)
		{
			grub_printf("\nCould not allocate memory for 'out_buffer'\n");
			grub_free(com);			
			return GRUB_ERR_IO;
		}

    // construct header
    com->tag = ntohs(TPM_TAG_RQU_COMMAND);
    com->paramSize = ntohl(paramSize);
    com->ordinal = ntohl(TPM_ORD_GetRandom);

    com->bytesRequested = ntohl(size);

//    SABLE_TPM_COPY_TO(com, sizeof(stTPM_GETRANDOM));

				assert(TCG_BUFFER_SIZE >= tpm_offset_out + paramSize);
//	  memcpy(out_buffer + tpm_offset_out, SRC, SIZE);
		BYTE *dp = (out_buffer + tpm_offset_out);
		const BYTE *sp = com;
		for (UINT32 i = 0; i < 2; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
		sp += 2;
		for (UINT32 i = 0; i < (paramSize-2); i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
	  tpm_offset_out += paramSize;

    tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE);

    res = (TPM_RESULT) ntohl(*((UINT32 *) (in_buffer+6)));

    if (ntohl(*((unsigned int*)(in_buffer+10)))!=size)
		{
			grub_printf("\nCould not get enough random bytes from TPM\n");
		}

    TPM_COPY_FROM(dest,4,size);

    // cleanup
    grub_free(com);
    grub_free(out_buffer);

    return res;
}

