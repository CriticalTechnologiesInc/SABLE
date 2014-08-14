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


#include "include/alloc.h"
#include "include/sable_tpm.h"
#include "include/util.h"
#include "include/hmac.h"

// out = xor(authData, sha1(sharedSecret ++ nonceEven))
void 
encAuth_gen(
        TPM_AUTHDATA *auth, 
        BYTE *sharedSecret, 
        TPM_NONCE *nonceEven, 
        TPM_ENCAUTH *encAuth)
{
    struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);

    sha1_init(ctx);
    sha1(ctx, sharedSecret, TCG_HASH_SIZE);
    sha1(ctx, nonceEven->nonce, sizeof(TPM_NONCE));
    sha1_finish(ctx);

    do_xor(auth->authdata, ctx->hash, encAuth->authdata, TCG_HASH_SIZE);
}

TPM_RESULT 
TPM_Start_OIAP(BYTE *in_buffer, SessionCtx *sctx){
    TPM_RESULT res;
    TPM_COMMAND *com = alloc(heap, sizeof(TPM_COMMAND), 0);
    UINT32 tpm_offset_out = 0;
    UINT32 paramSize = sizeof(TPM_COMMAND);
    BYTE *out_buffer = alloc(heap, paramSize, 0);
    
    // construct header
    com->tag = ntohs(TPM_TAG_RQU_COMMAND);
    com->paramSize = ntohl(paramSize);
    com->ordinal = ntohl(TPM_ORD_OIAP);

    SABLE_TPM_COPY_TO(com, paramSize);
    ERROR(-1, tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0, "TPM_Start_OIAP() failed on transmit");

    res = (TPM_RESULT) ntohl(*(in_buffer+6));
    TPM_COPY_FROM((BYTE *)&sctx->authHandle,0,4);
    TPM_COPY_FROM((BYTE *)&sctx->nonceEven,4,20);
    TPM_GetRandom(in_buffer, sctx->nonceOdd.nonce, sizeof(TPM_NONCE));

    return res;
}

int TPM_Unseal(
        BYTE *in_buffer, 
        BYTE *inData, 
        BYTE *secretData,
        UINT32 secretDataBufSize,
        UINT32 *secretDataSize,
        SessionCtx *sctxParent, 
        SessionCtx *sctxEntity)
{
    TPM_RESULT res;
    struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
    struct HMAC_Context *hctx = alloc(heap, sizeof(struct HMAC_Context), 0);
    stTPM_UNSEAL *com = alloc(heap, sizeof(stTPM_UNSEAL), 0);
    SessionEnd *endBufParent = alloc(heap, sizeof(SessionEnd), 0);
    SessionEnd *endBufEntity = alloc(heap, sizeof(SessionEnd), 0);

    UINT32 sealInfoSize = ntohl(*((UINT32 *)(inData + 4)));
    UINT32 encDataSize= ntohl(*((UINT32 *)(inData + 8 + sealInfoSize)));
    UINT32 inDataSize = 12 + sealInfoSize + encDataSize;

    UINT32 tpm_offset_out = 0; 
    UINT32 paramSize = sizeof(stTPM_UNSEAL) + inDataSize + 2*sizeof(SessionEnd);
    BYTE *out_buffer = alloc(heap, paramSize, 0);

    com->tag = ntohs(TPM_TAG_RQU_AUTH2_COMMAND);
    com->paramSize = ntohl(paramSize);
    com->ordinal = ntohl(TPM_ORD_Unseal);
    com->parentHandle = ntohl(TPM_KH_SRK);

    endBufParent->authHandle = sctxParent->authHandle;
    endBufParent->nonceOdd = sctxParent->nonceOdd;
    endBufParent->continueAuthSession = FALSE;
    memset(endBufParent->pubAuth.authdata, 0, sizeof(TPM_AUTHDATA));

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
    memset(endBufEntity->pubAuth.authdata, 0, sizeof(TPM_AUTHDATA));

    hmac_init(hctx, endBufEntity->pubAuth.authdata, sizeof(TPM_AUTHDATA));
    hmac(hctx, ctx->hash, TCG_HASH_SIZE);
    hmac(hctx, sctxEntity->nonceEven.nonce, sizeof(TPM_NONCE));
    hmac(hctx, endBufEntity->nonceOdd.nonce, sizeof(TPM_NONCE));
    hmac(hctx, &endBufEntity->continueAuthSession, sizeof(TPM_BOOL));
    hmac_finish(hctx);

    memcpy(&endBufEntity->pubAuth, hctx->ctx.hash, sizeof(TPM_AUTHDATA));

    SABLE_TPM_COPY_TO(com, sizeof(stTPM_UNSEAL));
    SABLE_TPM_COPY_TO(inData, inDataSize);
    SABLE_TPM_COPY_TO(endBufParent, sizeof(SessionEnd));
    SABLE_TPM_COPY_TO(endBufEntity, sizeof(SessionEnd));

    ERROR(-1, tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0, "TPM_Unseal() failed on transmit");

    res = (int) ntohl(*((unsigned int *) (in_buffer+6)));
    if(res==0){
        *secretDataSize=ntohl(*((unsigned long*)(in_buffer+10)));
        //this check is necessary to prevent a buffer overflow
#ifdef EXEC
        ERROR(108,*secretDataSize>secretDataBufSize,"secret data too big for buffer");
#else
        ERROR(108,*secretDataSize>secretDataBufSize,&string_literal);
#endif

        memcpy((unsigned char *)secretData,in_buffer+14,*secretDataSize);
    }
      
    return res;
}

//this function assumes using PCRs 17 and 19
// this returns TPM_PCR_INFO_SHORT in buffer. 
void
getTPM_PCR_INFO_SHORT(
        BYTE *buffer, 
        sdTPM_PCR_INFO_SHORT *info, 
        sdTPM_PCR_SELECTION select)
{
    struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
    sdTPM_PCR_COMPOSITE *comp = alloc(heap, sizeof(sdTPM_PCR_COMPOSITE), 0);

    comp->select = select;
    comp->valueSize = ntohl(2 * sizeof(TPM_COMPOSITE_HASH));
    TPM_PcrRead(buffer, &comp->hash1, SLB_PCR_ORD);
    TPM_PcrRead(buffer, &comp->hash2, MODULE_PCR_ORD);

    info->pcrSelection = select;
    info->localityAtRelease = TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE;

    sha1_init(ctx);
    sha1(ctx, (BYTE *)comp, sizeof(sdTPM_PCR_COMPOSITE));
    sha1_finish(ctx);
    memcpy(info->digestAtRelease.digest, ctx->hash, sizeof(TPM_DIGEST));
}

TPM_RESULT TPM_NV_DefineSpace(
        BYTE *in_buffer, 
        sdTPM_PCR_SELECTION select,
        SessionCtx *sctx)
{
    TPM_RESULT res;
    UINT32 tpm_offset_out = 0;
    struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
    struct HMAC_Context *hctx = alloc(heap, sizeof(struct HMAC_Context), 0);

    // declare data structures
    TPM_NV_ATTRIBUTES *perm = alloc(heap, sizeof(TPM_NV_ATTRIBUTES), 0);
    TPM_AUTHDATA *authData = alloc(heap, sizeof(TPM_AUTHDATA), 0);
    sdTPM_PCR_INFO_SHORT *info = alloc(heap, sizeof(sdTPM_PCR_INFO_SHORT), 0);
    sdTPM_NV_DATA_PUBLIC *pub = alloc(heap, sizeof(sdTPM_NV_DATA_PUBLIC), 0);
    TPM_ENCAUTH *encAuth = alloc(heap, sizeof(TPM_ENCAUTH), 0);

    // declare the command
    stTPM_NV_DEFINESPACE *com = alloc(heap, sizeof(stTPM_NV_DEFINESPACE), 0);
    SessionEnd *se = alloc(heap, sizeof(SessionEnd), 0);

    // designate buffers
    UINT32 paramSize = sizeof(stTPM_NV_DEFINESPACE) + sizeof(SessionEnd);
    BYTE *out_buffer = alloc(heap, paramSize, 0);

    // populate the data structures
    perm->tag = ntohs(TPM_TAG_NV_ATTRIBUTES);
    perm->attributes = ntohl(TPM_NV_PER_AUTHWRITE | TPM_NV_PER_AUTHREAD);

    getTPM_PCR_INFO_SHORT(in_buffer, info, select);

    pub->tag = ntohs(TPM_TAG_NV_DATA_PUBLIC);
    pub->nvIndex = ntohl(NV_DATA_OFFSET);
    pub->pcrInfoRead = *info;
    pub->pcrInfoWrite = *info;
    pub->permission = *perm;
    pub->bReadSTClear = FALSE;
    pub->bWriteSTClear = FALSE;
    pub->bWriteDefine = FALSE;
    pub->dataSize = ntohl(NV_DATA_SIZE);

    memset(&authData->authdata, 0, TCG_HASH_SIZE);
    encAuth_gen(authData, sctx->sharedSecret, &sctx->nonceEven, encAuth);

    // populate the command
    com->tag = ntohs(TPM_TAG_RQU_AUTH1_COMMAND);
    com->paramSize = ntohl(paramSize);
    com->ordinal = ntohl(TPM_ORD_NV_DefineSpace);
    com->pubInfo = *pub;
    com->encAuth = *encAuth;

    sha1_init(ctx);
    sha1(ctx, (BYTE *)&com->ordinal, sizeof(TPM_COMMAND_CODE));
    sha1(ctx, (BYTE *)&com->pubInfo, sizeof(sdTPM_NV_DATA_PUBLIC));
    sha1(ctx, (BYTE *)&com->encAuth, sizeof(TPM_ENCAUTH));
    sha1_finish(ctx);

    se->authHandle = sctx->authHandle;
    res = TPM_GetRandom(in_buffer, se->nonceOdd.nonce, TCG_HASH_SIZE);
#ifdef EXEC
    CHECK4(108, res, "could not get random num from TPM", res);
#else
    CHECK4(108, res, &string_literal, res);
#endif
    se->continueAuthSession = FALSE;

    hmac_init(hctx, sctx->sharedSecret, TCG_HASH_SIZE);
    hmac(hctx, ctx->hash, TCG_HASH_SIZE);
    hmac(hctx, sctx->nonceEven.nonce, sizeof(TPM_NONCE));
    hmac(hctx, se->nonceOdd.nonce, sizeof(TPM_NONCE));
    hmac(hctx, &se->continueAuthSession, sizeof(TPM_BOOL));
    hmac_finish(hctx);

    memcpy(&se->pubAuth, hctx->ctx.hash, TCG_HASH_SIZE);
    
    // package the entire command into a bytestream
    SABLE_TPM_COPY_TO(com, sizeof(stTPM_NV_DEFINESPACE));
    SABLE_TPM_COPY_TO(se, sizeof(SessionEnd));

    // transmit command to TPM
    ERROR(-1, tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0, "TPM_NV_DefineSpace() failed on transmit");

    res = (TPM_RESULT) ntohl(*((UINT32 *) (in_buffer + 6)));

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
    UINT32 paramSize = sizeof(stTPM_NV_READVALUE) + sizeof(SessionEnd);
    BYTE *out_buffer = alloc(heap, paramSize, 0);

    // declare data structures
    struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
    struct HMAC_Context *hctx = alloc(heap, sizeof(struct HMAC_Context), 0);
    stTPM_NV_READVALUE *com = alloc(heap, sizeof(stTPM_NV_READVALUE), 0);
    SessionEnd *se = alloc(heap, sizeof(SessionEnd), 0);
    TPM_AUTHDATA *authData = alloc(heap, sizeof(TPM_AUTHDATA), 0);

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

    memset(authData->authdata, 0, sizeof(TPM_AUTHDATA));

    hmac_init(hctx, authData->authdata, TCG_HASH_SIZE);
    hmac(hctx, ctx->hash, TCG_HASH_SIZE);
    hmac(hctx, sctx->nonceEven.nonce, sizeof(TPM_NONCE));
    hmac(hctx, se->nonceOdd.nonce, sizeof(TPM_NONCE));
    hmac(hctx, &se->continueAuthSession, sizeof(TPM_BOOL));
    hmac_finish(hctx);

    memcpy(se->pubAuth.authdata, hctx->ctx.hash, sizeof(TPM_AUTHDATA));

    UINT32 receivedDataSize;
    
    // package the entire command into a bytestream
    SABLE_TPM_COPY_TO(com, sizeof(stTPM_NV_READVALUE));
    SABLE_TPM_COPY_TO(se, sizeof(SessionEnd));

    // transmit command to TPM
    ERROR(-1, tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0, "TPM_NV_ReadValueAuth() failed on transmit");

    res = (TPM_RESULT) ntohl(*((UINT32 *) (in_buffer + 6)));

    if (res == 0) {
	    receivedDataSize = (int) ntohl(*((UINT32 *) (in_buffer + 10)));
	    if (receivedDataSize > TCG_BUFFER_SIZE){
#ifdef EXEC
            out_string("\nBuffer overflow detected\n");
#else
            out_string(&string_literal);
#endif
		    return res;
	    }
	    memcpy(data, in_buffer + 14, receivedDataSize);
    }
    return res;

}


TPM_RESULT 
TPM_NV_WriteValueAuth(
        BYTE *in_buffer, 
        BYTE *data, 
        UINT32 dataSize, 
        SessionCtx *sctx)
{
    TPM_RESULT res;
    UINT32 tpm_offset_out = 0;

    // designate buffers
    UINT32 paramSize = sizeof(stTPM_NV_WRITEVALUE) + dataSize + sizeof(SessionEnd);
    BYTE *out_buffer = alloc(heap, paramSize, 0);

    // declare data structures
    struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
    struct HMAC_Context *hctx = alloc(heap, sizeof(struct HMAC_Context), 0);
    stTPM_NV_WRITEVALUE *com = alloc(heap, sizeof(stTPM_NV_WRITEVALUE), 0);
    SessionEnd *se = alloc(heap, sizeof(SessionEnd), 0);
    TPM_AUTHDATA *authData = alloc(heap, sizeof(TPM_AUTHDATA), 0);

    // populate structures
    com->tag = ntohs(TPM_TAG_RQU_AUTH1_COMMAND);
    com->paramSize = ntohl(paramSize);
    com->ordinal = ntohl(TPM_ORD_NV_WriteValueAuth);
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
    sha1(ctx, data, dataSize);
    sha1_finish(ctx);

    memset(authData->authdata, 0, sizeof(TPM_AUTHDATA));

    hmac_init(hctx, authData->authdata, TCG_HASH_SIZE);
    hmac(hctx, ctx->hash, TCG_HASH_SIZE);
    hmac(hctx, sctx->nonceEven.nonce, sizeof(TPM_NONCE));
    hmac(hctx, se->nonceOdd.nonce, sizeof(TPM_NONCE));
    hmac(hctx, &se->continueAuthSession, sizeof(TPM_BOOL));
    hmac_finish(hctx);

    memcpy(se->pubAuth.authdata, hctx->ctx.hash, sizeof(TPM_AUTHDATA));
    
    // package the entire command into a bytestream
    SABLE_TPM_COPY_TO(com, sizeof(stTPM_NV_READVALUE));
    SABLE_TPM_COPY_TO(data, dataSize);
    SABLE_TPM_COPY_TO(se, sizeof(SessionEnd));

    // transmit command to TPM
    ERROR(-1, tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0, "TPM_NV_WriteValueAuth() failed on transmit");

    res = (TPM_RESULT) ntohl(*((UINT32 *) (in_buffer + 6)));

    return res;
}

TPM_RESULT
TPM_Flush(
        BYTE *in_buffer, 
        SessionCtx *sctx) 
{
    TPM_RESULT res;
    UINT32 tpm_offset_out = 0;
    stTPM_FLUSH_SPECIFIC *com = alloc(heap, sizeof(stTPM_FLUSH_SPECIFIC), 0);

    UINT32 paramSize = sizeof(stTPM_FLUSH_SPECIFIC);
    BYTE *out_buffer = alloc(heap, paramSize, 0);

    com->tag = ntohs(TPM_TAG_RQU_COMMAND);
    com->paramSize = ntohl(18);
    com->ordinal=ntohl(TPM_ORD_FlushSpecific);
    com->handle = sctx->authHandle;
    com->resourceType = ntohl(TPM_RT_AUTH);
    
    // package the entire command into a bytestream
    SABLE_TPM_COPY_TO(com, sizeof(stTPM_FLUSH_SPECIFIC));

    // transmit command to TPM
    ERROR(-1, tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0, "TPM_Flush() failed on transmit");

	res = (TPM_RESULT) ntohl(*((unsigned int *) (in_buffer+6)));
    return res;
}

void
getTPM_PCR_INFO_LONG(
        BYTE *buffer, 
        sdTPM_PCR_INFO_LONG *info, 
        sdTPM_PCR_SELECTION select)
{
    struct SHA1_Context ctx;
    sdTPM_PCR_COMPOSITE comp;

    comp.select = select;
    comp.valueSize = ntohl(2 * TCG_HASH_SIZE);
    TPM_PcrRead(buffer, &comp.hash1, SLB_PCR_ORD);
    TPM_PcrRead(buffer, &comp.hash2, MODULE_PCR_ORD);

    sha1_init(&ctx);
    sha1(&ctx, (BYTE *)&comp, sizeof(sdTPM_PCR_COMPOSITE));
    sha1_finish(&ctx);

    info->tag = ntohs(TPM_TAG_PCR_INFO_LONG);
    info->localityAtCreation = TPM_LOC_TWO;
    info->localityAtRelease = TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE;
    info->creationPCRSelection = select;
    info->releasePCRSelection = select;

    memcpy(info->digestAtCreation.digest, ctx.hash, TCG_HASH_SIZE);
    memcpy(info->digestAtRelease.digest, ctx.hash, TCG_HASH_SIZE);
}

int TPM_Seal(
        BYTE *in_buffer, 
        sdTPM_PCR_SELECTION select,
        BYTE *data,
        UINT32 dataSize, 
        BYTE *stored_data,
        SessionCtx *sctx)
{
    int res;
    struct SHA1_Context ctx;
    struct HMAC_Context hctx;
    sdTPM_PCR_INFO_LONG info;
    SessionEnd se;
    stTPM_SEAL com;
    TPM_AUTHDATA entityAuthData;

    UINT32 sha_offset = 0, hmac_offset = 0, tpm_offset_out = 0;
    UINT32 sha_size = sizeof(TPM_COMMAND_CODE) + sizeof(TPM_ENCAUTH) + sizeof(UINT32) + sizeof(sdTPM_PCR_INFO_LONG) + sizeof(UINT32) + dataSize;
    UINT32 hmac_size = TCG_HASH_SIZE + sizeof(TPM_NONCE) + sizeof(TPM_NONCE) + sizeof(TPM_BOOL);
    BYTE *sha_buf = alloc(heap, sha_size, 0);
    BYTE *hmac_buf = alloc(heap, sha_size, 0);

    int paramSize = sizeof(stTPM_SEAL) + dataSize + sizeof(SessionEnd);
    BYTE *out_buffer = alloc(heap, paramSize, 0);

    // construct command header
    com.tag = ntohs(TPM_TAG_RQU_AUTH1_COMMAND);
    com.paramSize = ntohl(paramSize);
    com.ordinal = ntohl(TPM_ORD_Seal);

    // handle of the SRK
    com.keyHandle = ntohl(TPM_KH_SRK);

    /* get encAuth to assign authData needed to Unseal. authData isn't part of our access control model so we just use a well-known secret of zeroes. */
    memset(entityAuthData.authdata, 0, 20);
    encAuth_gen(&entityAuthData, sctx->sharedSecret, &sctx->nonceEven, &com.encAuth); 

    // generate TPM_PCR_INFO
    getTPM_PCR_INFO_LONG(in_buffer, &info, select);
    com.pcrInfoSize = ntohl(sizeof(sdTPM_PCR_INFO_LONG));
    com.pcrInfo = info;

    com.inDataSize = ntohl(dataSize);

    // prepare necessary elements for SHA1
    SHA_COPY_TO(&com.ordinal, sizeof(TPM_COMMAND_CODE));
    SHA_COPY_TO(&com.encAuth, sizeof(TPM_ENCAUTH));
    SHA_COPY_TO(&com.pcrInfoSize, sizeof(UINT32));
    SHA_COPY_TO(&com.pcrInfo, sizeof(sdTPM_PCR_INFO_LONG));
    SHA_COPY_TO(&com.inDataSize, sizeof(UINT32));
    SHA_COPY_TO(data, dataSize);

    sha1_init(&ctx);
    sha1(&ctx, sha_buf, sha_size);
    sha1_finish(&ctx);

    se.authHandle = sctx->authHandle;
    res = TPM_GetRandom(in_buffer, (BYTE *)&se.nonceOdd, TCG_HASH_SIZE);
#ifdef EXEC
    CHECK4(108, res, "could not get random num from TPM", res);
#else
    CHECK4(108, res, &string_literal, res);
#endif
    se.continueAuthSession = TRUE;

    // prepare elements for HMAC
    HMAC_COPY_TO(&ctx.hash, TCG_HASH_SIZE);
    HMAC_COPY_TO(&sctx->nonceEven.nonce, sizeof(TPM_NONCE));
    HMAC_COPY_TO(&se.nonceOdd.nonce, sizeof(TPM_NONCE));
    HMAC_COPY_TO(&se.continueAuthSession, sizeof(TPM_BOOL));

    hmac_init(&hctx, sctx->sharedSecret, TCG_HASH_SIZE);
    hmac(&hctx, hmac_buf, hmac_offset);
    hmac_finish(&hctx);
    memcpy(&se.pubAuth, hctx.ctx.hash, TCG_HASH_SIZE);

    // package the entire command into a bytestream
    SABLE_TPM_COPY_TO(&com, sizeof(stTPM_SEAL));
    SABLE_TPM_COPY_TO(data, dataSize);
    SABLE_TPM_COPY_TO(&se, sizeof(SessionEnd));

    // transmit command to TPM
    TPM_TRANSMIT();

    unsigned long sealedDataSize=0;
    unsigned long sealInfoSize;
    unsigned long encDataSize;
    if(res>=0){

        res=(int) ntohl(*((unsigned int *) (in_buffer+6)));
        if (res > 0)
            return res;

        sealInfoSize=ntohl(*((unsigned long *)(in_buffer+14)));	
        
        encDataSize=ntohl(*((unsigned long *)(in_buffer+18+sealInfoSize)));
        sealedDataSize=12+sealInfoSize+encDataSize;

        //CHECK4(108,sealedDataSize>sealedDataBufSize,"sealed data too big", sealedDataSize);

        memcpy(stored_data,in_buffer+10,sealedDataSize);

    }

    return res;
}

int TPM_GetRandom(
        BYTE *in_buffer, 
        BYTE *dest,
        UINT32 size)
{
    int res;
    stTPM_GETRANDOM com;
    UINT32 tpm_offset_out = 0;
    UINT32 paramSize = sizeof(stTPM_GETRANDOM);
    BYTE *out_buffer = alloc(heap, paramSize, 0);

    // construct header
    com.tag = ntohs(TPM_TAG_RQU_COMMAND);
    com.paramSize = ntohl(paramSize);
    com.ordinal = ntohl(TPM_ORD_GetRandom);

    com.bytesRequested = ntohl(size);
    SABLE_TPM_COPY_TO(&com, sizeof(stTPM_GETRANDOM));
    TPM_TRANSMIT();
      if(res>=0)
        res=(int) ntohl(*((unsigned int *) (in_buffer+6)));

#ifdef EXEC
    CHECK4(108,ntohl(*((unsigned int*)(in_buffer+10)))!=size,"could not get enough random bytes from TPM", ntohl(*((unsigned int*)(in_buffer+10))));
#else
    CHECK4(108,ntohl(*((unsigned int*)(in_buffer+10)))!=size,&string_literal, ntohl(*((unsigned int*)(in_buffer+10))));
#endif
      TPM_COPY_FROM(dest,4,size);

    return res;
}

int
TPM_PcrRead(BYTE *in_buffer, TPM_DIGEST *hash, TPM_PCRINDEX pcrindex) {
    int res;
    UINT32 paramSize = sizeof(stTPM_PCRREAD);
    UINT32 tpm_offset_out = 0;
    stTPM_PCRREAD com;
    BYTE *out_buffer = alloc(heap, paramSize, 0);

    // construct the command
    com.tag = ntohs(TPM_TAG_RQU_COMMAND);
    com.paramSize = ntohl(paramSize);
    com.ordinal = ntohl(TPM_ORD_PcrRead);
    com.pcrIndex = ntohl(pcrindex);

    // transmit command to TPM
    SABLE_TPM_COPY_TO(&com, paramSize);
    TPM_TRANSMIT();

    // error detection
    if (res >= 0)
        res = (int)ntohl(*((UINT32 *) (in_buffer + 6)));
    else
#ifdef EXEC
        CHECK3(TPM_TRANSMIT_FAIL, TRUE, "tis_transmit() failed in TPM_PcrRead()");
#else
        CHECK3(TPM_TRANSMIT_FAIL, TRUE, &string_literal);
#endif
#ifdef EXEC
    CHECK4(res, res, "TPM_PcrRead() failed:", res);
#else
    CHECK4(res, res, &string_literal, res);
#endif

    // if everything succeeded, extract the PCR value
    TPM_COPY_FROM(hash->digest, 0, TCG_HASH_SIZE);

    return res;
}

int
TPM_Extend(
        BYTE *in_buffer, 
        TPM_PCRINDEX pcr_index, 
        TPM_DIGEST *hash)
{
    int res;
    UINT32 tpm_offset_out = 0;
    stTPM_Extend com;
    UINT32 paramSize = sizeof(stTPM_Extend);
    BYTE *out_buffer = alloc(heap, paramSize, 0);

    com.tag = ntohs(TPM_TAG_RQU_COMMAND);
    com.paramSize = ntohl(paramSize);
    com.ordinal = ntohl(TPM_ORD_Extend);
    com.pcrNum = ntohl(pcr_index);
    com.inDigest = *hash;

    SABLE_TPM_COPY_TO(&com, sizeof(stTPM_Extend));
    TPM_TRANSMIT();
    TPM_COPY_FROM(hash->digest, 0, TCG_HASH_SIZE);

    return res < 0 ? res : (int) ntohl(*((unsigned int *) (in_buffer+6)));
}

int TPM_Start_OSAP(BYTE *in_buffer, BYTE *usageAuth, UINT32 entityType, UINT32 entityValue, SessionCtx * sctx){
    int res;
    UINT32 tpm_offset_out = 0;
    struct HMAC_Context hctx;
    TPM_OSAP com;
    TPM_NONCE nonceOddOSAP;

    UINT32 paramSize = sizeof(TPM_OSAP);
    BYTE *out_buffer = alloc(heap, paramSize, 0);
    BYTE hmac_buffer[60];

    res = TPM_GetRandom(in_buffer, nonceOddOSAP.nonce, sizeof(TPM_NONCE));
#ifdef EXEC
    CHECK4(108, res, "could not get random num from TPM", res);
#else
    CHECK4(108, res, &string_literal, res);
#endif

    // construct header
    com.tag = ntohs(TPM_TAG_RQU_COMMAND);
    com.paramSize = ntohl(paramSize);
    com.ordinal = ntohl(TPM_ORD_OSAP);
    com.entityType = ntohs(entityType);
    com.entityValue = ntohl(entityValue);
    com.nonceOddOSAP = nonceOddOSAP;

    SABLE_TPM_COPY_TO(&com, paramSize);
    TPM_TRANSMIT();

    if(res>=0){
        res=(int) ntohl(*((unsigned int *) (in_buffer+6)));
        TPM_COPY_FROM((unsigned char *)&sctx->authHandle,0,4);
        TPM_COPY_FROM((unsigned char *)&sctx->nonceEven,4,20);
        TPM_COPY_FROM(hmac_buffer,24,20);
        memcpy(hmac_buffer+20,nonceOddOSAP.nonce,20);
        hmac_init(&hctx,usageAuth,20);
        hmac(&hctx,hmac_buffer,40);
        hmac_finish(&hctx);
        memcpy((unsigned char *)&sctx->sharedSecret,hctx.ctx.hash,20);
    }

    return res;
}

/**
 * Send a startup to the TPM.
 *
 * Note: We could use the TPM_TRANSMIT_FUNC macro, but this generates smaller code.
 */
int
TPM_Startup_Clear(unsigned char *buffer)
{
  ((unsigned int *)buffer)[0] = 0x0000c100;
  ((unsigned int *)buffer)[1] = 0x00000c00;
  ((unsigned int *)buffer)[2] = 0x01009900;
  int res = tis_transmit(buffer, 12, buffer, TCG_BUFFER_SIZE);
  return res < 0 ? res : (int) ntohl(*((unsigned int *) (buffer+6)));
}

/*
 * Get the number of suported pcrs.
 */
TPM_TRANSMIT_FUNC(GetCapability_Pcrs, (unsigned char *buffer, unsigned int *value),
		  unsigned long send_buffer[] = { TPM_ORD_GetCapability
		      AND TPM_CAP_PROPERTY
		      AND TPM_SUBCAP AND TPM_CAP_PROP_PCR };,
		  if (TPM_EXTRACT_LONG(0)!=4)
		    return -2;
		  *value= (unsigned int)TPM_EXTRACT_LONG(4);)

void
dump_pcrs(BYTE *buffer)
{
  TPM_PCRINDEX pcrs;
  TPM_DIGEST dig;

  if (TPM_GetCapability_Pcrs(buffer, (unsigned int *)&pcrs))
#ifdef EXEC
    out_info("TPM_GetCapability_Pcrs() failed");
#else
    out_info(&string_literal);
#endif
  else
#ifdef EXEC
    out_description("PCRs:", pcrs);
#else
    out_description(&string_literal, pcrs);
#endif

  for (TPM_PCRINDEX pcr=0; pcr < pcrs; pcr++)
    {
      int res = TPM_PcrRead(buffer, &dig, pcr);
      if (res)
	{
#ifdef EXEC
	  out_description("\nTPM_PcrRead() failed with",res);
#else
	  out_description(&string_literal,res);
#endif
	  break;
	}
      else
	{
#ifdef EXEC
	  out_string(" [");
#else
	  out_string(&string_literal);
#endif
	  out_hex(pcr, 0);
#ifdef EXEC
	  out_string("]: ");
#else
	  out_string(&string_literal);
#endif
	  for (unsigned i=0; i<4; i++)
	    out_hex(dig.digest[i], 7);
	}
      out_char(pcr% 4==3 ? '\n' : ' ');

    }
}
