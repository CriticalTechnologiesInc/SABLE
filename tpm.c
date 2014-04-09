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


#include "sable_tpm.h"
#include "util.h"
#include "hmac.h"

void encAuth_gen(
        TPM_AUTHDATA *auth, 
        BYTE *sharedSecret, 
        TPM_NONCE *nonceEven, 
        TPM_ENCAUTH *encAuth)
{
    // out = xor(authData, sha1(sharedSecret ++ nonceEven))
    BYTE buffer[40];
    struct Context ctx;
    memcpy(buffer, sharedSecret, 20);
    memcpy(buffer+20, nonceEven->nonce, 20);
    sha1_init(&ctx);
    sha1(&ctx, buffer, 40);
    sha1_finish(&ctx);
    do_xor(auth->authdata, ctx.hash, encAuth->authdata, 20);
}

int TPM_Start_OIAP(BYTE *in_buffer, SessionCtx *sctx){
    int res;
    TPM_COMMAND com;
    UINT32 tpm_offset_out = 0;
    UINT32 paramSize = sizeof(TPM_COMMAND);
    BYTE out_buffer[paramSize];
    
    // construct header
    com.tag = ntohs(TPM_TAG_RQU_COMMAND);
    com.paramSize = ntohl(paramSize);
    com.ordinal = ntohl(TPM_ORD_OIAP);

    SABLE_TPM_COPY_TO(&com, paramSize);
    TPM_TRANSMIT();

    if (res >= 0)
    {
        res=(int) ntohl(*((unsigned int *) (in_buffer+6)));
        TPM_COPY_FROM((unsigned char *)&sctx->authHandle,0,4);
        TPM_COPY_FROM((unsigned char *)&sctx->nonceEven,4,20);
        TPM_GetRandom(in_buffer,(unsigned char *)&sctx->nonceOdd,20);
    }

    return res;
}

int TPM_Unseal(
        BYTE *buffer, 
        BYTE *inData, 
        BYTE *secretData,
        UINT32 secretDataBufSize,
        UINT32 *secretDataSize,
        SessionCtx *sctxParent, 
        SessionCtx *sctxEntity)
{
    int guard=0;
    unsigned char outbuffer[TCG_BUFFER_SIZE];
    struct Context ctx;
    struct HContext hctx;
    stTPM_UNSEAL * unseal = (stTPM_UNSEAL *) outbuffer;
    unsigned long sealInfoSize = ntohl(*((unsigned long *)(inData+4)));
    unsigned long encDataSize= ntohl(*((unsigned long *)(inData+8+sealInfoSize)));
    unsigned long inDataSize=12+sealInfoSize+encDataSize;

    unseal->tag=ntohs(TPM_TAG_RQU_AUTH2_COMMAND);
    unseal->paramSize=ntohl(sizeof(stTPM_UNSEAL)+inDataSize+2*sizeof(SessionEnd));
    unseal->ordinal=ntohl(TPM_ORD_Unseal);
    unseal->parentHandle=ntohl(TPM_KH_SRK);
    memcpy(outbuffer+sizeof(stTPM_UNSEAL),inData,inDataSize);

    SessionEnd * endbufParent = (SessionEnd *)(outbuffer+sizeof(stTPM_UNSEAL)+inDataSize);
    endbufParent->authHandle = sctxParent->authHandle;
    memcpy((unsigned char *)&endbufParent->nonceOdd, (unsigned char *)&sctxParent->nonceOdd,20);
    endbufParent->continueAuthSession=0;

    SessionEnd * endbufEntity= (SessionEnd *)(outbuffer+sizeof(stTPM_UNSEAL)+inDataSize+sizeof(SessionEnd));
    endbufEntity->authHandle = sctxEntity->authHandle;
    memcpy((unsigned char *)&endbufEntity->nonceOdd, (unsigned char *)&sctxEntity->nonceOdd,20);
    endbufEntity->continueAuthSession=0;

    unsigned long offset=0;
    memcpy(buffer+offset,(unsigned char *)&unseal->ordinal,4);
    offset+=4;
    memcpy(buffer+offset,outbuffer+sizeof(stTPM_UNSEAL),inDataSize);
    offset+=inDataSize;
    sha1_init(&ctx);
    sha1(&ctx,buffer,offset);
    sha1_finish(&ctx);

    offset=0;
    memcpy(buffer+offset,ctx.hash,20);
    offset+=20;
    memcpy(buffer+offset,(unsigned char *)&sctxParent->nonceEven,20);
    offset+=20;
    memcpy(buffer+offset,(unsigned char *)&endbufParent->nonceOdd,20);
    offset+=20;
    memcpy(buffer+offset,(unsigned char *)&endbufParent->continueAuthSession,1);
    offset+=1;

    unsigned char authDataParent[20];
    memset(authDataParent,0,20);
    hmac_init(&hctx, authDataParent, 20);
    hmac(&hctx, buffer, offset);
    hmac_finish(&hctx);
    memcpy((unsigned char *)&endbufParent->pubAuth,hctx.ctx.hash,20);

    offset=20;
    memcpy(buffer+offset,(unsigned char *)&sctxEntity->nonceEven,20);
    offset+=20;
    memcpy(buffer+offset,(unsigned char *)&endbufEntity->nonceOdd,20);
    offset+=20;
    memcpy(buffer+offset,(unsigned char *)&endbufEntity->continueAuthSession,1);
    offset+=1;

    unsigned char authDataEntity[20];
    memset(authDataEntity,0,20);
    hmac_init(&hctx, authDataEntity, 20);
    hmac(&hctx, buffer, offset);
    hmac_finish(&hctx);
    memcpy((unsigned char *)&endbufEntity->pubAuth,hctx.ctx.hash,20);

    ERROR(108,guard!=0,"BUFFER OVERFLOW DETECED");
    int res = tis_transmit(outbuffer, sizeof(stTPM_UNSEAL)+inDataSize+2*sizeof(SessionEnd), outbuffer, 500);
    ERROR(108,res<0,"failed to send/receive data to/from the TPM");
    res=(int) ntohl(*((unsigned int *) (outbuffer+6)));
    CHECK4(108,res!=0,"Unseal unsuccessful",res);
    if(res==0){
        *secretDataSize=ntohl(*((unsigned long*)(outbuffer+10)));
        //this check is necessary to prevent a buffer overflow
        ERROR(108,*secretDataSize>secretDataBufSize,"secret data too big for buffer");

        memcpy((unsigned char *)secretData,outbuffer+14,*secretDataSize);
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
    struct Context ctx;
    sdTPM_PCR_COMPOSITE comp;

    TPM_PcrRead(buffer, &comp.hash1, SLB_PCR_ORD);
    TPM_PcrRead(buffer, &comp.hash2, MODULE_PCR_ORD);
    comp.select = select;
    comp.valueSize = ntohl(2 * TCG_HASH_SIZE);

    info->pcrSelection = select;
    info->localityAtRelease = TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE;

    sha1_init(&ctx);
    sha1(&ctx, (BYTE *)&comp, sizeof(sdTPM_PCR_COMPOSITE));
    sha1_finish(&ctx);
    memcpy(info->digestAtRelease.digest, ctx.hash, TCG_HASH_SIZE);
}

int TPM_NV_DefineSpace(
        BYTE *in_buffer, 
        sdTPM_PCR_SELECTION select,
        SessionCtx *sctx)
{
    int res;
    UINT32 sha_offset = 0, hmac_offset = 0, tpm_offset_out = 0;
    struct Context ctx;
    struct HContext hctx;

    // declare data structures
    TPM_NV_ATTRIBUTES perm;
    TPM_AUTHDATA authData;
    sdTPM_PCR_INFO_SHORT info;
    sdTPM_NV_DATA_PUBLIC pub;
    TPM_ENCAUTH encAuth;

    // declare the command
    stTPM_NV_DEFINESPACE com;
    SessionEnd se;

    // designate buffers
    UINT32 paramSize = sizeof(stTPM_NV_DEFINESPACE) + sizeof(SessionEnd);
    UINT32 sha_size = sizeof(TPM_COMMAND_CODE) + sizeof(sdTPM_NV_DATA_PUBLIC) + sizeof(TPM_ENCAUTH);
    UINT32 hmac_size = TCG_HASH_SIZE + sizeof(TPM_NONCE) + sizeof(TPM_NONCE) + sizeof(TPM_BOOL);
    BYTE out_buffer[paramSize];
    BYTE sha_buf[sha_size];
    BYTE hmac_buf[hmac_size];

    // populate the data structures
    perm.tag = ntohs(TPM_TAG_NV_ATTRIBUTES);
    perm.attributes = ntohl(TPM_NV_PER_AUTHWRITE | TPM_NV_PER_AUTHREAD);

    getTPM_PCR_INFO_SHORT(in_buffer, &info, select);

    pub.tag = ntohs(TPM_TAG_NV_DATA_PUBLIC);
    pub.nvIndex = ntohl(NV_DATA_OFFSET);
    pub.pcrInfoRead = info;
    pub.pcrInfoWrite = info;
    pub.permission = perm;
    pub.bReadSTClear = FALSE;
    pub.bWriteSTClear = FALSE;
    pub.bWriteDefine = FALSE;
    pub.dataSize = ntohl(NV_DATA_SIZE);

    memset(&authData.authdata, 0, TCG_HASH_SIZE);
    encAuth_gen(&authData, sctx->sharedSecret, &sctx->nonceEven, &encAuth);

    // populate the command
    com.tag = ntohs(TPM_TAG_RQU_AUTH1_COMMAND);
    com.paramSize = ntohl(paramSize);
    com.ordinal = ntohl(TPM_ORD_NV_DefineSpace);
    com.pubInfo = pub;
    com.encAuth = encAuth;

    SHA_COPY_TO(&com.ordinal, sizeof(TPM_COMMAND_CODE));
    SHA_COPY_TO(&com.pubInfo, sizeof(sdTPM_NV_DATA_PUBLIC));
    SHA_COPY_TO(&com.encAuth, sizeof(TPM_ENCAUTH));

    sha1_init(&ctx);
    sha1(&ctx, sha_buf, sha_size);
    sha1_finish(&ctx);

    se.authHandle = sctx->authHandle;
    CHECK4(108,(res=TPM_GetRandom(in_buffer,(BYTE *)&se.nonceOdd,TCG_HASH_SIZE)),"could not get random num from TPM", res);
    se.continueAuthSession = FALSE;

    HMAC_COPY_TO(&ctx.hash, TCG_HASH_SIZE);
    HMAC_COPY_TO(&sctx->nonceEven.nonce, sizeof(TPM_NONCE));
    HMAC_COPY_TO(&se.nonceOdd.nonce, sizeof(TPM_NONCE));
    HMAC_COPY_TO(&se.continueAuthSession, sizeof(TPM_BOOL));

    hmac_init(&hctx, sctx->sharedSecret, TCG_HASH_SIZE);
    hmac(&hctx, hmac_buf, hmac_offset);
    hmac_finish(&hctx);
    memcpy(&se.pubAuth, hctx.ctx.hash, TCG_HASH_SIZE);
    
    // package the entire command into a bytestream
    SABLE_TPM_COPY_TO(&com, sizeof(stTPM_NV_DEFINESPACE));
    SABLE_TPM_COPY_TO(&se, sizeof(SessionEnd));

    // transmit command to TPM
    TPM_TRANSMIT();

    if(res>=0){
        out_string("\nDefineSpace transmit successful\n");
        res=(int) ntohl(*((UINT32 *) (in_buffer + 6)));
    }
    return res;

}

int TPM_NV_ReadValueAuth(BYTE *buffer, BYTE *data, UINT32 dataSize, UINT32 dataBufferSize, SessionCtx *sctx){
struct Context ctx;
struct HContext hctx;
unsigned char outbuffer[TCG_BUFFER_SIZE];
stTPM_NV_WRITEVALUE * buf = (stTPM_NV_WRITEVALUE*) outbuffer;
buf->tag=ntohs(TPM_TAG_RQU_AUTH1_COMMAND);
buf->paramSize=ntohl(sizeof(stTPM_NV_WRITEVALUE)+sizeof(SessionEnd));
buf->ordinal=ntohl(TPM_ORD_NV_ReadValueAuth);
buf->nvIndex=ntohl(0x10000);
buf->offset=ntohl(0);
buf->dataSize=ntohl(dataSize);

SessionEnd * endbuf= (SessionEnd *)(outbuffer+sizeof(stTPM_NV_WRITEVALUE));
endbuf->authHandle = sctx->authHandle;
memcpy((unsigned char *)&endbuf->nonceOdd, (unsigned char *)&sctx->nonceOdd,20);
endbuf->continueAuthSession=0;

unsigned long offset=0;
memcpy(buffer+offset,(unsigned char *)&buf->ordinal,4);
offset+=4;
memcpy(buffer+offset,(unsigned char *)&buf->nvIndex,4);
offset+=4;
memcpy(buffer+offset,(unsigned char *)&buf->offset,4);
offset+=4;
memcpy(buffer+offset,(unsigned char *)&buf->dataSize,4);
offset+=4;

sha1_init(&ctx);
sha1(&ctx,buffer,offset);
sha1_finish(&ctx);

offset=0;
memcpy(buffer+offset,ctx.hash,20);
offset+=20;
memcpy(buffer+offset,(unsigned char *)&sctx->nonceEven,20);
offset+=20;
memcpy(buffer+offset,(unsigned char *)&endbuf->nonceOdd,20);
offset+=20;
memcpy(buffer+offset,(unsigned char *)&endbuf->continueAuthSession,1);
offset+=1;

unsigned char authData[20];
memset(authData,0,20);
hmac_init(&hctx, authData, 20);
hmac(&hctx,buffer,offset);
hmac_finish(&hctx);
memcpy((unsigned char *)&endbuf->pubAuth,hctx.ctx.hash,20);

unsigned long receivedDataSize;
int res = tis_transmit(outbuffer, sizeof(stTPM_NV_WRITEVALUE)+sizeof(SessionEnd), outbuffer, 600);
    if(res>=0){
	out_string("\nReadValueAuth transmit successful\n");
	res=(int) ntohl(*((unsigned int *) (outbuffer+6)));
	receivedDataSize=(int) ntohl(*((unsigned int *) (outbuffer+10)));
	if(receivedDataSize>dataBufferSize){
		out_string("\nBuffer overflow detected\n");
		return res;
	}
	memcpy(data,outbuffer+14,receivedDataSize);

    }
    return res;


}


int TPM_NV_WriteValueAuth(BYTE *buffer, BYTE *data, UINT32 dataSize, SessionCtx *sctx){
struct Context ctx;
struct HContext hctx;
unsigned char outbuffer[TCG_BUFFER_SIZE];
stTPM_NV_WRITEVALUE * buf = (stTPM_NV_WRITEVALUE*) outbuffer;
buf->tag=ntohs(TPM_TAG_RQU_AUTH1_COMMAND);
buf->paramSize=ntohl(sizeof(stTPM_NV_WRITEVALUE)+dataSize+sizeof(SessionEnd));
buf->ordinal=ntohl(TPM_ORD_NV_WriteValueAuth);
buf->nvIndex=ntohl(0x10000);
buf->offset=ntohl(0);
buf->dataSize=ntohl(dataSize);
memcpy(outbuffer+sizeof(stTPM_NV_WRITEVALUE),data,dataSize);

SessionEnd * endbuf= (SessionEnd *)(outbuffer+sizeof(stTPM_NV_WRITEVALUE)+dataSize);
endbuf->authHandle = sctx->authHandle;
memcpy((unsigned char *)&endbuf->nonceOdd, (unsigned char *)&sctx->nonceOdd,20);
endbuf->continueAuthSession=0;

unsigned long offset=0;
memcpy(buffer+offset,(unsigned char *)&buf->ordinal,4);
offset+=4;
memcpy(buffer+offset,(unsigned char *)&buf->nvIndex,4);
offset+=4;
memcpy(buffer+offset,(unsigned char *)&buf->offset,4);
offset+=4;
memcpy(buffer+offset,(unsigned char *)&buf->dataSize,4);
offset+=4;

memcpy(buffer+offset,outbuffer+sizeof(stTPM_NV_WRITEVALUE),dataSize);
offset+=dataSize;
sha1_init(&ctx);
sha1(&ctx,buffer,offset);
sha1_finish(&ctx);

offset=0;
memcpy(buffer+offset,ctx.hash,20);
offset+=20;
memcpy(buffer+offset,(unsigned char *)&sctx->nonceEven,20);
offset+=20;
memcpy(buffer+offset,(unsigned char *)&endbuf->nonceOdd,20);
offset+=20;
memcpy(buffer+offset,(unsigned char *)&endbuf->continueAuthSession,1);
offset+=1;

unsigned char authData[20];
memset(authData,0,20);
hmac_init(&hctx,authData,20);
hmac(&hctx,buffer,offset);
hmac_finish(&hctx);
memcpy((unsigned char *)&endbuf->pubAuth,hctx.ctx.hash,20);

int res = tis_transmit(outbuffer, sizeof(stTPM_NV_WRITEVALUE)+dataSize+sizeof(SessionEnd), outbuffer, 600);
    if(res>=0){
	out_string("\nWriteValueAuth transmit successful\n");
	res=(int) ntohl(*((unsigned int *) (outbuffer+6)));
    }
    return res;


}

int TPM_Flush(SessionCtx *sctx){
unsigned char buffer[TCG_BUFFER_SIZE];
TPM_COMMAND * flush = (TPM_COMMAND*)buffer;
flush->tag=ntohs(TPM_TAG_RQU_COMMAND);
flush->paramSize=ntohl(18);
flush->ordinal=ntohl(TPM_ORD_FlushSpecific);
unsigned char * temp=buffer+sizeof(TPM_COMMAND);
*((unsigned long*)temp)=(unsigned long)sctx->authHandle;
temp+=4;
*((unsigned long*)temp)=ntohl((unsigned long)0x2);
int res = tis_transmit(buffer,18 , buffer, 34);
if(res>=0){
	out_string("\n Flush transmit successful\n");
	res=(int) ntohl(*((unsigned int *) (buffer+6)));
}
return res;
}


void
getTPM_PCR_INFO_LONG(
        BYTE *buffer, 
        sdTPM_PCR_INFO_LONG *info, 
        sdTPM_PCR_SELECTION select)
{
    struct Context ctx;
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
    struct Context ctx;
    struct HContext hctx;
    sdTPM_PCR_INFO_LONG info;
    SessionEnd se;
    stTPM_SEAL com;
    TPM_AUTHDATA entityAuthData;

    UINT32 sha_offset = 0, hmac_offset = 0, tpm_offset_out = 0;
    UINT32 sha_size = sizeof(TPM_COMMAND_CODE) + sizeof(TPM_ENCAUTH) + sizeof(UINT32) + sizeof(sdTPM_PCR_INFO_LONG) + sizeof(UINT32) + dataSize;
    UINT32 hmac_size = TCG_HASH_SIZE + sizeof(TPM_NONCE) + sizeof(TPM_NONCE) + sizeof(TPM_BOOL);
    BYTE sha_buf[sha_size];
    BYTE hmac_buf[hmac_size];

    int paramSize = sizeof(stTPM_SEAL) + dataSize + sizeof(SessionEnd);
    BYTE out_buffer[paramSize];

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
    CHECK4(108,(res=TPM_GetRandom(in_buffer,(BYTE *)&se.nonceOdd,TCG_HASH_SIZE)),"could not get random num from TPM", res);
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
    BYTE out_buffer[paramSize];

    // construct header
    com.tag = ntohs(TPM_TAG_RQU_COMMAND);
    com.paramSize = ntohl(paramSize);
    com.ordinal = ntohl(TPM_ORD_GetRandom);

    com.bytesRequested = ntohl(size);
    SABLE_TPM_COPY_TO(&com, sizeof(stTPM_GETRANDOM));
    TPM_TRANSMIT();
      if(res>=0)
        res=(int) ntohl(*((unsigned int *) (in_buffer+6)));

    CHECK4(108,ntohl(*((unsigned int*)(in_buffer+10)))!=size,"could not get enough random bytes from TPM", ntohl(*((unsigned int*)(in_buffer+10))));
      TPM_COPY_FROM(dest,4,size);

    return res;
}

int
TPM_PcrRead(BYTE *in_buffer, TPM_DIGEST *hash, TPM_PCRINDEX pcrindex) {
    int res;
    UINT32 paramSize = sizeof(stTPM_PCRREAD);
    UINT32 tpm_offset_out = 0;
    stTPM_PCRREAD com;
    BYTE out_buffer[paramSize];

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
        CHECK3(TPM_TRANSMIT_FAIL, TRUE, "tis_transmit() failed in TPM_PcrRead()");
    CHECK4(res, res, "TPM_PcrRead() failed:", res);

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
    BYTE out_buffer[paramSize];

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
    struct HContext hctx;
    TPM_OSAP com;
    TPM_NONCE nonceOddOSAP;

    UINT32 paramSize = sizeof(TPM_OSAP);
    BYTE out_buffer[paramSize];
    BYTE hmac_buffer[60];

    CHECK4(108,(res=TPM_GetRandom(in_buffer, nonceOddOSAP.nonce, sizeof(TPM_NONCE))),"could not get random num from TPM", res);

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
		  *value=TPM_EXTRACT_LONG(4);)

void
dump_pcrs(BYTE *buffer)
{
  TPM_PCRINDEX pcrs;
  TPM_DIGEST dig;

  if (TPM_GetCapability_Pcrs(buffer, &pcrs))
    out_info("TPM_GetCapability_Pcrs() failed");
  else
    out_description("PCRs:", pcrs);

  for (TPM_PCRINDEX pcr=0; pcr < pcrs; pcr++)
    {
      int res;
      if ((res = TPM_PcrRead(buffer, &dig, pcr)))
	{
	  out_description("\nTPM_PcrRead() failed with",res);
	  break;
	}
      else
	{
	  out_string(" [");
	  out_hex(pcr, 0);
	  out_string("]: ");
	  for (unsigned i=0; i<4; i++)
	    out_hex(dig.digest[i], 7);
	}
      out_char(pcr% 4==3 ? '\n' : ' ');

    }
}
