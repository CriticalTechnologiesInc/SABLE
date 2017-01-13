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

#include "tpm.h"
#include "alloc.h"
#include "hmac.h"
#include "string.h"
#include "tpm_command.h"
#include "util.h"

TPM_GETRANDOM_GEN(TPM_NONCE)

// out = xor(authData, sha1(sharedSecret ++ nonceEven))
void encAuth_gen(TPM_AUTHDATA *auth, BYTE *sharedSecret, TPM_NONCE *nonceEven,
                 TPM_ENCAUTH *encAuth) {
  struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);

  sha1_init(ctx);
  sha1(ctx, sharedSecret, TCG_HASH_SIZE);
  sha1(ctx, nonceEven->nonce, sizeof(TPM_NONCE));
  sha1_finish(ctx);

  do_xor(auth->authdata, ctx->hash, encAuth->authdata, TCG_HASH_SIZE);

  // cleanup
  dealloc(heap, ctx, sizeof(struct SHA1_Context));
}

TPM_RESULT
TPM_Start_OIAP(BYTE *in_buffer, SessionCtx *sctx) {
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
  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_Start_OIAP_failed_on_transmit);

  res = (TPM_RESULT)ntohl(*(in_buffer + 6));
  TPM_COPY_FROM((BYTE *)&sctx->authHandle, 0, 4);
  TPM_COPY_FROM((BYTE *)&sctx->nonceEven, 4, 20);
  TPM_GETRANDOM_RET_TPM_NONCE nonce = TPM_GetRandom_TPM_NONCE();
  ERROR(-1, nonce.returnCode, s_nonce_generation_failed);
  sctx->nonceOdd = nonce.random_TPM_NONCE;

  // cleanup
  dealloc(heap, com, sizeof(TPM_COMMAND));
  dealloc(heap, out_buffer, paramSize);

  return res;
}

TPM_RESULT TPM_Unseal(BYTE *in_buffer, BYTE *inData, BYTE *secretData,
                      UINT32 secretDataBufSize, UINT32 *secretDataSize,
                      SessionCtx *sctxParent, SessionCtx *sctxEntity) {
  TPM_RESULT res;
  struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
  struct HMAC_Context *hctx = alloc(heap, sizeof(struct HMAC_Context), 0);
  stTPM_UNSEAL *com = alloc(heap, sizeof(stTPM_UNSEAL), 0);
  SessionEnd *endBufParent = alloc(heap, sizeof(SessionEnd), 0);
  SessionEnd *endBufEntity = alloc(heap, sizeof(SessionEnd), 0);

  UINT32 sealInfoSize = ntohl(*((UINT32 *)(inData + 4)));
  UINT32 encDataSize = ntohl(*((UINT32 *)(inData + 8 + sealInfoSize)));
  UINT32 inDataSize = 12 + sealInfoSize + encDataSize;

  UINT32 tpm_offset_out = 0;
  UINT32 paramSize = sizeof(stTPM_UNSEAL) + inDataSize + 2 * sizeof(SessionEnd);
  BYTE *out_buffer = alloc(heap, paramSize, 0);

  com->tag = ntohs(TPM_TAG_RQU_AUTH2_COMMAND);
  com->paramSize = ntohl(paramSize);
  com->ordinal = ntohl(TPM_ORD_Unseal);
  com->parentHandle = ntohl(TPM_KH_SRK);

  endBufParent->authHandle = sctxParent->authHandle;
  endBufParent->nonceOdd = sctxParent->nonceOdd;
  endBufParent->continueAuthSession = FALSE;
  endBufParent->pubAuth = sctxParent->pubAuth;

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
  endBufEntity->pubAuth = sctxEntity->pubAuth;

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

  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_Unseal_failed_on_transmit);

  res = (int)ntohl(*((unsigned int *)(in_buffer + 6)));
  if (res == 0) {
    *secretDataSize = ntohl(*((unsigned long *)(in_buffer + 10)));
    // this check is necessary to prevent a buffer overflow
    ERROR(108, *secretDataSize > secretDataBufSize,
          s_secret_data_too_big_for_buffer);

    memcpy((unsigned char *)secretData, in_buffer + 14, *secretDataSize);
  }

  // cleanup
  dealloc(heap, ctx, sizeof(struct SHA1_Context));
  dealloc(heap, hctx, sizeof(struct HMAC_Context));
  dealloc(heap, com, sizeof(stTPM_UNSEAL));
  dealloc(heap, endBufParent, sizeof(SessionEnd));
  dealloc(heap, endBufEntity, sizeof(SessionEnd));
  dealloc(heap, out_buffer, paramSize);

  return res;
}

// this function assumes using PCRs 17 and 19
void getTPM_PCR_INFO_SHORT(BYTE *buffer, sdTPM_PCR_INFO_SHORT *info,
                           sdTPM_PCR_SELECTION select) {
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

  // cleanup
  dealloc(heap, ctx, sizeof(struct SHA1_Context));
  dealloc(heap, comp, sizeof(sdTPM_PCR_COMPOSITE));
}

TPM_RESULT
TPM_NV_ReadValue(BYTE *in_buffer, BYTE *data, UINT32 dataSize) {
  TPM_RESULT res;
  UINT32 tpm_offset_out = 0;

  UINT32 paramSize = sizeof(stTPM_NV_READVALUE);
  BYTE *out_buffer = alloc(heap, paramSize, 0);
  stTPM_NV_READVALUE *com = alloc(heap, sizeof(stTPM_NV_READVALUE), 0);

  // populate structures
  com->tag = ntohs(TPM_TAG_RQU_COMMAND);
  com->paramSize = ntohl(paramSize);
  com->ordinal = ntohl(TPM_ORD_NV_ReadValue);
  com->nvIndex = ntohl(0x4); // HARDCODED
  com->offset = ntohl(0);        // HARDCODED
  com->dataSize = ntohl(dataSize);

  UINT32 receivedDataSize;

  // package the entire command into a bytestream
  SABLE_TPM_COPY_TO(com, sizeof(stTPM_NV_READVALUE));

  // transmit command to TPM
  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_NV_ReadValueAuth_failed_on_transmit);

  res = (TPM_RESULT)ntohl(*((UINT32 *)(in_buffer + 6)));

  if (res == 0) {
    receivedDataSize = (int)ntohl(*((UINT32 *)(in_buffer + 10)));
    if (receivedDataSize > TCG_BUFFER_SIZE) {
      out_string(s_buffer_overflow_detected);
      return res;
    }
    memcpy(data, in_buffer + 14, receivedDataSize);
  }

  // cleanup
  dealloc(heap, out_buffer, paramSize);
  dealloc(heap, com, sizeof(stTPM_NV_READVALUE));

  return res;
}

TPM_RESULT
TPM_NV_WriteValueAuth(BYTE *in_buffer, BYTE *data, UINT32 dataSize,
                      TPM_AUTHDATA auth, SessionCtx *sctx) {
  TPM_RESULT res;
  UINT32 tpm_offset_out = 0;

  // designate buffers
  UINT32 paramSize =
      sizeof(stTPM_NV_WRITEVALUE) + dataSize + sizeof(SessionEnd);
  BYTE *out_buffer = alloc(heap, paramSize, 0);

  // declare data structures
  struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
  struct HMAC_Context *hctx = alloc(heap, sizeof(struct HMAC_Context), 0);
  stTPM_NV_WRITEVALUE *com = alloc(heap, sizeof(stTPM_NV_WRITEVALUE), 0);
  SessionEnd *se = alloc(heap, sizeof(SessionEnd), 0);

  // populate structures
  com->tag = ntohs(TPM_TAG_RQU_AUTH1_COMMAND);
  com->paramSize = ntohl(paramSize);
  com->ordinal = ntohl(TPM_ORD_NV_WriteValueAuth);
  com->nvIndex = ntohl(0x4); // HARDCODED
  com->offset = ntohl(0);      // HARDCODED
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

  hmac_init(hctx, auth.authdata, TCG_HASH_SIZE);
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
  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_NV_WriteValueAuth_failed_on_transmit);

  res = (TPM_RESULT)ntohl(*((UINT32 *)(in_buffer + 6)));

  // cleanup
  dealloc(heap, out_buffer, paramSize);
  dealloc(heap, ctx, sizeof(struct SHA1_Context));
  dealloc(heap, hctx, sizeof(struct HMAC_Context));
  dealloc(heap, com, sizeof(stTPM_NV_WRITEVALUE));
  dealloc(heap, se, sizeof(SessionEnd));

  return res;
}

TPM_RESULT
TPM_Flush(BYTE *in_buffer, SessionCtx *sctx) {
  TPM_RESULT res;
  UINT32 tpm_offset_out = 0;
  stTPM_FLUSH_SPECIFIC *com = alloc(heap, sizeof(stTPM_FLUSH_SPECIFIC), 0);

  UINT32 paramSize = sizeof(stTPM_FLUSH_SPECIFIC);
  BYTE *out_buffer = alloc(heap, paramSize, 0);

  com->tag = ntohs(TPM_TAG_RQU_COMMAND);
  com->paramSize = ntohl(18);
  com->ordinal = ntohl(TPM_ORD_FlushSpecific);
  com->handle = sctx->authHandle;
  com->resourceType = ntohl(TPM_RT_AUTH);

  // package the entire command into a bytestream
  SABLE_TPM_COPY_TO(com, sizeof(stTPM_FLUSH_SPECIFIC));

  // transmit command to TPM
  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_Flush_failed_on_transmit);

  res = (TPM_RESULT)ntohl(*((unsigned int *)(in_buffer + 6)));

  // cleanup
  dealloc(heap, com, sizeof(stTPM_FLUSH_SPECIFIC));
  dealloc(heap, out_buffer, paramSize);

  return res;
}

void getTPM_PCR_INFO_LONG(BYTE *buffer, sdTPM_PCR_INFO_LONG *info,
                          sdTPM_PCR_SELECTION select) {
  struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
  sdTPM_PCR_COMPOSITE *comp = alloc(heap, sizeof(sdTPM_PCR_COMPOSITE), 0);

  comp->select = select;
  comp->valueSize = ntohl(2 * TCG_HASH_SIZE);
  TPM_PcrRead(buffer, &comp->hash1, SLB_PCR_ORD);
  TPM_PcrRead(buffer, &comp->hash2, MODULE_PCR_ORD);

  sha1_init(ctx);
  sha1(ctx, (BYTE *)comp, sizeof(sdTPM_PCR_COMPOSITE));
  sha1_finish(ctx);

  info->tag = ntohs(TPM_TAG_PCR_INFO_LONG);
  info->localityAtCreation = TPM_LOC_TWO;
  info->localityAtRelease =
      TPM_LOC_ZERO | TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE | TPM_LOC_FOUR;
  info->creationPCRSelection = select;
  info->releasePCRSelection = select;

  memcpy(info->digestAtCreation.digest, ctx->hash, TCG_HASH_SIZE);
  memcpy(info->digestAtRelease.digest, ctx->hash, TCG_HASH_SIZE);

  // cleanup
  dealloc(heap, ctx, sizeof(struct SHA1_Context));
  dealloc(heap, comp, sizeof(sdTPM_PCR_COMPOSITE));
}

TPM_RESULT TPM_Seal(BYTE *in_buffer, sdTPM_PCR_SELECTION select, BYTE *data,
                    UINT32 dataSize, BYTE *stored_data, SessionCtx *sctx,
                    BYTE *passPhraseAuthData) {
  TPM_RESULT res;
  struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
  struct HMAC_Context *hctx = alloc(heap, sizeof(struct HMAC_Context), 0);
  SessionEnd *se = alloc(heap, sizeof(SessionEnd), 0);
  stTPM_SEAL *com = alloc(heap, sizeof(stTPM_SEAL), 0);
  TPM_AUTHDATA *entityAuthData = alloc(heap, sizeof(TPM_AUTHDATA), 0);

  UINT32 tpm_offset_out = 0;
  int paramSize = sizeof(stTPM_SEAL) + dataSize + sizeof(SessionEnd);
  BYTE *out_buffer = alloc(heap, paramSize, 0);

  // construct command header
  com->tag = ntohs(TPM_TAG_RQU_AUTH1_COMMAND);
  com->paramSize = ntohl(paramSize);
  com->ordinal = ntohl(TPM_ORD_Seal);

  // handle of the SRK
  com->keyHandle = ntohl(TPM_KH_SRK);

  /* get encAuth to assign authData needed to Unseal. authData isn't part of our
   * access control model so we just use a well-known secret of zeroes. */
  memcpy(entityAuthData->authdata, passPhraseAuthData, sizeof(TPM_AUTHDATA));
  encAuth_gen(entityAuthData, sctx->sharedSecret, &sctx->nonceEven,
              &com->encAuth);

  // generate TPM_PCR_INFO
  getTPM_PCR_INFO_LONG(in_buffer, &com->pcrInfo, select);
  com->pcrInfoSize = ntohl(sizeof(sdTPM_PCR_INFO_LONG));

  com->inDataSize = ntohl(dataSize);

  // prepare necessary elements for SHA1
  sha1_init(ctx);
  sha1(ctx, (BYTE *)&com->ordinal, sizeof(TPM_COMMAND_CODE));
  sha1(ctx, (BYTE *)&com->encAuth, sizeof(TPM_ENCAUTH));
  sha1(ctx, (BYTE *)&com->pcrInfoSize, sizeof(UINT32));
  sha1(ctx, (BYTE *)&com->pcrInfo, sizeof(sdTPM_PCR_INFO_LONG));
  sha1(ctx, (BYTE *)&com->inDataSize, sizeof(UINT32));
  sha1(ctx, (BYTE *)data, dataSize);
  sha1_finish(ctx);

  se->authHandle = sctx->authHandle;
  TPM_GETRANDOM_RET_TPM_NONCE nonce = TPM_GetRandom_TPM_NONCE();
  ERROR(-1, nonce.returnCode, s_nonce_generation_failed);
  se->nonceOdd = nonce.random_TPM_NONCE;
  se->continueAuthSession = TRUE;

  // prepare elements for HMAC
  hmac_init(hctx, sctx->sharedSecret, TCG_HASH_SIZE);
  hmac(hctx, (BYTE *)&ctx->hash, TCG_HASH_SIZE);
  hmac(hctx, (BYTE *)&sctx->nonceEven.nonce, sizeof(TPM_NONCE));
  hmac(hctx, (BYTE *)&se->nonceOdd.nonce, sizeof(TPM_NONCE));
  hmac(hctx, (BYTE *)&se->continueAuthSession, sizeof(TPM_BOOL));
  hmac_finish(hctx);

  memcpy(&se->pubAuth, hctx->ctx.hash, TCG_HASH_SIZE);

  // package the entire command into a bytestream
  SABLE_TPM_COPY_TO(com, sizeof(stTPM_SEAL));
  SABLE_TPM_COPY_TO(data, dataSize);
  SABLE_TPM_COPY_TO(se, sizeof(SessionEnd));

  // transmit command to TPM
  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_Seal_failed_on_transmit);

  unsigned long sealedDataSize = 0;
  unsigned long sealInfoSize;
  unsigned long encDataSize;

  res = (TPM_RESULT)ntohl(*((unsigned int *)(in_buffer + 6)));
  if (res > 0)
    return res;

  sealInfoSize = ntohl(*((unsigned long *)(in_buffer + 14)));

  encDataSize = ntohl(*((unsigned long *)(in_buffer + 18 + sealInfoSize)));
  sealedDataSize = 12 + sealInfoSize + encDataSize;

  memcpy(stored_data, in_buffer + 10, sealedDataSize);

  // cleanup
  dealloc(heap, out_buffer, paramSize);
  dealloc(heap, ctx, sizeof(struct SHA1_Context));
  dealloc(heap, hctx, sizeof(struct HMAC_Context));
  dealloc(heap, com, sizeof(stTPM_NV_WRITEVALUE));
  dealloc(heap, se, sizeof(SessionEnd));
  dealloc(heap, entityAuthData, sizeof(TPM_AUTHDATA));

  return res;
}

TPM_RESULT
TPM_PcrRead(BYTE *in_buffer, TPM_DIGEST *hash, TPM_PCRINDEX pcrindex) {
  TPM_RESULT res;
  UINT32 paramSize = sizeof(stTPM_PCRREAD);
  UINT32 tpm_offset_out = 0;
  stTPM_PCRREAD *com = alloc(heap, sizeof(stTPM_PCRREAD), 0);
  BYTE *out_buffer = alloc(heap, paramSize, 0);

  // construct the command
  com->tag = ntohs(TPM_TAG_RQU_COMMAND);
  com->paramSize = ntohl(paramSize);
  com->ordinal = ntohl(TPM_ORD_PcrRead);
  com->pcrIndex = ntohl(pcrindex);

  // transmit command to TPM
  SABLE_TPM_COPY_TO(com, paramSize);
  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_PcrRead_failed_on_transmit);

  res = (TPM_RESULT)ntohl(*((UINT32 *)(in_buffer + 6)));

  // if everything succeeded, extract the PCR value
  TPM_COPY_FROM(hash->digest, 0, TCG_HASH_SIZE);

  // cleanup
  dealloc(heap, com, sizeof(stTPM_PCRREAD));
  dealloc(heap, out_buffer, paramSize);

  return res;
}

TPM_EXTEND_RET TPM_Extend(TPM_PCRINDEX pcr_index, TPM_DIGEST hash) {
  TPM_RQU_COMMAND_EXTEND *in = (TPM_RQU_COMMAND_EXTEND *)tis_buffers.in;

  in->head.tag = ntohs(TPM_TAG_RQU_COMMAND);
  in->head.paramSize = ntohl(sizeof(TPM_RQU_COMMAND_EXTEND));
  in->ordinal = ntohl(TPM_ORD_Extend);
  in->pcrNum = ntohl(pcr_index);
  in->inDigest = hash;

  tis_transmit_new(); // FIXME: check return value

  const TPM_RSP_COMMAND_EXTEND *out =
      (const TPM_RSP_COMMAND_EXTEND *)tis_buffers.out;
  const TPM_EXTEND_RET ret = {.returnCode = out->returnCode,
                              .outDigest = out->outDigest};

  return ret;
}

TPM_RESULT TPM_Start_OSAP(BYTE *in_buffer, BYTE *usageAuth, UINT32 entityType,
                          UINT32 entityValue, SessionCtx *sctx) {
  TPM_RESULT res;
  UINT32 tpm_offset_out = 0;
  struct HMAC_Context *hctx = alloc(heap, sizeof(struct HMAC_Context), 0);
  TPM_OSAP *com = alloc(heap, sizeof(TPM_OSAP), 0);
  TPM_NONCE *nonceEvenOSAP = alloc(heap, sizeof(TPM_NONCE), 0);

  UINT32 paramSize = sizeof(TPM_OSAP);
  BYTE *out_buffer = alloc(heap, paramSize, 0);

  // construct header
  com->tag = ntohs(TPM_TAG_RQU_COMMAND);
  com->paramSize = ntohl(paramSize);
  com->ordinal = ntohl(TPM_ORD_OSAP);
  com->entityType = ntohs(entityType);
  com->entityValue = ntohl(entityValue);
  TPM_GETRANDOM_RET_TPM_NONCE nonce = TPM_GetRandom_TPM_NONCE();
  ERROR(108, nonce.returnCode, s_nonce_generation_failed);
  com->nonceOddOSAP = nonce.random_TPM_NONCE;

  SABLE_TPM_COPY_TO(com, paramSize);
  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_Start_OSAP_failed_on_transmit);

  res = (TPM_RESULT)ntohl(*((UINT32 *)(in_buffer + 6)));

  TPM_COPY_FROM((BYTE *)&sctx->authHandle, 0, sizeof(TPM_AUTHHANDLE));
  TPM_COPY_FROM((BYTE *)&sctx->nonceEven, 4, sizeof(TPM_NONCE));
  TPM_COPY_FROM(nonceEvenOSAP, 24, sizeof(TPM_NONCE));

  hmac_init(hctx, usageAuth, sizeof(TPM_AUTHDATA));
  hmac(hctx, nonceEvenOSAP->nonce, sizeof(TPM_NONCE));
  hmac(hctx, com->nonceOddOSAP.nonce, sizeof(TPM_NONCE));
  hmac_finish(hctx);

  memcpy((BYTE *)&sctx->sharedSecret, hctx->ctx.hash, TCG_HASH_SIZE);

  // cleanup
  dealloc(heap, hctx, sizeof(struct HMAC_Context));
  dealloc(heap, com, sizeof(TPM_OSAP));
  dealloc(heap, nonceEvenOSAP, sizeof(TPM_NONCE));
  dealloc(heap, out_buffer, paramSize);

  return res;
}

/**
 * Send a startup to the TPM.
 *
 * Note: We could use the TPM_TRANSMIT_FUNC macro, but this generates smaller
 * code.
 */
TPM_RESULT
TPM_Startup_Clear(BYTE *in_buffer) {
  TPM_RESULT res;
  UINT32 tpm_offset_out = 0;
  stTPM_STARTUP *com = alloc(heap, sizeof(stTPM_STARTUP), 0);
  UINT32 paramSize = sizeof(stTPM_STARTUP);
  BYTE *out_buffer = alloc(heap, paramSize, 0);

  com->tag = ntohs(TPM_TAG_RQU_COMMAND);
  com->paramSize = ntohl(paramSize);
  com->ordinal = ntohl(TPM_ORD_Startup);
  com->startupType = ntohs(TPM_ST_CLEAR);

  SABLE_TPM_COPY_TO(com, sizeof(stTPM_STARTUP));
  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_Startup_failed_on_transmit);

  res = (TPM_RESULT)ntohl(*((UINT32 *)(in_buffer + 6)));

  // cleanup
  dealloc(heap, com, sizeof(stTPM_STARTUP));
  dealloc(heap, out_buffer, paramSize);

  return res;
}

/*
 * Get the number of suported pcrs.
 */
TPM_TRANSMIT_FUNC(
    GetCapability_Pcrs, (BYTE * buffer, TPM_PCRINDEX *value),
    unsigned long send_buffer[] = {TPM_ORD_GetCapability AND TPM_CAP_PROPERTY
                                       AND TPM_SUBCAP AND TPM_CAP_PROP_PCR};
    , if (TPM_EXTRACT_LONG(0) != 4) return -2;
    *value = (unsigned int)TPM_EXTRACT_LONG(4);)

void dump_pcrs(BYTE *buffer) {
  TPM_PCRINDEX *pcrs = alloc(heap, sizeof(TPM_PCRINDEX), 0);
  TPM_DIGEST *dig = alloc(heap, sizeof(TPM_DIGEST), 0);

  if (TPM_GetCapability_Pcrs(buffer, pcrs))
    out_info(s_TPM_GetCapability_Pcrs_failed);
  else
    out_description(s_PCRs, *pcrs);

  for (TPM_PCRINDEX pcr = 0; pcr < *pcrs; pcr++) {
    TPM_RESULT res = TPM_PcrRead(buffer, dig, pcr);
    if (res) {
      out_description(s_TPM_PcrRead_failed_with, res);
      break;
    } else {
      out_string(s_left_bracket);
      out_hex(pcr, 0);
      out_string(s_right_bracket);
      for (unsigned i = 0; i < 4; i++)
        out_hex(dig->digest[i], 7);
    }
    out_char(pcr % 4 == 3 ? '\n' : ' ');
  }

  // cleanup
  dealloc(heap, pcrs, sizeof(TPM_PCRINDEX));
  dealloc(heap, dig, sizeof(TPM_DIGEST));
}
