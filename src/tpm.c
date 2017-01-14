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
  sha1_init();
  sha1(sharedSecret, TCG_HASH_SIZE);
  sha1(nonceEven->bytes, sizeof(TPM_NONCE));
  TPM_DIGEST hash = sha1_finish();

  do_xor(auth->bytes, hash.bytes, encAuth->bytes, TCG_HASH_SIZE);
}

TPM_OIAP_RET TPM_OIAP(void) {
  TPM_RQU_COMMAND_OIAP *in = (TPM_RQU_COMMAND_OIAP *)tis_buffers.in;

  in->head.tag = ntohs(TPM_TAG_RQU_COMMAND);
  in->head.paramSize = ntohl(sizeof(TPM_RQU_COMMAND_OIAP));
  in->ordinal = ntohl(TPM_ORD_OIAP);

  tis_transmit_new();

  const TPM_RSP_COMMAND_OIAP *out =
      (const TPM_RSP_COMMAND_OIAP *)tis_buffers.out;
  const TPM_OIAP_RET ret = {
      .returnCode = ntohl(out->returnCode),
      .session = {.authHandle = ntohl(out->authHandle), .nonceEven = out->nonceEven}};

  return ret;
}

TPM_RESULT TPM_Unseal(BYTE *in_buffer, BYTE *inData, BYTE *secretData,
                      UINT32 secretDataBufSize, UINT32 *secretDataSize,
                      SessionCtx *sctxParent, SessionCtx *sctxEntity) {
  TPM_RESULT res;
  TPM_DIGEST hash, parentHMAC, entityHMAC;
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

  sha1_init();
  sha1((BYTE *)&com->ordinal, sizeof(TPM_COMMAND_CODE));
  sha1(inData, inDataSize);
  hash = sha1_finish();

  hmac_init(endBufParent->pubAuth.bytes, sizeof(TPM_AUTHDATA));
  hmac(hash.bytes, TCG_HASH_SIZE);
  hmac(sctxParent->nonceEven.bytes, sizeof(TPM_NONCE));
  hmac(endBufParent->nonceOdd.bytes, sizeof(TPM_NONCE));
  hmac(&endBufParent->continueAuthSession, sizeof(TPM_BOOL));
  parentHMAC = hmac_finish();

  memcpy(&endBufParent->pubAuth, parentHMAC.bytes, sizeof(TPM_AUTHDATA));

  endBufEntity->authHandle = sctxEntity->authHandle;
  endBufEntity->nonceOdd = sctxEntity->nonceOdd;
  endBufEntity->continueAuthSession = FALSE;
  endBufEntity->pubAuth = sctxEntity->pubAuth;

  hmac_init(endBufEntity->pubAuth.bytes, sizeof(TPM_AUTHDATA));
  hmac(hash.bytes, TCG_HASH_SIZE);
  hmac(sctxEntity->nonceEven.bytes, sizeof(TPM_NONCE));
  hmac(endBufEntity->nonceOdd.bytes, sizeof(TPM_NONCE));
  hmac(&endBufEntity->continueAuthSession, sizeof(TPM_BOOL));
  entityHMAC = hmac_finish();

  memcpy(&endBufEntity->pubAuth, entityHMAC.bytes, sizeof(TPM_AUTHDATA));

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
  dealloc(heap, com, sizeof(stTPM_UNSEAL));
  dealloc(heap, endBufParent, sizeof(SessionEnd));
  dealloc(heap, endBufEntity, sizeof(SessionEnd));
  dealloc(heap, out_buffer, paramSize);

  return res;
}

// this function assumes using PCRs 17 and 19
void getTPM_PCR_INFO_SHORT(BYTE *buffer, sdTPM_PCR_INFO_SHORT *info,
                           sdTPM_PCR_SELECTION select) {
  sdTPM_PCR_COMPOSITE *comp = alloc(heap, sizeof(sdTPM_PCR_COMPOSITE), 0);

  comp->select = select;
  comp->valueSize = ntohl(2 * sizeof(TPM_COMPOSITE_HASH));
  TPM_PcrRead(buffer, &comp->hash1, SLB_PCR_ORD);
  TPM_PcrRead(buffer, &comp->hash2, MODULE_PCR_ORD);

  info->pcrSelection = select;
  info->localityAtRelease = TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE;

  sha1_init();
  sha1((BYTE *)comp, sizeof(sdTPM_PCR_COMPOSITE));
  TPM_DIGEST hash = sha1_finish();
  memcpy(info->digestAtRelease.bytes, hash.bytes, sizeof(TPM_DIGEST));

  // cleanup
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
  com->offset = ntohl(0);    // HARDCODED
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
TPM_NV_WriteValueAuth(BYTE *data, TPM_NV_INDEX nvIndex, UINT32 offset,
                      TPM_AUTHDATA nv_auth, OIAP_Session session) {
  TPM_DIGEST inParamDigest, outParamDigest, outParamHMAC;
  TPM_RQU_COMMAND_NV_WRITEVALUEAUTH *in =
      (TPM_RQU_COMMAND_NV_WRITEVALUEAUTH *)tis_buffers.in;

  // Generate a fresh nonce
  TPM_GETRANDOM_RET_TPM_NONCE nonce_ret = TPM_GetRandom_TPM_NONCE();
  ERROR(-1, nonce_ret.returnCode, s_nonce_generation_failed);
  TPM_NONCE nonceOdd = nonce_ret.random_TPM_NONCE;

  in->head.tag = htons(TPM_TAG_RQU_AUTH1_COMMAND);
  in->head.paramSize = htonl(sizeof(TPM_RQU_COMMAND_NV_WRITEVALUEAUTH));
  in->ordinal = htonl(TPM_ORD_NV_WriteValueAuth);
  in->nvIndex = htonl(nvIndex);
  in->offset = htonl(offset);
  in->dataSize = htonl(400);
  memcpy(in->data, data, 400);
  in->authHandle = htonl(session.authHandle);
  in->nonceOdd = nonceOdd;
  in->continueAuthSession = FALSE;

  sha1_init();
  sha1((BYTE *)&in->ordinal, sizeof(TPM_COMMAND_CODE));
  sha1((BYTE *)&in->nvIndex, sizeof(TPM_NV_INDEX));
  sha1((BYTE *)&in->offset, sizeof(UINT32));
  sha1((BYTE *)&in->dataSize, sizeof(UINT32));
  sha1(data, 400);
  inParamDigest = sha1_finish();

  hmac_init(nv_auth.bytes, sizeof(TPM_AUTHDATA));
  hmac(inParamDigest.bytes, TCG_HASH_SIZE);
  hmac(session.nonceEven.bytes, sizeof(TPM_NONCE));
  hmac(in->nonceOdd.bytes, sizeof(TPM_NONCE));
  hmac(&in->continueAuthSession, sizeof(TPM_BOOL));
  in->authValue = hmac_finish();

  tis_transmit_new();

  const TPM_RSP_COMMAND_NV_WRITEVALUEAUTH *out =
      (const TPM_RSP_COMMAND_NV_WRITEVALUEAUTH *)tis_buffers.out;

  TPM_RESULT res = ntohl(out->returnCode);
  if (res) return res;

  sha1_init();
  sha1((BYTE *)&out->returnCode, sizeof(TPM_RESULT));
  sha1((BYTE *)&in->ordinal, sizeof(TPM_COMMAND_CODE));
  outParamDigest = sha1_finish();

  hmac_init(nv_auth.bytes, sizeof(TPM_AUTHDATA));
  hmac(outParamDigest.bytes, TCG_HASH_SIZE);
  hmac(out->nonceEven.bytes, sizeof(TPM_NONCE));
  hmac(nonceOdd.bytes, sizeof(TPM_NONCE));
  hmac(&out->continueAuthSession, sizeof(TPM_BOOL));
  outParamHMAC = hmac_finish();

  ERROR(-1,
        bufcmp(outParamHMAC.bytes, out->authValue.bytes, sizeof(TPM_AUTHDATA)),
        "Man-in-the-Middle Attack Detected!");

  return res;
}

void getTPM_PCR_INFO_LONG(BYTE *buffer, sdTPM_PCR_INFO_LONG *info,
                          sdTPM_PCR_SELECTION select) {
  sdTPM_PCR_COMPOSITE *comp = alloc(heap, sizeof(sdTPM_PCR_COMPOSITE), 0);

  comp->select = select;
  comp->valueSize = ntohl(2 * TCG_HASH_SIZE);
  TPM_PcrRead(buffer, &comp->hash1, SLB_PCR_ORD);
  TPM_PcrRead(buffer, &comp->hash2, MODULE_PCR_ORD);

  sha1_init();
  sha1((BYTE *)comp, sizeof(sdTPM_PCR_COMPOSITE));
  TPM_DIGEST hash = sha1_finish();

  info->tag = ntohs(TPM_TAG_PCR_INFO_LONG);
  info->localityAtCreation = TPM_LOC_TWO;
  info->localityAtRelease =
      TPM_LOC_ZERO | TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE | TPM_LOC_FOUR;
  info->creationPCRSelection = select;
  info->releasePCRSelection = select;
  info->digestAtCreation = hash;
  info->digestAtRelease = hash;

  // cleanup
  dealloc(heap, comp, sizeof(sdTPM_PCR_COMPOSITE));
}

TPM_RESULT TPM_Seal(BYTE *in_buffer, sdTPM_PCR_SELECTION select, BYTE *data,
                    UINT32 dataSize, BYTE *stored_data, SessionCtx *sctx,
                    BYTE *passPhraseAuthData) {
  TPM_RESULT res;
  TPM_DIGEST inParamDigest;
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
  memcpy(entityAuthData->bytes, passPhraseAuthData, sizeof(TPM_AUTHDATA));
  encAuth_gen(entityAuthData, sctx->sharedSecret, &sctx->nonceEven,
              &com->encAuth);

  // generate TPM_PCR_INFO
  getTPM_PCR_INFO_LONG(in_buffer, &com->pcrInfo, select);
  com->pcrInfoSize = ntohl(sizeof(sdTPM_PCR_INFO_LONG));

  com->inDataSize = ntohl(dataSize);

  sha1_init();
  sha1((BYTE *)&com->ordinal, sizeof(TPM_COMMAND_CODE));
  sha1(com->encAuth.bytes, sizeof(TPM_ENCAUTH));
  sha1((BYTE *)&com->pcrInfoSize, sizeof(UINT32));
  sha1((BYTE *)&com->pcrInfo, sizeof(sdTPM_PCR_INFO_LONG));
  sha1((BYTE *)&com->inDataSize, sizeof(UINT32));
  sha1(data, dataSize);
  inParamDigest = sha1_finish();

  se->authHandle = sctx->authHandle;
  TPM_GETRANDOM_RET_TPM_NONCE nonce = TPM_GetRandom_TPM_NONCE();
  ERROR(-1, nonce.returnCode, s_nonce_generation_failed);
  se->nonceOdd = nonce.random_TPM_NONCE;
  se->continueAuthSession = TRUE;

  // prepare elements for HMAC
  hmac_init(sctx->sharedSecret, TCG_HASH_SIZE);
  hmac(inParamDigest.bytes, TCG_HASH_SIZE);
  hmac(sctx->nonceEven.bytes, sizeof(TPM_NONCE));
  hmac(se->nonceOdd.bytes, sizeof(TPM_NONCE));
  hmac(&se->continueAuthSession, sizeof(TPM_BOOL));
  se->pubAuth = hmac_finish();

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
  TPM_COPY_FROM(hash->bytes, 0, TCG_HASH_SIZE);

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

  tis_transmit_new();

  const TPM_RSP_COMMAND_EXTEND *out =
      (const TPM_RSP_COMMAND_EXTEND *)tis_buffers.out;
  const TPM_EXTEND_RET ret = {.returnCode = ntohl(out->returnCode),
                              .outDigest = out->outDigest};

  return ret;
}

TPM_RESULT TPM_Start_OSAP(BYTE *in_buffer, BYTE *usageAuth, UINT32 entityType,
                          UINT32 entityValue, SessionCtx *sctx) {
  TPM_RESULT res;
  UINT32 tpm_offset_out = 0;
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

  hmac_init(usageAuth, sizeof(TPM_AUTHDATA));
  hmac(nonceEvenOSAP->bytes, sizeof(TPM_NONCE));
  hmac(com->nonceOddOSAP.bytes, sizeof(TPM_NONCE));
  TPM_DIGEST hmac = hmac_finish();

  memcpy((BYTE *)&sctx->sharedSecret, hmac.bytes, TCG_HASH_SIZE);

  // cleanup
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
        out_hex(dig->bytes[i], 7);
    }
    out_char(pcr % 4 == 3 ? '\n' : ' ');
  }

  // cleanup
  dealloc(heap, pcrs, sizeof(TPM_PCRINDEX));
  dealloc(heap, dig, sizeof(TPM_DIGEST));
}
