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
#include "tpm_struct.h"
#include "util.h"

typedef struct {
  TPM_AUTHHANDLE authHandle;
  TPM_NONCE nonceOdd;
  TPM_BOOL continueAuthSession;
  TPM_AUTHDATA authValue;
} TPM_SESSION_IN;

typedef struct {
  TPM_NONCE nonceEven;
  TPM_BOOL continueAuthSession;
  TPM_AUTHDATA authValue;
} TPM_SESSION_OUT;

/* TPM_GetRandom */
// out = xor(authData, sha1(sharedSecret ++ nonceEven))
void encAuth_gen(TPM_AUTHDATA *auth, BYTE *sharedSecret, TPM_NONCE *nonceEven,
                 TPM_ENCAUTH *encAuth) {
  sha1_init();
  sha1(sharedSecret, TCG_HASH_SIZE);
  sha1(nonceEven->bytes, sizeof(TPM_NONCE));
  TPM_DIGEST hash = sha1_finish();

  do_xor(auth->bytes, hash.bytes, encAuth->bytes, TCG_HASH_SIZE);
}

/* TPM_OIAP */

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_COMMAND_CODE ordinal;
} TPM_RQU_COMMAND_OIAP;

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_RESULT returnCode;
  TPM_AUTHHANDLE authHandle;
  TPM_NONCE nonceEven;
} TPM_RSP_COMMAND_OIAP;

TPM_OIAP_RET TPM_OIAP(void) {
  TPM_RQU_COMMAND_OIAP *in = (TPM_RQU_COMMAND_OIAP *)tis_buffers.in;

  in->head.tag = ntohs(TPM_TAG_RQU_COMMAND);
  in->head.paramSize = ntohl(sizeof(TPM_RQU_COMMAND_OIAP));
  in->ordinal = ntohl(TPM_ORD_OIAP);

  tis_transmit_new();

  const TPM_RSP_COMMAND_OIAP *out =
      (const TPM_RSP_COMMAND_OIAP *)tis_buffers.out;
  const TPM_OIAP_RET ret = {.returnCode = ntohl(out->returnCode),
                            .session = {.authHandle = ntohl(out->authHandle),
                                        .nonceEven = out->nonceEven}};

  return ret;
}

TPM_OSAP_RET TPM_OSAP(TPM_ENTITY_TYPE entityType_in, UINT32 entityValue_in,
                      TPM_NONCE nonceOddOSAP_in, TPM_SESSION *session) {
  TPM_OSAP_RET ret;

  TPM_TAG tag_in = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) +
                        sizeof(TPM_COMMAND_CODE) + sizeof(TPM_ENTITY_TYPE) +
                        sizeof(UINT32) + sizeof(TPM_NONCE);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_OSAP;

  pack_init(tis_buffers.in, sizeof(tis_buffers.in));
  pack_UINT16(tag_in, false);
  pack_UINT32(paramSize_in, false);
  pack_UINT32(ordinal_in, false);
  pack_UINT16(entityType_in, false);
  pack_UINT32(entityValue_in, false);
  pack_ptr(nonceOddOSAP_in.bytes, sizeof(TPM_NONCE), false);
  UINT32 bytes_packed = pack_finish();

  assert(bytes_packed == paramSize_in);

  tis_transmit_new();

  unpack_init(tis_buffers.out, sizeof(tis_buffers.out));
  TPM_TAG tag_out = unpack_UINT16(false);
  UINT32 paramSize_out = unpack_UINT32(false);
  TPM_RESULT returnCode_out = unpack_UINT32(false);
  ret.returnCode = returnCode_out;
  if (ret.returnCode)
    return ret;
  TPM_AUTHHANDLE authHandle_out = unpack_UINT32(false);
  TPM_NONCE nonceEven_out = unpack_TPM_NONCE(false);
  TPM_NONCE nonceEvenOSAP_out = unpack_TPM_NONCE(false);
  UINT32 bytes_unpacked = unpack_finish();

  assert(tag_out == TPM_TAG_RSP_COMMAND);
  assert(bytes_unpacked == paramSize_out);

  session->authHandle = authHandle_out;
  session->nonceEven = nonceEven_out;
  session->continueAuthSession = FALSE; // default
  ret.nonceEvenOSAP = nonceEvenOSAP_out;

  return ret;
}

/*TPM_RESULT TPM_Unseal(BYTE *in_buffer, BYTE *inData, BYTE *secretData,
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
}*/

// hardcoded PCRs 17 and 19
void getTPM_PCR_INFO_SHORT(BYTE *buffer, TPM_PCR_INFO_SHORT *info,
                           const TPM_PCR_SELECTION *select) {
  TPM_PCR_COMPOSITE *comp = alloc(heap, sizeof(TPM_PCR_COMPOSITE), 0);
  TPM_PCRVALUE *digests = alloc(heap, 2 * sizeof(TPM_PCRVALUE), 0);
  TPM_PCRVALUE *pcr17 = digests;
  TPM_PCRVALUE *pcr19 = digests + 1;

  comp->select = *select;
  comp->valueSize = ntohl(2 * sizeof(TPM_COMPOSITE_HASH));
  // FIXME: check errors
  *pcr17 = TPM_PCRRead(SLB_PCR_ORD).outDigest;
  *pcr19 = TPM_PCRRead(MODULE_PCR_ORD).outDigest;
  comp->pcrValue = digests;

  info->pcrSelection = *select;
  info->localityAtRelease = TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE;

  sha1_init();
  sha1((BYTE *)comp, sizeof(TPM_PCR_COMPOSITE));
  TPM_DIGEST hash = sha1_finish();
  memcpy(info->digestAtRelease.bytes, hash.bytes, sizeof(TPM_DIGEST));

  // cleanup
  dealloc(heap, comp, sizeof(TPM_PCR_COMPOSITE));
}

/******************************************************
 * TPM_ReadValue
 *****************************************************/

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_COMMAND_CODE ordinal;
  TPM_NV_INDEX nvIndex;
  UINT32 offset;
  UINT32 dataSize;
} TPM_RQU_COMMAND_NV_READVALUE;

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_RESULT returnCode;
  UINT32 dataSize;
} TPM_RSP_COMMAND_NV_READVALUE;

TPM_RESULT TPM_NV_ReadValue(BYTE *data, UINT32 dataSize, TPM_NV_INDEX nvIndex,
                            UINT32 offset) {
  TPM_RESULT res;
  TPM_RQU_COMMAND_NV_READVALUE *command_in =
      (TPM_RQU_COMMAND_NV_READVALUE *)tis_buffers.in;
  const TPM_RSP_COMMAND_NV_READVALUE *command_out =
      (const TPM_RSP_COMMAND_NV_READVALUE *)tis_buffers.out;
  const BYTE *data_out = tis_buffers.out + sizeof(TPM_RSP_COMMAND_NV_READVALUE);
  UINT32 dataSize_out;

  // populate structures
  command_in->head.tag = ntohs(TPM_TAG_RQU_COMMAND);
  command_in->head.paramSize = ntohl(sizeof(TPM_RQU_COMMAND_NV_READVALUE));
  command_in->ordinal = ntohl(TPM_ORD_NV_ReadValue);
  command_in->nvIndex = ntohl(nvIndex);
  command_in->offset = ntohl(offset);
  command_in->dataSize = ntohl(dataSize);

  tis_transmit_new();

  res = command_out->returnCode;
  if (res)
    return res;

  dataSize_out = ntohl(command_out->dataSize);
  assert(dataSize == dataSize_out);
  assert(ntohl(command_out->head.paramSize) ==
         sizeof(TPM_RSP_COMMAND_NV_READVALUE) + dataSize_out);
  memcpy(data, data_out, dataSize_out);

  return res;
}

/* TPM_NV_WriteValueAuth */

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_COMMAND_CODE ordinal;
  TPM_NV_INDEX nvIndex;
  UINT32 offset;
  UINT32 dataSize;
} TPM_RQU_COMMAND_NV_WRITEVALUEAUTH;

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_RESULT returnCode;
} TPM_RSP_COMMAND_NV_WRITEVALUEAUTH;

/*TPM_RESULT
TPM_NV_WriteValueAuth(const BYTE *data, UINT32 dataSize, TPM_NV_INDEX nvIndex,
                      UINT32 offset, TPM_AUTHDATA nv_auth,
                      TPM_SESSION nv_session) {
  TPM_RESULT res;
  TPM_DIGEST inParamDigest, outParamDigest, outParamHMAC;
  TPM_RQU_COMMAND_NV_WRITEVALUEAUTH *command_in;
  const TPM_RSP_COMMAND_NV_WRITEVALUEAUTH *command_out;
  BYTE *data_in;
  TPM_SESSION_IN *nv_session_in;
  const TPM_SESSION_OUT *nv_session_out;

  {
    UINT32 offset = 0;
    command_in = (TPM_RQU_COMMAND_NV_WRITEVALUEAUTH *)(tis_buffers.in + offset);
    offset += sizeof(TPM_RQU_COMMAND_NV_WRITEVALUEAUTH);
    data_in = (BYTE *)(tis_buffers.in + offset);
    offset += dataSize;
    nv_session_in = (TPM_SESSION_IN *)(tis_buffers.in + offset);
  }

  // Generate a fresh nonce
  TPM_GETRANDOM_RET_TPM_NONCE nonceOdd = TPM_GetRandom_TPM_NONCE();
  ERROR(-1, nonceOdd.returnCode, s_nonce_generation_failed);

  command_in->head.tag = htons(TPM_TAG_RQU_AUTH1_COMMAND);
  command_in->head.paramSize = htonl(sizeof(TPM_RQU_COMMAND_NV_WRITEVALUEAUTH) +
                                     dataSize + sizeof(TPM_SESSION_IN));
  command_in->ordinal = htonl(TPM_ORD_NV_WriteValueAuth);
  command_in->nvIndex = htonl(nvIndex);
  command_in->offset = htonl(offset);
  command_in->dataSize = htonl(dataSize);
  memcpy(data_in, data, dataSize);
  nv_session_in->authHandle = htonl(nv_session.authHandle);
  nv_session_in->nonceOdd = nonceOdd.random_TPM_NONCE;
  nv_session_in->continueAuthSession = FALSE;

  sha1_init();
  sha1((BYTE *)&command_in->ordinal, sizeof(TPM_COMMAND_CODE));
  sha1((BYTE *)&command_in->nvIndex, sizeof(TPM_NV_INDEX));
  sha1((BYTE *)&command_in->offset, sizeof(UINT32));
  sha1((BYTE *)&command_in->dataSize, sizeof(UINT32));
  sha1(data_in, dataSize);
  inParamDigest = sha1_finish();

  hmac_init(nv_auth.bytes, sizeof(TPM_AUTHDATA));
  hmac(inParamDigest.bytes, sizeof(TPM_DIGEST));
  hmac(nv_session.nonceEven.bytes, sizeof(TPM_NONCE));
  hmac(nv_session_in->nonceOdd.bytes, sizeof(TPM_NONCE));
  hmac(&nv_session_in->continueAuthSession, sizeof(TPM_BOOL));
  nv_session_in->authValue = hmac_finish();

  tis_transmit_new();

  {
    UINT32 offset = 0;
    command_out =
        (const TPM_RSP_COMMAND_NV_WRITEVALUEAUTH *)(tis_buffers.out + offset);
    offset += sizeof(TPM_RSP_COMMAND_NV_WRITEVALUEAUTH);
    nv_session_out = (const TPM_SESSION_OUT *)(tis_buffers.out + offset);
  }

  res = ntohl(command_out->returnCode);
  if (res)
    return res;

  assert(ntohl(command_out->head.paramSize) ==
         sizeof(TPM_RSP_COMMAND_NV_WRITEVALUEAUTH) + sizeof(TPM_SESSION_OUT));

  sha1_init();
  sha1((BYTE *)&command_out->returnCode, sizeof(TPM_RESULT));
  sha1((BYTE *)&command_in->ordinal, sizeof(TPM_COMMAND_CODE));
  outParamDigest = sha1_finish();

  hmac_init(nv_auth.bytes, sizeof(TPM_AUTHDATA));
  hmac(outParamDigest.bytes, sizeof(TPM_DIGEST));
  hmac(nv_session_out->nonceEven.bytes, sizeof(TPM_NONCE));
  hmac(nonceOdd.random_TPM_NONCE.bytes, sizeof(TPM_NONCE));
  hmac(&nv_session_out->continueAuthSession, sizeof(TPM_BOOL));
  outParamHMAC = hmac_finish();

  ERROR(-1, bufcmp(outParamHMAC.bytes, nv_session_out->authValue.bytes,
                   sizeof(TPM_AUTHDATA)),
        "Man-in-the-Middle Attack Detected!");

  return res;
}*/

void getTPM_PCR_INFO_LONG(BYTE *buffer, TPM_PCR_INFO_LONG *info,
                          const TPM_PCR_SELECTION *select) {
  TPM_PCR_COMPOSITE *comp = alloc(heap, sizeof(TPM_PCR_COMPOSITE), 0);
  TPM_PCRVALUE *digests = alloc(heap, 2 * sizeof(TPM_PCRVALUE), 0);
  TPM_PCRVALUE *pcr17 = digests;
  TPM_PCRVALUE *pcr19 = digests + 1;

  comp->select = *select;
  comp->valueSize = ntohl(2 * TCG_HASH_SIZE);
  // FIXME: check errors
  *pcr17 = TPM_PCRRead(SLB_PCR_ORD).outDigest;
  *pcr19 = TPM_PCRRead(MODULE_PCR_ORD).outDigest;
  comp->pcrValue = digests;

  sha1_init();
  sha1((BYTE *)comp, sizeof(TPM_PCR_COMPOSITE));
  TPM_DIGEST hash = sha1_finish();

  info->tag = ntohs(TPM_TAG_PCR_INFO_LONG);
  info->localityAtCreation = TPM_LOC_TWO;
  info->localityAtRelease =
      TPM_LOC_ZERO | TPM_LOC_ONE | TPM_LOC_TWO | TPM_LOC_THREE | TPM_LOC_FOUR;
  info->creationPCRSelection = *select;
  info->releasePCRSelection = *select;
  info->digestAtCreation = hash;
  info->digestAtRelease = hash;

  // cleanup
  dealloc(heap, comp, sizeof(TPM_PCR_COMPOSITE));
}

/*TPM_SEAL_RET TPM_Seal(TPM_KEY_HANDLE keyHandle_in, TPM_ENCAUTH encAuth_in,
                      UINT32 pcrInfoSize_in, const void *pcrInfo_in,
                      UINT32 inDataSize_in, const BYTE *inData_in,
                      TPM_SESSION *session, const TPM_AUTHDATA *key_auth) {
  TPM_SEAL_RET ret;

  TPM_TAG tag_in = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 paramSize_in =
      sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_COMMAND_CODE) +
      sizeof(TPM_KEY_HANDLE) + sizeof(TPM_ENCAUTH) + sizeof(UINT32) +
      pcrInfoSize_in + sizeof(UINT32) + inDataSize_in + sizeof(TPM_AUTHHANDLE) +
      sizeof(TPM_NONCE) + sizeof(TSS_BOOL) + sizeof(TPM_AUTHDATA);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_Seal;

  // compute inParamDigest
  sha1_init();
  sha1_UINT32(ordinal_in);
  sha1_TPM_DIGEST(encAuth_in);
  sha1_UINT32(pcrInfoSize_in);
  sha1_ptr(pcrInfo_in, pcrInfoSize_in);
  sha1_UINT32(inDataSize_in);
  sha1_ptr(inData_in, inDataSize_in);
  TPM_DIGEST inParamDigest = sha1_finish();

  // compute inAuthSetupParams
  hmac_init(key_auth->bytes, sizeof(TPM_AUTHDATA));
  hmac_TPM_DIGEST(inParamDigest);
  hmac_TPM_DIGEST(session->nonceEven);
  hmac_TPM_DIGEST(session->nonceOdd);
  hmac_BYTE(session->continueAuthSession);
  TPM_AUTHDATA pubAuth_in = hmac_finish();

  // pack the command
  pack_init(tis_buffers.in, sizeof(tis_buffers.in));
  pack_UINT16(htons(tag_in));
  pack_UINT32(htonl(paramSize_in));
  pack_UINT32(htonl(ordinal_in));
  pack_UINT32(ntohl(keyHandle_in));
  pack_TPM_DIGEST(encAuth_in);
  pack_UINT32(htonl(pcrInfoSize_in));
  pack_ptr(pcrInfo_in, pcrInfoSize_in);
  pack_UINT32(htonl(inDataSize_in));
  pack_ptr(inData_in, inDataSize_in);
  pack_UINT32(htonl(session->authHandle));
  pack_TPM_DIGEST(session->nonceOdd);
  pack_BYTE(session->continueAuthSession);
  pack_TPM_DIGEST(pubAuth_in);
  UINT32 bytes_packed = pack_finish();

  assert(bytes_packed == paramSize_in);

  tis_transmit_new();

  unpack_init(tis_buffers.out, sizeof(tis_buffers.out));
  TPM_TAG tag_out = ntohs(unpack_UINT16());
  UINT32 paramSize_out = ntohl(unpack_UINT32());
  ret.returnCode = ntohl(unpack_UINT32());
  if (ret.returnCode)
    return ret;
  ret.sealed_data = unpack_TPM_STORED_DATA12();
  session->nonceEven = unpack_TPM_DIGEST();
  session->continueAuthSession = unpack_BYTE();
  TPM_AUTHDATA resAuth_out = unpack_TPM_DIGEST();
  UINT32 bytes_unpacked = unpack_finish();

  assert(tag_out == TPM_TAG_RSP_COMMAND);
  assert(bytes_unpacked == paramSize_out);
  assert(session->continueAuthSession == FALSE);

  // compute outParamDigest
  TPM_DIGEST outParamDigest;

  // compute HM
  hmac_init(key_auth->bytes, sizeof(TPM_AUTHDATA));
  hmac_TPM_DIGEST(outParamDigest);
  hmac_TPM_DIGEST(session->nonceEven);
  hmac_TPM_DIGEST(session->nonceOdd);
  hmac_BYTE(session->continueAuthSession);
  TPM_AUTHDATA HM = hmac_finish();
  ERROR(-1, bufcmp(HM.bytes, resAuth_out.bytes, sizeof(TPM_DIGEST)),
        "MiM attack detected!");

  return ret;
}*/

/* TPM_PCRRead */

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_COMMAND_CODE ordinal;
  TPM_PCRINDEX pcrIndex;
} TPM_RQU_COMMAND_PCRREAD;

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_RESULT returnCode;
  TPM_DIGEST outDigest;
} TPM_RSP_COMMAND_PCRREAD;

TPM_PCRREAD_RET
TPM_PCRRead(TPM_PCRINDEX pcrIndex) {
  TPM_RQU_COMMAND_PCRREAD *in = (TPM_RQU_COMMAND_PCRREAD *)tis_buffers.in;

  // construct the command
  in->head.tag = ntohs(TPM_TAG_RQU_COMMAND);
  in->head.paramSize = ntohl(sizeof(TPM_RQU_COMMAND_PCRREAD));
  in->ordinal = ntohl(TPM_ORD_PcrRead);
  in->pcrIndex = ntohl(pcrIndex);

  tis_transmit_new();

  const TPM_RSP_COMMAND_PCRREAD *out =
      (const TPM_RSP_COMMAND_PCRREAD *)tis_buffers.out;
  const TPM_PCRREAD_RET ret = {.returnCode = ntohl(out->returnCode),
                               .outDigest = out->outDigest};

  return ret;
}

/* TPM_Extend */

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_COMMAND_CODE ordinal;
  TPM_PCRINDEX pcrNum;
  TPM_DIGEST inDigest;
} TPM_RQU_COMMAND_EXTEND;

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_RESULT returnCode;
  TPM_DIGEST outDigest;
} TPM_RSP_COMMAND_EXTEND;

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
