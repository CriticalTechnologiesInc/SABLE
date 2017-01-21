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
  Pack_Context pctx;
  Unpack_Context uctx;

  TPM_TAG tag_in = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) +
                        sizeof(TPM_COMMAND_CODE) + sizeof(TPM_ENTITY_TYPE) +
                        sizeof(UINT32) + sizeof(TPM_NONCE);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_OSAP;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  pack_UINT16(&pctx, tag_in, NULL);
  pack_UINT32(&pctx, paramSize_in, NULL);
  pack_UINT32(&pctx, ordinal_in, NULL);
  pack_UINT16(&pctx, entityType_in, NULL);
  pack_UINT32(&pctx, entityValue_in, NULL);
  pack_array(&pctx, nonceOddOSAP_in.nonce, sizeof(TPM_NONCE), NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit_new();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  TPM_TAG tag_out = unpack_UINT16(&uctx, NULL);
  UINT32 paramSize_out = unpack_UINT32(&uctx, NULL);
  TPM_RESULT returnCode_out = unpack_UINT32(&uctx, NULL);
  ret.returnCode = returnCode_out;
  if (ret.returnCode)
    return ret;
  TPM_AUTHHANDLE authHandle_out = unpack_UINT32(&uctx, NULL);
  TPM_NONCE nonceEven_out =
      *(TPM_NONCE *)unpack_array(&uctx, sizeof(TPM_NONCE), NULL);
  TPM_NONCE nonceEvenOSAP_out =
      *(TPM_NONCE *)unpack_array(&uctx, sizeof(TPM_NONCE), NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
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

TPM_SEAL_RET TPM_Seal(TPM_KEY_HANDLE keyHandle_in, TPM_ENCAUTH encAuth_in,
                      const void *pcrInfo_in, UINT32 pcrInfoSize_in,
                      const BYTE *inData_in, UINT32 inDataSize_in,
                      TPM_SESSION *session, const TPM_SECRET *sharedSecret) {
  TPM_SEAL_RET ret;
  Pack_Context pctx;
  Unpack_Context uctx;
  SHA1_Context sctx;
  HMAC_Context hctx;

  TPM_TAG tag_in = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 paramSize_in =
      sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_COMMAND_CODE) +
      sizeof(TPM_KEY_HANDLE) + sizeof(TPM_ENCAUTH) + sizeof(UINT32) +
      pcrInfoSize_in + sizeof(UINT32) + inDataSize_in + sizeof(TPM_AUTHHANDLE) +
      sizeof(TPM_NONCE) + sizeof(TSS_BOOL) + sizeof(TPM_AUTHDATA);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_Seal;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  sha1_init(&sctx);                                     // compute S
  pack_UINT16(&pctx, tag_in, NULL);                     //
  pack_UINT32(&pctx, paramSize_in, NULL);               //
  pack_UINT32(&pctx, ordinal_in, &sctx);                // 1S
  pack_UINT32(&pctx, keyHandle_in, NULL);               //
  pack_array(&pctx, encAuth_in.authdata,                // 2S
             sizeof(TPM_ENCAUTH), &sctx);               // 2S
  pack_UINT32(&pctx, pcrInfoSize_in, &sctx);            // 3S
  pack_array(&pctx, pcrInfo_in, pcrInfoSize_in, &sctx); // 4S
  pack_UINT32(&pctx, inDataSize_in, &sctx);             // 5S
  pack_array(&pctx, inData_in, inDataSize_in, &sctx);   // 6S
  sha1_finish(&sctx);
  TPM_DIGEST inParamDigest = sctx.hash;

  hmac_init(&hctx, sharedSecret->authdata, sizeof(TPM_SECRET)); // compute H1
  hmac(&hctx, inParamDigest.digest, sizeof(TPM_DIGEST));        // 1H1
  pack_UINT32(&pctx, session->authHandle, NULL);                //
  hmac(&hctx, session->nonceEven.nonce, sizeof(TPM_NONCE));     // 2H1
  pack_array(&pctx, session->nonceOdd.nonce, sizeof(TPM_NONCE), // 3H1
             &hctx.sctx);                                       // 3H1
  pack_BYTE(&pctx, session->continueAuthSession, &hctx.sctx);   // 4H1
  hmac_finish(&hctx);                                           //
  TPM_AUTHDATA pubAuth_in = *(TPM_AUTHDATA *)&hctx.sctx.hash;   //
  pack_array(&pctx, pubAuth_in.authdata, sizeof(TPM_DIGEST),    //
             NULL);                                             //

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit_new();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));
  sha1_init(&sctx);                                        // compute S
  TPM_TAG tag_out = unpack_UINT16(&uctx, NULL);            //
  UINT32 paramSize_out = unpack_UINT32(&uctx, NULL);       //
  ret.returnCode = unpack_UINT32(&uctx, &sctx);            // 1S
  if (ret.returnCode)                                      //
    return ret;                                            //
  sha1(&sctx, &ordinal_in, sizeof(UINT32));                // 2S
  ret.sealedData = unpack_TPM_STORED_DATA12(&uctx, &sctx); // 3S
  sha1_finish(&sctx);
  TPM_DIGEST outParamDigest = sctx.hash;

  hmac_init(&hctx, sharedSecret->authdata, sizeof(TPM_SECRET)); // compute H1
  hmac(&hctx, outParamDigest.digest, sizeof(TPM_DIGEST));       // 1H1
  session->nonceEven =                                          //
      *(TPM_NONCE *)unpack_array(&uctx, sizeof(TPM_NONCE), &hctx.sctx); // 2H1
  hmac(&hctx, session->nonceOdd.nonce, sizeof(TPM_NONCE));              // 3H1
  session->continueAuthSession = unpack_BYTE(&uctx, &hctx.sctx);        // 4H1
  TPM_AUTHDATA resAuth_out =                                            //
      *(TPM_AUTHDATA *)unpack_array(&uctx, sizeof(TPM_AUTHDATA), NULL); //

  hmac_finish(&hctx);
  TPM_AUTHDATA H1 = *(TPM_AUTHDATA *)&hctx.sctx.hash;
  UINT32 bytes_unpacked = unpack_finish(&uctx);

  assert(tag_out == TPM_TAG_RSP_AUTH1_COMMAND);
  assert(bytes_unpacked == paramSize_out);
  assert(session->continueAuthSession == FALSE);

  ERROR(-1, memcmp(H1.authdata, resAuth_out.authdata, sizeof(TPM_AUTHDATA)),
        "MiM attack detected!");

  return ret;
}

TPM_PCRREAD_RET
TPM_PCRRead(TPM_PCRINDEX pcrIndex_in) {
  TPM_PCRREAD_RET ret;
  Pack_Context pctx;
  Unpack_Context uctx;

  TPM_TAG tag_in = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) +
                        sizeof(TPM_COMMAND_CODE) + sizeof(TPM_PCRINDEX);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_PcrRead;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));
  pack_UINT16(&pctx, tag_in, NULL);
  pack_UINT32(&pctx, paramSize_in, NULL);
  pack_UINT32(&pctx, ordinal_in, NULL);
  pack_UINT32(&pctx, pcrIndex_in, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit_new();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));
  TPM_TAG tag_out = unpack_UINT16(&uctx, NULL);
  UINT32 paramSize_out = unpack_UINT32(&uctx, NULL);
  TPM_RESULT returnCode_out = unpack_UINT32(&uctx, NULL);
  ret.returnCode = returnCode_out;
  if (ret.returnCode)
    return ret;
  ret.outDigest = *(TPM_PCRVALUE *)unpack_array(&uctx, sizeof(TPM_PCRVALUE), NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  assert(tag_out == TPM_TAG_RSP_COMMAND);
  assert(bytes_unpacked == paramSize_out);

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
  stTPM_STARTUP com;
  UINT32 paramSize = sizeof(stTPM_STARTUP);
  BYTE out_buffer[128];

  com.tag = ntohs(TPM_TAG_RQU_COMMAND);
  com.paramSize = ntohl(paramSize);
  com.ordinal = ntohl(TPM_ORD_Startup);
  com.startupType = ntohs(TPM_ST_CLEAR);

  SABLE_TPM_COPY_TO(&com, sizeof(stTPM_STARTUP));
  ERROR(TPM_TRANSMIT_FAIL,
        tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE) < 0,
        s_TPM_Startup_failed_on_transmit);

  res = (TPM_RESULT)ntohl(*((UINT32 *)(in_buffer + 6)));

  return res;
}
