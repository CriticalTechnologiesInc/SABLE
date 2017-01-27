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

#include "asm.h"
#include "platform.h"
#include "tpm_ordinal.h"
#include "tcg.h"
#include "tis.h"
#include "tpm.h"
#include "sha.h"
#include "hmac.h"
#include "tpm_struct.h"
#include "util.h"

TPM_RESULT TPM_Startup(TPM_STARTUP_TYPE startupType_in) {
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;

  TPM_TAG tag_in = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) +
                        sizeof(TPM_COMMAND_CODE) + sizeof(TPM_STARTUP_TYPE);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_Startup;
  TPM_TAG tag_out;
  UINT32 paramSize_out;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  marshal_UINT16(tag_in, &pctx, NULL);
  marshal_UINT32(paramSize_in, &pctx, NULL);
  marshal_UINT32(ordinal_in, &pctx, NULL);
  marshal_UINT16(startupType_in, &pctx, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  assert(bytes_unpacked == paramSize_out);
  assert(tag_out == TPM_TAG_RSP_COMMAND);

  return res;
}

TPM_RESULT TPM_GetRandom(BYTE *randomBytes_out /* out */,
                         UINT32 bytesRequested_in) {
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;

  TPM_TAG tag_in = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) +
                        sizeof(TPM_COMMAND_CODE) + sizeof(UINT32);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_GetRandom;
  TPM_TAG tag_out;
  UINT32 paramSize_out;
  UINT32 randomBytesSize_out;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  marshal_UINT16(tag_in, &pctx, NULL);
  marshal_UINT32(paramSize_in, &pctx, NULL);
  marshal_UINT32(ordinal_in, &pctx, NULL);
  marshal_UINT32(bytesRequested_in, &pctx, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  if (res)
    return res;
  unmarshal_UINT32(&randomBytesSize_out, &uctx, NULL);
  assert(bytesRequested_in == randomBytesSize_out);
  unmarshal_array(randomBytes_out, randomBytesSize_out, &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  assert(bytes_unpacked == paramSize_out);
  assert(tag_out == TPM_TAG_RSP_COMMAND);

  return res;
}

TPM_RESULT TPM_PCRRead(TPM_PCRINDEX pcrIndex_in,
                       TPM_PCRVALUE *outDigest_out /* out */) {
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;

  TPM_TAG tag_in = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) +
                        sizeof(TPM_COMMAND_CODE) + sizeof(TPM_PCRINDEX);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_PcrRead;
  TPM_TAG tag_out;
  UINT32 paramSize_out;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  marshal_UINT16(tag_in, &pctx, NULL);
  marshal_UINT32(paramSize_in, &pctx, NULL);
  marshal_UINT32(ordinal_in, &pctx, NULL);
  marshal_UINT32(pcrIndex_in, &pctx, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  if (res)
    return res;
  unmarshal_array(outDigest_out, sizeof(TPM_PCRVALUE), &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  assert(bytes_unpacked == paramSize_out);
  assert(tag_out == TPM_TAG_RSP_COMMAND);

  return res;
}

TPM_RESULT TPM_Extend(TPM_PCRINDEX pcrNum_in, TPM_DIGEST inDigest_in,
                      TPM_PCRVALUE *outDigest_out /* out */) {
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;

  TPM_TAG tag_in = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) +
                        sizeof(TPM_COMMAND_CODE) + sizeof(TPM_PCRINDEX) +
                        sizeof(TPM_DIGEST);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_Extend;
  TPM_TAG tag_out;
  UINT32 paramSize_out;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  marshal_UINT16(tag_in, &pctx, NULL);
  marshal_UINT32(paramSize_in, &pctx, NULL);
  marshal_UINT32(ordinal_in, &pctx, NULL);
  marshal_UINT32(pcrNum_in, &pctx, NULL);
  marshal_array(&inDigest_in, sizeof(TPM_DIGEST), &pctx, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  if (res)
    return res;
  unmarshal_array(outDigest_out, sizeof(TPM_PCRVALUE), &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  assert(bytes_unpacked == paramSize_out);
  assert(tag_out == TPM_TAG_RSP_COMMAND);

  return res;
}

TPM_RESULT TPM_OIAP(TPM_SESSION *session /* out */) {
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;

  TPM_TAG tag_in = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize_in =
      sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_COMMAND_CODE);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_OIAP;
  TPM_TAG tag_out;
  UINT32 paramSize_out;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  marshal_UINT16(tag_in, &pctx, NULL);
  marshal_UINT32(paramSize_in, &pctx, NULL);
  marshal_UINT32(ordinal_in, &pctx, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  if (res)
    return res;
  unmarshal_UINT32(&session->authHandle, &uctx, NULL);
  unmarshal_array(&session->nonceEven, sizeof(TPM_NONCE), &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  assert(bytes_unpacked == paramSize_out);
  assert(tag_out == TPM_TAG_RSP_COMMAND);

  // Initialize the remainder of the session with default values
  memset(&session->nonceOdd, 0, sizeof(TPM_NONCE));
  session->continueAuthSession = FALSE;

  return res;
}

TPM_RESULT TPM_OSAP(TPM_ENTITY_TYPE entityType_in, UINT32 entityValue_in,
                    TPM_OSAP_SESSION *osap_session /* out */) {
  TPM_RESULT ret;
  Pack_Context pctx;
  Unpack_Context uctx;

  TPM_TAG tag_in = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) +
                        sizeof(TPM_COMMAND_CODE) + sizeof(TPM_ENTITY_TYPE) +
                        sizeof(UINT32) + sizeof(TPM_NONCE);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_OSAP;
  TPM_TAG tag_out;
  UINT32 paramSize_out;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  marshal_UINT16(tag_in, &pctx, NULL);
  marshal_UINT32(paramSize_in, &pctx, NULL);
  marshal_UINT32(ordinal_in, &pctx, NULL);
  marshal_UINT16(entityType_in, &pctx, NULL);
  marshal_UINT32(entityValue_in, &pctx, NULL);
  marshal_array(&osap_session->nonceOddOSAP, sizeof(TPM_NONCE), &pctx, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&ret, &uctx, NULL);
  if (ret)
    return ret;
  unmarshal_UINT32(&osap_session->session.authHandle, &uctx, NULL);
  unmarshal_array(&osap_session->session.nonceEven, sizeof(TPM_NONCE), &uctx,
                  NULL);
  unmarshal_array(&osap_session->nonceEvenOSAP, sizeof(TPM_NONCE), &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  assert(bytes_unpacked == paramSize_out);
  assert(tag_out == TPM_TAG_RSP_COMMAND);

  // Initialize the remainder of the session with default values
  memset(&osap_session->session.nonceOdd, 0, sizeof(TPM_NONCE));
  osap_session->session.continueAuthSession = FALSE;

  return ret;
}

TPM_RESULT TPM_NV_WriteValueAuth(const BYTE *data_in, UINT32 dataSize_in,
                                 TPM_NV_INDEX nvIndex_in, UINT32 offset_in,
                                 const TPM_AUTHDATA *nv_auth,
                                 TPM_SESSION *session) {
  TPM_RESULT ret;
  Pack_Context pctx;
  Unpack_Context uctx;
  SHA1_Context sctx;
  HMAC_Context hctx;

  TPM_TAG tag_in = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) +
                        sizeof(TPM_COMMAND_CODE) + sizeof(TPM_NV_INDEX) +
                        sizeof(UINT32) + sizeof(UINT32) + dataSize_in +
                        sizeof(TPM_AUTHHANDLE) + sizeof(TPM_NONCE) +
                        sizeof(TPM_BOOL) + sizeof(TPM_AUTHDATA);
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_NV_WriteValueAuth;
  TPM_TAG tag_out;
  UINT32 paramSize_out;
  TPM_AUTHDATA resAuth_out;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  sha1_init(&sctx);                                  // compute inParamDigest
  marshal_UINT16(tag_in, &pctx, NULL);               //
  marshal_UINT32(paramSize_in, &pctx, NULL);         //
  marshal_UINT32(ordinal_in, &pctx, &sctx);          // 1S
  marshal_UINT32(nvIndex_in, &pctx, &sctx);          // 2S
  marshal_UINT32(offset_in, &pctx, &sctx);           // 3S
  marshal_UINT32(dataSize_in, &pctx, &sctx);         // 4S
  marshal_array(data_in, dataSize_in, &pctx, &sctx); // 5S
  sha1_finish(&sctx); // inParamDigest = sctx.hash

  hmac_init(&hctx, nv_auth->authdata, sizeof(TPM_SECRET)); // compute pubAuth
  marshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
  marshal_UINT32(session->authHandle, &pctx, NULL);                //
  marshal_array(&session->nonceEven, sizeof(TPM_NONCE), NULL,      // 2H1
                &hctx.sctx);                                       // 2H1
  marshal_array(&session->nonceOdd, sizeof(TPM_NONCE), &pctx,      // 3H1
                &hctx.sctx);                                       // 3H1
  marshal_BYTE(session->continueAuthSession, &pctx, &hctx.sctx);   // 4H1
  hmac_finish(&hctx); // inAuth = hctx.sctx.hash
  marshal_array(&hctx.sctx.hash, sizeof(TPM_DIGEST), &pctx, NULL); //

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  sha1_init(&sctx);                              // compute outParamDigest
  unmarshal_UINT16(&tag_out, &uctx, NULL);       //
  unmarshal_UINT32(&paramSize_out, &uctx, NULL); //
  unmarshal_UINT32(&ret, &uctx, &sctx);          // 1S
  if (ret)                                       //
    return ret;                                  //
  unmarshal_UINT32(&ordinal_in, NULL, &sctx);    // 2S
  sha1_finish(&sctx);                            // outParamDigest = sctx.hash

  hmac_init(&hctx, nv_auth->authdata, sizeof(TPM_SECRET)); // compute HM
  unmarshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
  unmarshal_array(&session->nonceEven, sizeof(TPM_NONCE), &uctx,     // 2H1
                  &hctx.sctx);                                       // 2H1
  unmarshal_array(&session->nonceOdd, sizeof(TPM_NONCE), NULL,       // 3H1
                  &hctx.sctx);                                       // 3H1
  unmarshal_BYTE(&session->continueAuthSession, &uctx, &hctx.sctx);  // 4H1
  unmarshal_array(&resAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);  //
  hmac_finish(&hctx); // HM = hctx.sctx.hash

  UINT32 bytes_unpacked = unpack_finish(&uctx);

  assert(bytes_unpacked == paramSize_out);
  assert(session->continueAuthSession == FALSE);
  assert(tag_out == TPM_TAG_RSP_AUTH1_COMMAND);

  ERROR(-1, memcmp(&hctx.sctx.hash, &resAuth_out, sizeof(TPM_AUTHDATA)),
        "MiM attack detected!");

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

/*TPM_RESULT TPM_NV_ReadValue(BYTE *data, UINT32 dataSize, TPM_NV_INDEX nvIndex,
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
}*/

TPM_RESULT TPM_Seal(TPM_STORED_DATA12 *storedData /* out */,
                    BYTE *rawData /* out */, UINT32 rawDataSize,
                    TPM_KEY_HANDLE keyHandle_in, TPM_ENCAUTH encAuth_in,
                    const void *pcrInfo_in, UINT32 pcrInfoSize_in,
                    const BYTE *inData_in, UINT32 inDataSize_in,
                    TPM_SESSION *session, const TPM_SECRET *sharedSecret) {
  TPM_RESULT res;
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
  TPM_TAG tag_out;
  UINT32 paramSize_out;
  TPM_AUTHDATA resAuth_out;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  sha1_init(&sctx);                          // compute inParamDigest
  marshal_UINT16(tag_in, &pctx, NULL);       //
  marshal_UINT32(paramSize_in, &pctx, NULL); //
  marshal_UINT32(ordinal_in, &pctx, &sctx);  // 1S
  marshal_UINT32(keyHandle_in, &pctx, NULL); //
  marshal_array(&encAuth_in, sizeof(TPM_ENCAUTH), &pctx, &sctx); // 2S
  marshal_UINT32(pcrInfoSize_in, &pctx, &sctx);                  // 3S
  marshal_array(pcrInfo_in, pcrInfoSize_in, &pctx, &sctx);       // 4S
  marshal_UINT32(inDataSize_in, &pctx, &sctx);                   // 5S
  marshal_array(inData_in, inDataSize_in, &pctx, &sctx);         // 6S
  sha1_finish(&sctx); // inParamDigest = sctx.hash

  hmac_init(&hctx, sharedSecret->authdata,
            sizeof(TPM_SECRET)); // compute pubAuth
  marshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
  marshal_UINT32(session->authHandle, &pctx, NULL);                //
  marshal_array(&session->nonceEven, sizeof(TPM_NONCE), NULL,      // 2H1
                &hctx.sctx);                                       // 2H1
  marshal_array(&session->nonceOdd, sizeof(TPM_NONCE), &pctx,      // 3H1
                &hctx.sctx);                                       // 3H1
  marshal_BYTE(session->continueAuthSession, &pctx, &hctx.sctx);   // 4H1
  hmac_finish(&hctx); // inAuth = hctx.sctx.hash
  marshal_array(&hctx.sctx.hash, sizeof(TPM_DIGEST), &pctx, NULL); //

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  sha1_init(&sctx);                              // compute outParamDigest
  unmarshal_UINT16(&tag_out, &uctx, NULL);       //
  unmarshal_UINT32(&paramSize_out, &uctx, NULL); //
  unmarshal_UINT32(&res, &uctx, &sctx);          // 1S
  if (res)                                       //
    return res;                                  //
  unmarshal_UINT32(&ordinal_in, NULL, &sctx);    // 2S
  unmarshal_TPM_STORED_DATA12(storedData, &uctx, &sctx); // 3S
  sha1_finish(&sctx); // outParamDigest = sctx.hash

  hmac_init(&hctx, sharedSecret->authdata, sizeof(TPM_SECRET)); // compute HM
  unmarshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
  unmarshal_array(&session->nonceEven, sizeof(TPM_NONCE), &uctx,     // 2H1
                  &hctx.sctx);                                       // 2H1
  unmarshal_array(&session->nonceOdd, sizeof(TPM_NONCE), NULL,       // 3H1
                  &hctx.sctx);                                       // 3H1
  unmarshal_BYTE(&session->continueAuthSession, &uctx, &hctx.sctx);  // 4H1
  unmarshal_array(&resAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);  //
  hmac_finish(&hctx); // HM = hctx.sctx.hash

  UINT32 bytes_unpacked = unpack_finish(&uctx);

  assert(bytes_unpacked == paramSize_out);
  assert(session->continueAuthSession == FALSE);
  assert(tag_out == TPM_TAG_RSP_AUTH1_COMMAND);

  // Pack the storedData into a buffer
  pack_init(&pctx, rawData, rawDataSize);
  marshal_TPM_STORED_DATA12(storedData, &pctx, NULL);
  pack_finish(&pctx);

  ERROR(-1, memcmp(&hctx.sctx.hash, &resAuth_out, sizeof(TPM_AUTHDATA)),
        "MiM attack detected!");

  return res;
}
