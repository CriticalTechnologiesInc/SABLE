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
#include "macro.h"
#include "platform.h"
#include "tcg.h"
#include "tis.h"
#include "sha.h"
#include "hmac.h"
#include "tpm_ordinal.h"
#include "tpm_struct.h"
#include "util.h"
#include "tpm.h"

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

struct TPM_PCRRead_ret TPM_PCRRead(TPM_PCRINDEX pcrIndex_in) {
  struct TPM_PCRRead_ret ret;
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
  unmarshal_UINT32(&ret.returnCode, &uctx, NULL);
  if (ret.returnCode)
    return ret;
  unmarshal_array(&ret.outDigest, sizeof(TPM_PCRVALUE), &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  assert(bytes_unpacked == paramSize_out);
  assert(tag_out == TPM_TAG_RSP_COMMAND);

  return ret;
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
                                 TPM_AUTHDATA nv_auth, TPM_SESSION *session) {
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

  hmac_init(&hctx, nv_auth.authdata, sizeof(TPM_SECRET)); // compute pubAuth
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

  hmac_init(&hctx, nv_auth.authdata, sizeof(TPM_SECRET)); // compute HM
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

TPM_RESULT TPM_NV_ReadValue(BYTE *data_out /* out */, TPM_NV_INDEX nvIndex_in,
                            UINT32 offset_in, UINT32 dataSize_in,
                            OPTION(TPM_AUTHDATA) ownerAuth_in,
                            TPM_SESSION *session) {

  assert((ownerAuth_in.hasValue && session) ||
         (!ownerAuth_in.hasValue && !session));

  TPM_TAG tag_in;
  UINT32 paramSize_in;
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_NV_ReadValue;
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;
  SHA1_Context sctx;
  HMAC_Context hctx;

  TPM_TAG tag_out;
  UINT32 paramSize_out;
  TPM_AUTHDATA ownerAuth_out;

  if (session != NULL) {
    tag_in = TPM_TAG_RQU_AUTH1_COMMAND;
    paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_COMMAND_CODE) +
                   sizeof(TPM_NV_INDEX) + sizeof(UINT32) + sizeof(UINT32) +
                   sizeof(TPM_AUTHHANDLE) + sizeof(TPM_NONCE) +
                   sizeof(TSS_BOOL) + sizeof(TPM_AUTHDATA);
  } else {
    tag_in = TPM_TAG_RQU_COMMAND;
    paramSize_in = sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_COMMAND_CODE) +
                   sizeof(TPM_NV_INDEX) + sizeof(UINT32) + sizeof(UINT32);
  }

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));
  sha1_init(&sctx); // compute inParamDigest
  marshal_UINT16(tag_in, &pctx, NULL);
  marshal_UINT32(paramSize_in, &pctx, NULL);
  marshal_UINT32(ordinal_in, &pctx, &sctx);  // 1S
  marshal_UINT32(nvIndex_in, &pctx, &sctx);  // 2S
  marshal_UINT32(offset_in, &pctx, &sctx);   // 3S
  marshal_UINT32(dataSize_in, &pctx, &sctx); // 4S
  sha1_finish(&sctx);                        // inParamDigest = sctx.hash

  if (session != NULL) {
    hmac_init(&hctx, ownerAuth_in.value.authdata,
              sizeof(TPM_SECRET)); // compute ownerAuth
    marshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
    marshal_UINT32(session->authHandle, &pctx, NULL);
    marshal_array(&session->nonceEven, sizeof(TPM_NONCE), NULL,
                  &hctx.sctx); // 2H1
    marshal_array(&session->nonceOdd, sizeof(TPM_NONCE), &pctx,
                  &hctx.sctx);                                     // 3H1
    marshal_BYTE(session->continueAuthSession, &pctx, &hctx.sctx); // 4H1
    hmac_finish(&hctx); // inAuth = hctx.sctx.hash
    marshal_array(&hctx.sctx.hash, sizeof(TPM_NONCE), &pctx, NULL);
  }

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);
  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));
  sha1_init(&sctx); // compute outParamDigest
  unmarshal_UINT16(&tag_out, &uctx, NULL);

  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, &sctx); // 1S

  if (res) {
    return res;
  }
  if (session != NULL) {
    assert(tag_out == TPM_TAG_RSP_AUTH1_COMMAND);
  } else {
    assert(tag_out == TPM_TAG_RSP_COMMAND);
  }

  unmarshal_UINT32(&ordinal_in, NULL, &sctx);           // 2S
  unmarshal_UINT32(&dataSize_in, &uctx, &sctx);         // 3S
  unmarshal_array(data_out, dataSize_in, &uctx, &sctx); // 4S
  sha1_finish(&sctx); // outParamDigest = sctx.hash

  if (session != NULL) {
    hmac_init(&hctx, ownerAuth_in.value.authdata,
              sizeof(TPM_SECRET)); // compute HM
    unmarshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
    unmarshal_array(&session->nonceEven, sizeof(TPM_NONCE), &uctx,
                    &hctx.sctx); // 2H1
    unmarshal_array(&session->nonceOdd, sizeof(TPM_NONCE), NULL,
                    &hctx.sctx);                                      // 3H1
    unmarshal_BYTE(&session->continueAuthSession, &uctx, &hctx.sctx); // 4H1
    hmac_finish(&hctx); // HM = hctx.sctx.hash
    unmarshal_array(&ownerAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);
  }

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  assert(bytes_unpacked == paramSize_out);
  if (session != NULL) {
    assert(session->continueAuthSession == FALSE);
  }
  if (session != NULL) {
    ERROR(-1, memcmp(&hctx.sctx.hash, &ownerAuth_out, sizeof(TPM_AUTHDATA)),
          "MiM attack detected!");
  }
  return res;
}

TPM_RESULT TPM_Unseal(TPM_STORED_DATA12 inData_in /* in */,
                      BYTE *secret_out /* out */, UINT32 secretSizeMax,
                      TPM_KEY_HANDLE parentHandle_in, TPM_AUTHDATA parentAuth,
                      TPM_SESSION *parentSession, TPM_AUTHDATA dataAuth,
                      TPM_SESSION *dataSession) {
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;
  SHA1_Context sctx;
  HMAC_Context hctx;

  TPM_TAG tag_in = TPM_TAG_RQU_AUTH2_COMMAND;
  UINT32 inDataSize_in = sizeof_TPM_STORED_DATA12(&inData_in);
  UINT32 paramSize_in =
      sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_COMMAND_CODE) +
      sizeof(TPM_KEY_HANDLE) + inDataSize_in + sizeof(TPM_AUTHHANDLE) +
      sizeof(TPM_NONCE) + sizeof(TSS_BOOL) + sizeof(TPM_AUTHDATA) +
      sizeof(TPM_AUTHHANDLE) + sizeof(TPM_NONCE) + sizeof(TSS_BOOL) +
      sizeof(TPM_AUTHDATA);

  TPM_COMMAND_CODE ordinal_in = TPM_ORD_Unseal;
  TPM_TAG tag_out;
  UINT32 paramSize_out;
  TPM_AUTHDATA resAuth_out;
  TPM_AUTHDATA dataAuth_out;

  pack_init(&pctx, tis_buffers.in, sizeof(tis_buffers.in));

  sha1_init(&sctx); // compute inParamDigest
  marshal_UINT16(tag_in, &pctx, NULL);
  marshal_UINT32(paramSize_in, &pctx, NULL);
  marshal_UINT32(ordinal_in, &pctx, &sctx); // 1S
  marshal_UINT32(parentHandle_in, &pctx, NULL);
  marshal_TPM_STORED_DATA12(&inData_in, &pctx, &sctx); // 2S
  sha1_finish(&sctx); // inParamDigest = sctx.hash

  hmac_init(&hctx, parentAuth.authdata,
            sizeof(TPM_SECRET)); // compute parentAuth
  marshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
  marshal_UINT32(parentSession->authHandle, &pctx, NULL);
  marshal_array(&parentSession->nonceEven, sizeof(TPM_NONCE), NULL,
                &hctx.sctx); // 2H1
  marshal_array(&parentSession->nonceOdd, sizeof(TPM_NONCE), &pctx,
                &hctx.sctx);                                           // 3H1
  marshal_BYTE(parentSession->continueAuthSession, &pctx, &hctx.sctx); // 4H1
  hmac_finish(&hctx); // inAuth = hctx.sctx.hash
  marshal_array(&hctx.sctx.hash, sizeof(TPM_DIGEST), &pctx, NULL);

  hmac_init(&hctx, dataAuth.authdata, sizeof(TPM_SECRET)); // compute dataAuth
  marshal_UINT32(dataSession->authHandle, &pctx, NULL);
  marshal_array(&dataSession->nonceEven, sizeof(TPM_NONCE), NULL,
                &hctx.sctx); // 2H2
  marshal_array(&dataSession->nonceOdd, sizeof(TPM_NONCE), &pctx,
                &hctx.sctx);                                         // 3H2
  marshal_BYTE(dataSession->continueAuthSession, &pctx, &hctx.sctx); // 4H2
  hmac_finish(&hctx); // inAuth = hctx.sctx.hash
  marshal_array(&hctx.sctx.hash, sizeof(TPM_DIGEST), &pctx, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  assert(bytes_packed == paramSize_in);

  tis_transmit();

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  sha1_init(&sctx); // compute outParamDigest
  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, &sctx); // 1S
  if (res) {
    return res;
  }
  assert(tag_out == TPM_TAG_RSP_AUTH2_COMMAND);
  unmarshal_UINT32(&ordinal_in, NULL, &sctx);     // 2S
  unmarshal_UINT32(&secretSizeMax, &uctx, &sctx); // 3S
  unmarshal_BYTE(secret_out, &uctx, &sctx);       // 4S
  sha1_finish(&sctx);                             // outParamDigest = sctx.hash

  hmac_init(&hctx, parentAuth.authdata, sizeof(TPM_SECRET)); // compute HM
  unmarshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx);
  unmarshal_array(&parentSession->nonceEven, sizeof(TPM_NONCE), &uctx,
                  &hctx.sctx); // 2H1
  unmarshal_array(&parentSession->nonceOdd, sizeof(TPM_NONCE), NULL,
                  &hctx.sctx); // 3H1
  unmarshal_BYTE(&parentSession->continueAuthSession, &uctx, &hctx.sctx);
  unmarshal_array(&resAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);
  hmac_finish(&hctx); // HM = hctx.sctx.hash

  // ERROR(-1, memcmp(&hctx.sctx.hash, &resAuth_out, sizeof(TPM_AUTHDATA)),
  //	"MiM attack detected!");

  hmac_init(&hctx, dataAuth.authdata, sizeof(TPM_SECRET)); // compute HM
  unmarshal_array(&dataSession->nonceEven, sizeof(TPM_NONCE), &uctx,
                  &hctx.sctx); // 2H2
  unmarshal_array(&dataSession->nonceOdd, sizeof(TPM_NONCE), NULL,
                  &hctx.sctx);                                          // 3H2
  unmarshal_BYTE(&dataSession->continueAuthSession, &uctx, &hctx.sctx); // 4H2
  unmarshal_array(&dataAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);
  hmac_finish(&hctx); // HM = hctx.sctx.hash

  // ERROR(-1, memcmp(&hctx.sctx.hash, &dataAuth_out, sizeof(TPM_AUTHDATA)),
  //	"MiM attack detected!");

  // UINT32 bytes_unpacked = unpack_finish(&uctx);
  // assert(bytes_unpacked == paramSize_out);
  // assert(parentSession->continueAuthSession == FALSE);
  // assert(dataSession->continueAuthSession == FALSE);

  return res;
}

struct TPM_Seal_ret TPM_Seal(BYTE *rawData /* out */, UINT32 rawDataSize,
                             TPM_KEY_HANDLE keyHandle_in,
                             TPM_ENCAUTH encAuth_in,
                             TPM_PCR_INFO_LONG pcrInfo_in,
                             const BYTE *inData_in, UINT32 inDataSize_in,
                             TPM_SESSION *session, TPM_SECRET sharedSecret) {
  struct TPM_Seal_ret ret;
  Pack_Context pctx;
  Unpack_Context uctx;
  SHA1_Context sctx;
  HMAC_Context hctx;

  TPM_TAG tag_in = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 pcrInfoSize_in = sizeof_TPM_PCR_INFO_LONG(&pcrInfo_in);
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
  marshal_TPM_PCR_INFO_LONG(&pcrInfo_in, &pctx, &sctx);          // 4S
  marshal_UINT32(inDataSize_in, &pctx, &sctx);                   // 5S
  marshal_array(inData_in, inDataSize_in, &pctx, &sctx);         // 6S
  sha1_finish(&sctx); // inParamDigest = sctx.hash

  hmac_init(&hctx, sharedSecret.authdata,
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

  sha1_init(&sctx);                                // compute outParamDigest
  unmarshal_UINT16(&tag_out, &uctx, NULL);         //
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);   //
  unmarshal_UINT32(&ret.returnCode, &uctx, &sctx); // 1S
  if (ret.returnCode)                              //
    return ret;                                    //
  unmarshal_UINT32(&ordinal_in, NULL, &sctx);      // 2S
  unmarshal_TPM_STORED_DATA12(&ret.sealedData, &uctx, &sctx); // 3S
  sha1_finish(&sctx); // outParamDigest = sctx.hash

  hmac_init(&hctx, sharedSecret.authdata, sizeof(TPM_SECRET)); // compute HM
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
  marshal_TPM_STORED_DATA12(&ret.sealedData, &pctx, NULL);
  pack_finish(&pctx);
  // Direct storedData to reference rawData
  unpack_init(&uctx, rawData, rawDataSize);
  unmarshal_TPM_STORED_DATA12(&ret.sealedData, &uctx, NULL);
  unpack_finish(&uctx);

  ERROR(-1, memcmp(&hctx.sctx.hash, &resAuth_out, sizeof(TPM_AUTHDATA)),
        "MiM attack detected!");

  return ret;
}
