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
#include "option.h"
#include "platform.h"
#include "exception.h"
#include "alloc.h"
#include "tcg.h"
#include "tis.h"
#include "sha.h"
#include "hmac.h"
#include "tpm_error.h"
#include "tpm_ordinal.h"
#include "tpm_struct.h"
#include "util.h"
#include "tpm.h"

RESULT TPM_Startup(TPM_STARTUP_TYPE startupType_in) {
  RESULT ret = {.exception.error = NONE};
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
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  TPM_ERROR(res);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  ERROR(tag_out != TPM_TAG_RSP_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad tag_out");

  return ret;
}

RESULT TPM_GetRandom(BYTE *randomBytes_out /* out */,
                     UINT32 bytesRequested_in) {
  RESULT ret = {.exception.error = NONE};
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
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  TPM_ERROR(res);
  unmarshal_UINT32(&randomBytesSize_out, &uctx, NULL);
  ERROR(bytesRequested_in != randomBytesSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Did not get the requested number of random bytes");
  unmarshal_array(randomBytes_out, randomBytesSize_out, &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  ERROR(tag_out != TPM_TAG_RSP_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad tag_out");

  return ret;
}

RESULT_(TPM_PCRVALUE) TPM_PCRRead(TPM_PCRINDEX pcrIndex_in) {
  RESULT_(TPM_PCRVALUE) ret = {.exception.error = NONE};
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
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  TPM_ERROR(res);
  unmarshal_array(&ret.value, sizeof(TPM_PCRVALUE), &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  ERROR(tag_out != TPM_TAG_RSP_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad tag_out");

  return ret;
}

RESULT_(TPM_PCRVALUE)
TPM_Extend(TPM_PCRINDEX pcrNum_in, TPM_DIGEST inDigest_in) {
  RESULT_(TPM_PCRVALUE) ret = {.exception.error = NONE};
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
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  TPM_ERROR(res);
  unmarshal_array(&ret.value, sizeof(TPM_PCRVALUE), &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  ERROR(tag_out != TPM_TAG_RSP_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad tag_out");

  return ret;
}

RESULT TPM_OIAP(TPM_SESSION **session) {
  ASSERT(session);
  RESULT ret = {.exception.error = NONE};
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
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  TPM_ERROR(res);
  TPM_SESSION *s = *session = alloc(sizeof(TPM_SESSION));
  unmarshal_UINT32(&s->authHandle, &uctx, NULL);
  unmarshal_array(&s->nonceEven, sizeof(TPM_NONCE), &uctx, NULL);
  s->osap = NULL;

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  ERROR(tag_out != TPM_TAG_RSP_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad tag_out");

  return ret;
}

RESULT TPM_OSAP(TPM_ENTITY_TYPE entityType_in, UINT32 entityValue_in,
                TPM_NONCE nonceOddOSAP, TPM_SESSION **session) {
  ASSERT(session);
  RESULT ret = {.exception.error = NONE};
  TPM_RESULT res;
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
  marshal_array(&nonceOddOSAP, sizeof(TPM_NONCE), &pctx, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  unmarshal_UINT16(&tag_out, &uctx, NULL);
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, NULL);
  TPM_ERROR(res);
  TPM_SESSION *s = *session = alloc(sizeof(TPM_SESSION));
  s->osap = alloc(sizeof(TPM_OSAP_EXTENSION));
  unmarshal_UINT32(&s->authHandle, &uctx, NULL);
  unmarshal_array(&s->nonceEven, sizeof(TPM_NONCE), &uctx, NULL);
  unmarshal_array(&s->osap->nonceEvenOSAP, sizeof(TPM_NONCE), &uctx, NULL);

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  ERROR(tag_out != TPM_TAG_RSP_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad tag_out");

  s->osap->nonceOddOSAP = nonceOddOSAP;

  return ret;
}

RESULT TPM_NV_WriteValueAuth(const BYTE *data_in, UINT32 dataSize_in,
                             TPM_NV_INDEX nvIndex_in, UINT32 offset_in,
                             TPM_AUTHDATA nv_auth, TPM_SESSION **session) {
  ASSERT(session);
  RESULT ret = {.exception.error = NONE};
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;
  SHA1_Context sctx;
  HMAC_Context hctx;
  TPM_SESSION *s = *session;

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
  marshal_UINT32(s->authHandle, &pctx, NULL);                      //
  marshal_array(&s->nonceEven, sizeof(TPM_NONCE), NULL,            // 2H1
                &hctx.sctx);                                       // 2H1
  marshal_array(&s->nonceOdd, sizeof(TPM_NONCE), &pctx,            // 3H1
                &hctx.sctx);                                       // 3H1
  marshal_BYTE(s->continueAuthSession, &pctx, &hctx.sctx);         // 4H1
  hmac_finish(&hctx); // inAuth = hctx.sctx.hash
  marshal_array(&hctx.sctx.hash, sizeof(TPM_DIGEST), &pctx, NULL); //

  UINT32 bytes_packed = pack_finish(&pctx);
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  sha1_init(&sctx);                              // compute outParamDigest
  unmarshal_UINT16(&tag_out, &uctx, NULL);       //
  unmarshal_UINT32(&paramSize_out, &uctx, NULL); //
  unmarshal_UINT32(&res, &uctx, &sctx);          // 1S
  TPM_ERROR(res);                                //
  unmarshal_UINT32(&ordinal_in, NULL, &sctx);    // 2S
  sha1_finish(&sctx);                            // outParamDigest = sctx.hash

  hmac_init(&hctx, nv_auth.authdata, sizeof(TPM_SECRET)); // compute HM
  unmarshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
  unmarshal_array(&s->nonceEven, sizeof(TPM_NONCE), &uctx,           // 2H1
                  &hctx.sctx);                                       // 2H1
  unmarshal_array(&s->nonceOdd, sizeof(TPM_NONCE), NULL,             // 3H1
                  &hctx.sctx);                                       // 3H1
  unmarshal_BYTE(&s->continueAuthSession, &uctx, &hctx.sctx);        // 4H1
  unmarshal_array(&resAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);  //
  hmac_finish(&hctx); // HM = hctx.sctx.hash

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  ERROR(tag_out != TPM_TAG_RSP_AUTH1_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad tag_out");

  if (!s->continueAuthSession)
    *session = NULL;

  ERROR(memcmp(&hctx.sctx.hash, &resAuth_out, sizeof(TPM_AUTHDATA)),
        ERROR_TPM_BAD_OUTPUT_AUTH, "Bad nvAuth out");

  return ret;
}

RESULT_(HEAP_DATA)
TPM_NV_ReadValue(TPM_NV_INDEX nvIndex_in, UINT32 offset_in, UINT32 dataSize_in,
                 OPTION(TPM_AUTHDATA) ownerAuth_in, TPM_SESSION **session) {
  ASSERT((ownerAuth_in.hasValue && session && *session) ||
         (!ownerAuth_in.hasValue && (!session || !*session)));
  RESULT_(HEAP_DATA) ret = {.exception.error = NONE};
  TPM_RESULT res;
  TPM_TAG tag_in;
  UINT32 paramSize_in;
  TPM_COMMAND_CODE ordinal_in = TPM_ORD_NV_ReadValue;
  Pack_Context pctx;
  Unpack_Context uctx;
  SHA1_Context sctx;
  HMAC_Context hctx;
  TPM_SESSION *s = session && *session ? *session : NULL;

  TPM_TAG tag_out;
  UINT32 paramSize_out;
  TPM_AUTHDATA ownerAuth_out;

  if (s) {
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

  if (s) {
    hmac_init(&hctx, ownerAuth_in.value.authdata,
              sizeof(TPM_SECRET)); // compute ownerAuth
    marshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
    marshal_UINT32(s->authHandle, &pctx, NULL);
    marshal_array(&s->nonceEven, sizeof(TPM_NONCE), NULL, &hctx.sctx); // 2H1
    marshal_array(&s->nonceOdd, sizeof(TPM_NONCE), &pctx, &hctx.sctx); // 3H1
    marshal_BYTE(s->continueAuthSession, &pctx, &hctx.sctx);           // 4H1
    hmac_finish(&hctx); // inAuth = hctx.sctx.hash
    marshal_array(&hctx.sctx.hash, sizeof(TPM_NONCE), &pctx, NULL);
  }

  UINT32 bytes_packed = pack_finish(&pctx);
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));
  sha1_init(&sctx); // compute outParamDigest
  unmarshal_UINT16(&tag_out, &uctx, NULL);

  unmarshal_UINT32(&paramSize_out, &uctx, NULL);
  unmarshal_UINT32(&res, &uctx, &sctx);                             // 1S
  TPM_ERROR(res);                                                   //
  unmarshal_UINT32(&ordinal_in, NULL, &sctx);                       // 2S
  unmarshal_UINT32(&ret.value.dataSize, &uctx, &sctx);              // 3S
  unmarshal_ptr(&ret.value.data, ret.value.dataSize, &uctx, &sctx); // 4S
  sha1_finish(&sctx); // outParamDigest = sctx.hash

  if (s) {
    hmac_init(&hctx, ownerAuth_in.value.authdata,
              sizeof(TPM_SECRET)); // compute HM
    unmarshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx);    // 1H1
    unmarshal_array(&s->nonceEven, sizeof(TPM_NONCE), &uctx, &hctx.sctx); // 2H1
    unmarshal_array(&s->nonceOdd, sizeof(TPM_NONCE), NULL, &hctx.sctx);   // 3H1
    unmarshal_BYTE(&s->continueAuthSession, &uctx, &hctx.sctx);           // 4H1
    hmac_finish(&hctx); // HM = hctx.sctx.hash
    unmarshal_array(&ownerAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);

    if (!s->continueAuthSession) {
      *session = NULL;
    }
  }

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  if (s) {
    ERROR(tag_out != TPM_TAG_RSP_AUTH1_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
          "Bad tag_out");
  } else {
    ERROR(tag_out != TPM_TAG_RSP_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
          "Bad tag_out");
  }
  if (s) {
    ERROR(memcmp(&hctx.sctx.hash, &ownerAuth_out, sizeof(TPM_AUTHDATA)),
          ERROR_TPM_BAD_OUTPUT_AUTH, "Bad output ownerAuth");
  }
  return ret;
}

RESULT_(HEAP_DATA)
TPM_Unseal(TPM_STORED_DATA12 inData_in /* in */, TPM_KEY_HANDLE parentHandle_in,
           TPM_AUTHDATA parentAuth, TPM_SESSION **parentSession,
           TPM_AUTHDATA dataAuth, TPM_SESSION **dataSession) {
  ASSERT(parentSession && dataSession);
  RESULT_(HEAP_DATA) ret = {.exception.error = NONE};
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;
  SHA1_Context sctx;
  HMAC_Context hctx;
  TPM_SESSION *parentS = *parentSession;
  TPM_SESSION *dataS = *dataSession;

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
  marshal_UINT32(parentS->authHandle, &pctx, NULL);                //
  marshal_array(&parentS->nonceEven, sizeof(TPM_NONCE), NULL,      // 2H1
                &hctx.sctx);                                       // 2H1
  marshal_array(&parentS->nonceOdd, sizeof(TPM_NONCE), &pctx,      // 3H1
                &hctx.sctx);                                       // 3H1
  marshal_BYTE(parentS->continueAuthSession, &pctx, &hctx.sctx);   // 4H1
  hmac_finish(&hctx); // inAuth = hctx.sctx.hash
  marshal_array(&hctx.sctx.hash, sizeof(TPM_DIGEST), &pctx, NULL);

  hmac_init(&hctx, dataAuth.authdata, sizeof(TPM_SECRET)); // compute dataAuth
  marshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H2
  marshal_UINT32(dataS->authHandle, &pctx, NULL);                  //
  marshal_array(&dataS->nonceEven, sizeof(TPM_NONCE), NULL,        // 2H2
                &hctx.sctx);                                       // 2H2
  marshal_array(&dataS->nonceOdd, sizeof(TPM_NONCE), &pctx,        // 3H2
                &hctx.sctx);                                       // 3H2
  marshal_BYTE(dataS->continueAuthSession, &pctx, &hctx.sctx);     // 4H2
  hmac_finish(&hctx); // inAuth = hctx.sctx.hash
  marshal_array(&hctx.sctx.hash, sizeof(TPM_DIGEST), &pctx, NULL);

  UINT32 bytes_packed = pack_finish(&pctx);
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  sha1_init(&sctx);                                    // compute outParamDigest
  unmarshal_UINT16(&tag_out, &uctx, NULL);             //
  unmarshal_UINT32(&paramSize_out, &uctx, NULL);       //
  unmarshal_UINT32(&res, &uctx, &sctx);                // 1S
  TPM_ERROR(res);                                      //
  unmarshal_UINT32(&ordinal_in, NULL, &sctx);          // 2S
  unmarshal_UINT32(&ret.value.dataSize, &uctx, &sctx); // 3S
  unmarshal_ptr(&ret.value.data, ret.value.dataSize, &uctx, &sctx); // 4S
  sha1_finish(&sctx); // outParamDigest = sctx.hash

  hmac_init(&hctx, parentAuth.authdata, sizeof(TPM_SECRET)); // compute HM1
  unmarshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
  unmarshal_array(&parentS->nonceEven, sizeof(TPM_NONCE), &uctx,     // 2H1
                  &hctx.sctx);                                       // 2H1
  unmarshal_array(&parentS->nonceOdd, sizeof(TPM_NONCE), NULL,       // 3H1
                  &hctx.sctx);                                       // 3H1
  unmarshal_BYTE(&parentS->continueAuthSession, &uctx, &hctx.sctx);  // 4H1
  unmarshal_array(&resAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);  //
  hmac_finish(&hctx); // HM = hctx.sctx.hash

  if (!parentS->continueAuthSession) {
    *parentSession = NULL;
  }

  ERROR(memcmp(&hctx.sctx.hash, &resAuth_out, sizeof(TPM_AUTHDATA)),
        ERROR_TPM_BAD_OUTPUT_AUTH, "Bad output parentAuth");

  hmac_init(&hctx, dataAuth.authdata, sizeof(TPM_SECRET)); // compute HM2
  unmarshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx);      // 1H2
  unmarshal_array(&dataS->nonceEven, sizeof(TPM_NONCE), &uctx,            // 2H2
                  &hctx.sctx);                                            // 2H2
  unmarshal_array(&dataS->nonceOdd, sizeof(TPM_NONCE), NULL, &hctx.sctx); // 3H2
  unmarshal_BYTE(&dataS->continueAuthSession, &uctx, &hctx.sctx);         // 4H2
  unmarshal_array(&dataAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);      //
  hmac_finish(&hctx); // HM = hctx.sctx.hash

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  ERROR(tag_out != TPM_TAG_RSP_AUTH2_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad tag_out");

  ERROR(memcmp(&hctx.sctx.hash, &dataAuth_out, sizeof(TPM_AUTHDATA)),
        ERROR_TPM_BAD_OUTPUT_AUTH, "Bad output dataAuth");

  if (!dataS->continueAuthSession) {
    *dataSession = NULL;
  }

  return ret;
}

RESULT_(TPM_STORED_DATA12)
TPM_Seal(TPM_KEY_HANDLE keyHandle_in, TPM_ENCAUTH encAuth_in,
         TPM_PCR_INFO_LONG pcrInfo_in, const BYTE *inData_in,
         UINT32 inDataSize_in, TPM_SESSION **session, TPM_SECRET sharedSecret) {
  ASSERT(session);
  RESULT_(TPM_STORED_DATA12) ret = {.exception.error = NONE};
  TPM_RESULT res;
  Pack_Context pctx;
  Unpack_Context uctx;
  SHA1_Context sctx;
  HMAC_Context hctx;
  TPM_SESSION *s = *session;

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
  marshal_UINT32(s->authHandle, &pctx, NULL);                      //
  marshal_array(&s->nonceEven, sizeof(TPM_NONCE), NULL,            // 2H1
                &hctx.sctx);                                       // 2H1
  marshal_array(&s->nonceOdd, sizeof(TPM_NONCE), &pctx,            // 3H1
                &hctx.sctx);                                       // 3H1
  marshal_BYTE(s->continueAuthSession, &pctx, &hctx.sctx);         // 4H1
  hmac_finish(&hctx); // inAuth = hctx.sctx.hash
  marshal_array(&hctx.sctx.hash, sizeof(TPM_DIGEST), &pctx, NULL); //

  UINT32 bytes_packed = pack_finish(&pctx);
  ASSERT(bytes_packed == paramSize_in);

  RESULT transmit_ret = tis_transmit();
  THROW(transmit_ret.exception);

  unpack_init(&uctx, tis_buffers.out, sizeof(tis_buffers.out));

  sha1_init(&sctx);                              // compute outParamDigest
  unmarshal_UINT16(&tag_out, &uctx, NULL);       //
  unmarshal_UINT32(&paramSize_out, &uctx, NULL); //
  unmarshal_UINT32(&res, &uctx, &sctx);          // 1S
  TPM_ERROR(res);                                //
  unmarshal_UINT32(&ordinal_in, NULL, &sctx);    // 2S
  unmarshal_TPM_STORED_DATA12(&ret.value, &uctx, &sctx); // 3S
  sha1_finish(&sctx); // outParamDigest = sctx.hash

  hmac_init(&hctx, sharedSecret.authdata, sizeof(TPM_SECRET)); // compute HM
  unmarshal_array(&sctx.hash, sizeof(TPM_DIGEST), NULL, &hctx.sctx); // 1H1
  unmarshal_array(&s->nonceEven, sizeof(TPM_NONCE), &uctx,           // 2H1
                  &hctx.sctx);                                       // 2H1
  unmarshal_array(&s->nonceOdd, sizeof(TPM_NONCE), NULL,             // 3H1
                  &hctx.sctx);                                       // 3H1
  unmarshal_BYTE(&s->continueAuthSession, &uctx, &hctx.sctx);        // 4H1
  unmarshal_array(&resAuth_out, sizeof(TPM_AUTHDATA), &uctx, NULL);  //
  hmac_finish(&hctx); // HM = hctx.sctx.hash

  UINT32 bytes_unpacked = unpack_finish(&uctx);
  ERROR(bytes_unpacked != paramSize_out, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad paramSize_out");
  ERROR(tag_out != TPM_TAG_RSP_AUTH1_COMMAND, ERROR_TPM_BAD_OUTPUT_PARAM,
        "Bad tag_out");

  ERROR(memcmp(&hctx.sctx.hash, &resAuth_out, sizeof(TPM_AUTHDATA)),
        ERROR_TPM_BAD_OUTPUT_AUTH, "Bad output sealing key auth");
  ERROR(s->continueAuthSession, ERROR_TPM_BAD_OUTPUT_PARAM,
        "TPM_Seal did not end the ADIP session");

  *session = NULL;

  return ret;
}
