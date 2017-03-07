#ifndef __TPM_H__
#define __TPM_H__

#include "tcg.h"
#include "option.h"
#include "exception.h"

OPTION_GEN(TPM_AUTHDATA);

typedef struct tdTPM_OSAP_EXTENSION {
  TPM_NONCE nonceEvenOSAP;
  TPM_NONCE nonceOddOSAP;
} TPM_OSAP_EXTENSION;

typedef struct tdTPM_SESSION {
  TPM_AUTHHANDLE authHandle;
  TPM_NONCE nonceEven;
  TPM_NONCE nonceOdd;
  TPM_BOOL continueAuthSession;
  TPM_OSAP_EXTENSION *osap;
} TPM_SESSION;

typedef struct tdHEAP_DATA {
  UINT32 dataSize;
  BYTE *data;
} HEAP_DATA;

// Generate RESULT types
RESULT_GEN(TPM_PCRVALUE);
RESULT_GEN(HEAP_DATA);
RESULT_GEN(TPM_STORED_DATA12);

///////////////////////////////////////////////////////////////////////////
/*
 * For all TPM_* functions:
 * Except:
 * ERROR_TPM
 * ERROR_TPM_BAD_OUTPUT_PARAM
 * ERROR_TPM_BAD_OUTPUT_AUTH (only for authorized commands)
 */
RESULT TPM_Startup(TPM_STARTUP_TYPE startupType_in);
RESULT TPM_GetRandom(BYTE *randomBytes_out /* out */, UINT32 bytesRequested_in);
RESULT_(TPM_PCRVALUE) TPM_PCRRead(TPM_PCRINDEX pcrIndex_in);
RESULT_(TPM_PCRVALUE) TPM_Extend(TPM_PCRINDEX pcrNum_in, TPM_DIGEST inDigest_in);
/* Only populates the authHandle and nonceEven fields. nonceOdd and
 * and continueAuthSession must be populated by the caller. */
RESULT TPM_OIAP(TPM_SESSION **session);
RESULT TPM_OSAP(TPM_ENTITY_TYPE entityType_in, UINT32 entityValue_in,
                TPM_NONCE nonceOddOSAP, TPM_SESSION **session);
RESULT TPM_NV_WriteValueAuth(const BYTE *data_in, UINT32 dataSize_in,
                             TPM_NV_INDEX nvIndex_in, UINT32 offset_in,
                             TPM_AUTHDATA nv_auth, TPM_SESSION **session);
RESULT_(HEAP_DATA)
TPM_NV_ReadValue(TPM_NV_INDEX nvIndex_in, UINT32 offset_in, UINT32 dataSize_in,
                 OPTION(TPM_AUTHDATA) ownerAuth_in, TPM_SESSION **session);
RESULT_(HEAP_DATA)
TPM_Unseal(TPM_STORED_DATA12 inData_in /* in */, TPM_KEY_HANDLE parentHandle_in,
           TPM_AUTHDATA parentAuth, TPM_SESSION **parentSession,
           TPM_AUTHDATA dataAuth, TPM_SESSION **dataSession);
RESULT_(TPM_STORED_DATA12)
TPM_Seal(TPM_KEY_HANDLE keyHandle_in, TPM_ENCAUTH encAuth_in,
         TPM_PCR_INFO_LONG pcrInfo_in, const BYTE *inData_in,
         UINT32 inDataSize_in, TPM_SESSION **session, TPM_SECRET sharedSecret);

#endif
