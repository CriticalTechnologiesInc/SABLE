#ifndef TPM_COMMAND_H
#define TPM_COMMAND_H

#include "tcg.h"

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
} TPM_COMMAND_HEADER;

typedef struct {
  TPM_AUTHHANDLE authHandle;
  TPM_NONCE nonceEven;
  TPM_NONCE nonceOdd;
  TPM_BOOL continueAuthSession;
} TPM_SESSION;

typedef struct {
  TPM_SESSION session;
  TPM_NONCE nonceEvenOSAP;
  TPM_NONCE nonceOddOSAP;
} TPM_OSAP_SESSION;

typedef struct {
  TPM_RESULT returnCode;
  TPM_DIGEST outDigest;
} TPM_EXTEND_RET;

typedef struct {
  TPM_RESULT returnCode;
  TPM_PCRVALUE outDigest;
} TPM_PCRREAD_RET;

typedef struct {
  TPM_RESULT returnCode;
  TPM_SESSION session;
} TPM_OIAP_RET;

typedef struct {
  TPM_RESULT returnCode;
  TPM_STORED_DATA12 sealedData;
} TPM_SEAL_RET;

#endif
