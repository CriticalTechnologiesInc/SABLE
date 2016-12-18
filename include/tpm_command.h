#ifndef TPM_COMMAND_H
#define TPM_COMMAND_H

#include "tpm.h"

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
} TPM_COMMAND_HEADER;

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

typedef struct {
  TPM_RESULT returnCode;
  TPM_DIGEST outDigest;
} TPM_EXTEND_RET;

#endif
