#ifndef TPM_COMMAND_H
#define TPM_COMMAND_H

#include "tcg.h"

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

/* TPM_GetRandom */

typedef struct {
  TPM_COMMAND_HEADER head;
  TPM_COMMAND_CODE ordinal;
  UINT32 bytesRequested;
} TPM_RQU_COMMAND_GETRANDOM;

#define TPM_RSP_COMMAND_GETRANDOM_GEN(Type)                                    \
  typedef struct {                                                             \
    TPM_COMMAND_HEADER head;                                                   \
    TPM_RESULT returnCode;                                                     \
    UINT32 randomBytesSize;                                                    \
    Type randomBytes;                                                          \
  } TPM_RSP_COMMAND_GETRANDOM_##Type

#define TPM_GETRANDOM_RET_GEN(Type)                                            \
  typedef struct {                                                             \
    TPM_RESULT returnCode;                                                     \
    Type random_##Type;                                                        \
  } TPM_GETRANDOM_RET_##Type

#endif
