#ifndef TPM_COMMAND_H
#define TPM_COMMAND_H

#include "tpm.h"

typedef struct tdTPM_COMMAND_HEADER {
  TPM_TAG tag;
  UINT32 paramSize;
} TPM_COMMAND_HEADER;

#endif
