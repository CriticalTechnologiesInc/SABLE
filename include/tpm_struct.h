#ifndef TPM_STRUCT_H
#define TPM_STRUCT_H

#include "tcg.h"

OPTION_GEN(TPM_PCR_SELECTION)

UINT32 pack_array(BYTE *buffer, const BYTE *data, UINT32 size);
UINT32 pack_TPM_PCR_SELECTION(BYTE *buffer, const TPM_PCR_SELECTION *select);
OPTION(TPM_PCR_SELECTION) unpack_TPM_PCR_SELECTION(BYTE *buffer);

#endif
