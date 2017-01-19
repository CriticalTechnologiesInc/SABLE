#ifndef TPM_STRUCT_H
#define TPM_STRUCT_H

#include "tcg.h"

void pack_BYTE(BYTE val, bool hash);
BYTE unpack_BYTE(bool hash);
void pack_UINT16(UINT16 val, bool hash);
UINT16 unpack_UINT16(bool hash);
void pack_UINT32(UINT32 val, bool hash);
UINT32 unpack_UINT32(bool hash);

void pack_init(BYTE *buffer, UINT32 bufferSize);
void unpack_init(const BYTE *buffer, UINT32 bufferSize);
UINT32 pack_finish(void);
UINT32 unpack_finish(void);

void pack_ptr(const void *data, UINT32 size, bool hash);
void *unpack_ptr(UINT32 size, bool hash);
void pack_TPM_DIGEST(TPM_DIGEST val, bool hash);
TPM_DIGEST unpack_TPM_DIGEST(bool hash);
void pack_TPM_PCR_SELECTION(TPM_PCR_SELECTION select, bool hash);
TPM_PCR_SELECTION unpack_TPM_PCR_SELECTION(bool hash);
void pack_TPM_STORED_DATA12(TPM_STORED_DATA12 data, bool hash);
TPM_STORED_DATA12 unpack_TPM_STORED_DATA12(bool hash);

#endif
