#ifndef TPM_STRUCT_H
#define TPM_STRUCT_H

#include "tcg.h"

/* APIs to pack/unpack TPM data structures to/from a buffer */

void pack_init(BYTE *buffer, UINT32 bufferSize);
void unpack_init(const BYTE *buffer, UINT32 bufferSize);
UINT32 pack_finish(void);
UINT32 unpack_finish(void);

void pack_BYTE(BYTE val, bool hash);
BYTE unpack_BYTE(bool hash);
void pack_UINT16(UINT16 val, bool hash);
UINT16 unpack_UINT16(bool hash);
void pack_UINT32(UINT32 val, bool hash);
UINT32 unpack_UINT32(bool hash);

void pack_ptr(const void *data, UINT32 size, bool hash);
void *unpack_ptr(UINT32 size, bool hash);
void pack_TPM_PCR_SELECTION(TPM_PCR_SELECTION select, bool hash);
TPM_PCR_SELECTION unpack_TPM_PCR_SELECTION(bool hash);
void pack_TPM_PCR_INFO_LONG(TPM_PCR_INFO_LONG pcrInfo, bool hash);
TPM_PCR_INFO_LONG unpack_TPM_PCR_INFO_LONG(bool hash);
void pack_TPM_STORED_DATA12(TPM_STORED_DATA12 data, bool hash);
TPM_STORED_DATA12 unpack_TPM_STORED_DATA12(bool hash);

/* Helper functions to compute the size of TPM structs */

UINT32 sizeof_TPM_PCR_SELECTION(TPM_PCR_SELECTION select);
UINT32 sizeof_TPM_PCR_INFO_LONG(TPM_PCR_INFO_LONG pcrInfo);

/* APIs to generate specific TPM structs */

TPM_COMPOSITE_HASH get_TPM_COMPOSITE_HASH(TPM_PCR_COMPOSITE comp);
TPM_ENCAUTH encAuth_gen(const TPM_AUTHDATA *auth,
                        const TPM_SECRET *sharedSecret,
                        const TPM_NONCE *nonceEven);

#endif
