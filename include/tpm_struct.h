#ifndef TPM_STRUCT_H
#define TPM_STRUCT_H

#include "tcg.h"
#include "sha.h"

/* APIs to pack/unpack TPM data structures to/from a buffer */

typedef struct {
  BYTE *pack_buffer;
  UINT32 bytes_packed;
  UINT32 size;
} Pack_Context;

typedef struct {
  const BYTE *unpack_buffer;
  UINT32 bytes_unpacked;
  UINT32 size;
} Unpack_Context;

void pack_init(Pack_Context *ctx, BYTE *buffer, UINT32 bufferSize);
void unpack_init(Unpack_Context *ctx, const BYTE *buffer, UINT32 bufferSize);
UINT32 pack_finish(Pack_Context *ctx);
UINT32 unpack_finish(Unpack_Context *ctx);

void pack_BYTE(Pack_Context *ctx, BYTE val, SHA1_Context *sctx);
BYTE unpack_BYTE(Unpack_Context *ctx, SHA1_Context *sctx);
void pack_UINT16(Pack_Context *ctx, UINT16 val, SHA1_Context *sctx);
UINT16 unpack_UINT16(Unpack_Context *ctx, SHA1_Context *sctx);
void pack_UINT32(Pack_Context *ctx, UINT32 val, SHA1_Context *sctx);
UINT32 unpack_UINT32(Unpack_Context *ctx, SHA1_Context *sctx);

void pack_array(Pack_Context *ctx, const void *data, UINT32 size, SHA1_Context *sctx);
void *unpack_array(Unpack_Context *ctx, UINT32 size, SHA1_Context *sctx);
void pack_TPM_PCR_SELECTION(Pack_Context *ctx, TPM_PCR_SELECTION select, SHA1_Context *sctx);
TPM_PCR_SELECTION unpack_TPM_PCR_SELECTION(Unpack_Context *ctx, SHA1_Context *sctx);
void pack_TPM_PCR_INFO_LONG(Pack_Context *ctx, TPM_PCR_INFO_LONG pcrInfo, SHA1_Context *sctx);
TPM_PCR_INFO_LONG unpack_TPM_PCR_INFO_LONG(Unpack_Context *ctx, SHA1_Context *sctx);
void pack_TPM_STORED_DATA12(Pack_Context *ctx, TPM_STORED_DATA12 data, SHA1_Context *sctx);
TPM_STORED_DATA12 unpack_TPM_STORED_DATA12(Unpack_Context *ctx, SHA1_Context *sctx);

/* Helper functions to compute the size of TPM structs */

UINT32 sizeof_TPM_PCR_SELECTION(TPM_PCR_SELECTION select);
UINT32 sizeof_TPM_PCR_INFO_LONG(TPM_PCR_INFO_LONG pcrInfo);

/* APIs to generate specific TPM structs */

TPM_COMPOSITE_HASH get_TPM_COMPOSITE_HASH(TPM_PCR_COMPOSITE comp);
TPM_ENCAUTH encAuth_gen(const TPM_AUTHDATA *auth,
                        const TPM_SECRET *sharedSecret,
                        const TPM_NONCE *nonceEven);

#endif
