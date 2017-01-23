#ifndef TPM_STRUCT_H
#define TPM_STRUCT_H

#include "sha.h"
#include "tcg.h"

/* APIs to marshal/unmarshal TPM data structures to/from a buffer */

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

void marshal_BYTE(BYTE val, Pack_Context *ctx, SHA1_Context *sctx);
void unmarshal_BYTE(BYTE *val /* in/out */, Unpack_Context *ctx, SHA1_Context *sctx);
void marshal_UINT16(UINT16 val, Pack_Context *ctx, SHA1_Context *sctx);
void unmarshal_UINT16(UINT16 *val /* in/out */, Unpack_Context *ctx,
                   SHA1_Context *sctx);
void marshal_UINT32(UINT32 val, Pack_Context *ctx, SHA1_Context *sctx);
void unmarshal_UINT32(UINT32 *val /* in/out */, Unpack_Context *ctx,
                   SHA1_Context *sctx);

void marshal_array(const void *data, UINT32 size, Pack_Context *ctx,
                SHA1_Context *sctx);
void unmarshal_array(void *data /* in/out */, UINT32 size, Unpack_Context *ctx,
                  SHA1_Context *sctx);
void unmarshal_ptr(void *ptr /* in/out */, UINT32 size, Unpack_Context *ctx,
                  SHA1_Context *sctx);
void marshal_TPM_PCR_SELECTION(const TPM_PCR_SELECTION *select, Pack_Context *ctx,
                            SHA1_Context *sctx);
void unmarshal_TPM_PCR_SELECTION(TPM_PCR_SELECTION *select /* in/out */,
                              Unpack_Context *ctx, SHA1_Context *sctx);
void marshal_TPM_PCR_INFO_LONG(const TPM_PCR_INFO_LONG *pcrInfo, Pack_Context *ctx,
                            SHA1_Context *sctx);
void unmarshal_TPM_PCR_INFO_LONG(TPM_PCR_INFO_LONG *pcrInfo /* in/out */,
                              Unpack_Context *ctx, SHA1_Context *sctx);
void marshal_TPM_STORED_DATA12(const TPM_STORED_DATA12 *data, Pack_Context *ctx,
                            SHA1_Context *sctx);
void unmarshal_TPM_STORED_DATA12(TPM_STORED_DATA12 *data /* in/out */,
                              Unpack_Context *ctx, SHA1_Context *sctx);

/* Helper functions to compute the size of TPM structs */

UINT32 sizeof_TPM_PCR_SELECTION(TPM_PCR_SELECTION select);
UINT32 sizeof_TPM_PCR_INFO_LONG(TPM_PCR_INFO_LONG pcrInfo);

/* APIs to generate specific TPM structs */

TPM_COMPOSITE_HASH get_TPM_COMPOSITE_HASH(TPM_PCR_COMPOSITE comp);
TPM_ENCAUTH encAuth_gen(const TPM_AUTHDATA *auth,
                        const TPM_SECRET *sharedSecret,
                        const TPM_NONCE *nonceEven);

#endif
