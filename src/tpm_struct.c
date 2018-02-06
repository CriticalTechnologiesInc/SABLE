#ifndef ISABELLE
#include "asm.h"
#include "alloc.h"
#include "heap.h"
#include "hmac.h"
#include "util.h"
#include "tpm_struct.h"

void pack_init(Pack_Context *ctx, BYTE *buffer, UINT32 bufferSize) {
  ctx->pack_buffer = buffer;
  ctx->bytes_packed = 0;
  ctx->size = bufferSize;
}
void unpack_init(Unpack_Context *ctx, const BYTE *buffer, UINT32 bufferSize) {
  ctx->unpack_buffer = buffer;
  ctx->bytes_unpacked = 0;
  ctx->size = bufferSize;
}

UINT32 pack_finish(Pack_Context *ctx) { return ctx->bytes_packed; }
UINT32 unpack_finish(Unpack_Context *ctx) { return ctx->bytes_unpacked; }

static RESULT check_pack_overflow(Pack_Context *ctx, UINT32 sizeOfPack) {
  RESULT ret = {.exception.error = NONE};
  if (!(ctx->bytes_packed + sizeOfPack <= ctx->size))
    exit(-1); // FIXME: should throw an error
  /*ERROR(!(ctx->bytes_packed + sizeOfPack <= ctx->size), ERROR_BUFFER_OVERFLOW,
        "Buffer overflow during pack");*/
  return ret;
}
static RESULT check_unpack_overflow(Unpack_Context *ctx, UINT32 sizeOfUnpack) {
  RESULT ret = {.exception.error = NONE};
  if (!(ctx->bytes_unpacked + sizeOfUnpack <= ctx->size))
    exit(-1); // FIXME: should throw an error
              /*ERROR(!(ctx->bytes_unpacked + sizeOfUnpack <= ctx->size),
                 ERROR_BUFFER_OVERFLOW,
                    "Unpacking beyond buffer's end");*/
  return ret;
}

/*
 * Steps for packing a primitive value (BYTE, UINT16, UINT32, *):
 * 1) Check for overflow
 * 2) If the value needs to be converted to network format, do that
 * 3) Optionally hash the value to be written
 * 4) Pack the value by writing it to pack_buffer
 * 5) Increment bytes_packed by the size of the written type
 *
 * Steps for unpacking:
 * 1) Check for overflow
 * 2) Unpack the value by copying it into a local variable (unless it is
 *    an array, in which case we just return a pointer to that array)
 * 3) Optionally hash the unpacked value, or pointed-to array
 * 4) If the value unpacked needs to be converted to host format, do that
 * 5) Increment bytes_unpacked by the size of the written type
 * 6) return the unpacked value
 */

void marshal_BYTE(BYTE val, Pack_Context *ctx, SHA1_Context *sctx) {
  if (sctx) {
    sha1(sctx, &val, sizeof(BYTE));
  }
  if (ctx) {
    check_pack_overflow(ctx, sizeof(BYTE));
    BYTE *tmp = (BYTE *)(ctx->pack_buffer + ctx->bytes_packed);
    *tmp = val;
    ctx->bytes_packed += sizeof(BYTE);
  }
}
void unmarshal_BYTE(BYTE *val, Unpack_Context *ctx, SHA1_Context *sctx) {
  ASSERT(val);
  ASSERT(ctx || sctx);
  if (sctx && !ctx) {
    sha1(sctx, val, sizeof(BYTE));
    return;
  }
  const BYTE *tmp = (const BYTE *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  check_unpack_overflow(ctx, sizeof(BYTE));
  *val = *tmp;
  ctx->bytes_unpacked += sizeof(BYTE);
  if (sctx) {
    sha1(sctx, tmp, sizeof(BYTE));
  }
}

void marshal_UINT16(UINT16 val, Pack_Context *ctx, SHA1_Context *sctx) {
  val = htons(val);
  if (sctx) {
    sha1(sctx, &val, sizeof(UINT16));
  }
  if (ctx) {
    check_pack_overflow(ctx, sizeof(UINT16));
    UINT16 *tmp = (UINT16 *)(ctx->pack_buffer + ctx->bytes_packed);
    *tmp = val;
    ctx->bytes_packed += sizeof(UINT16);
  }
}
void unmarshal_UINT16(UINT16 *val, Unpack_Context *ctx, SHA1_Context *sctx) {
  ASSERT(val);
  ASSERT(ctx || sctx);
  if (sctx && !ctx) {
    UINT16 tmp = htonl(*val);
    sha1(sctx, &tmp, sizeof(UINT16));
    return;
  }
  const UINT16 *tmp =
      (const UINT16 *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  check_unpack_overflow(ctx, sizeof(UINT16));
  *val = ntohs(*tmp);
  ctx->bytes_unpacked += sizeof(UINT16);
  if (sctx) {
    sha1(sctx, tmp, sizeof(UINT16));
  }
}

void marshal_UINT32(UINT32 val, Pack_Context *ctx, SHA1_Context *sctx) {
  val = htonl(val);
  if (sctx) {
    sha1(sctx, &val, sizeof(UINT32));
  }
  if (ctx) {
    check_pack_overflow(ctx, sizeof(UINT32));
    UINT32 *tmp = (UINT32 *)(ctx->pack_buffer + ctx->bytes_packed);
    *tmp = val;
    ctx->bytes_packed += sizeof(UINT32);
  }
}
void unmarshal_UINT32(UINT32 *val, Unpack_Context *ctx, SHA1_Context *sctx) {
  ASSERT(val);
  ASSERT(ctx || sctx);
  if (sctx && !ctx) {
    UINT32 tmp = htonl(*val);
    sha1(sctx, &tmp, sizeof(UINT32));
    return;
  }
  const UINT32 *tmp =
      (const UINT32 *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  check_unpack_overflow(ctx, sizeof(UINT32));
  *val = ntohl(*tmp);
  ctx->bytes_unpacked += sizeof(UINT32);
  if (sctx) {
    sha1(sctx, tmp, sizeof(UINT32));
  }
}

void marshal_TPM_SECRET(TPM_SECRET val, Pack_Context *ctx, SHA1_Context *sctx) {
  if (sctx) {
    sha1(sctx, &val, sizeof(TPM_SECRET));
  }
  if (ctx) {
    check_pack_overflow(ctx, sizeof(TPM_SECRET));
    memcpy(ctx->pack_buffer + ctx->bytes_packed, &val, sizeof(TPM_SECRET));
    ctx->bytes_packed += sizeof(TPM_SECRET);
  }
}

void marshal_array(const void *data, UINT32 size, Pack_Context *ctx,
                   SHA1_Context *sctx) {
  ASSERT(data);
  if (sctx) {
    sha1(sctx, data, size);
  }
  if (ctx) {
    check_pack_overflow(ctx, size);
    memcpy(ctx->pack_buffer + ctx->bytes_packed, data, size);
    ctx->bytes_packed += size;
  }
}
void unmarshal_array(void *data, UINT32 size, Unpack_Context *ctx,
                     SHA1_Context *sctx) {
  ASSERT(ctx || sctx);
  if (sctx && !ctx) {
    sha1(sctx, data, size);
    return;
  }
  void *tmp = (void *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  check_unpack_overflow(ctx, size);
  if (data) {
    memcpy(data, tmp, size);
  }
  ctx->bytes_unpacked += size;
  if (sctx) {
    sha1(sctx, data, size);
  }
}
void unmarshal_ptr(void *ptr, UINT32 size, Unpack_Context *ctx,
                   SHA1_Context *sctx) {
  ASSERT(ptr);
  ASSERT(ctx);
  void **tmp = (void **)ptr;
  check_unpack_overflow(ctx, size);
  *tmp = alloc(heap, size);
  ASSERT(*tmp);
  memcpy(*tmp, ctx->unpack_buffer + ctx->bytes_unpacked, size);
  ctx->bytes_unpacked += size;
  if (sctx) {
    sha1(sctx, *tmp, size);
  }
}

void marshal_TPM_PCR_SELECTION(const TPM_PCR_SELECTION *select,
                               Pack_Context *ctx, SHA1_Context *sctx) {
  marshal_UINT16(select->sizeOfSelect, ctx, sctx);
  marshal_array(select->pcrSelect, (UINT32)select->sizeOfSelect, ctx, sctx);
}
void unmarshal_TPM_PCR_SELECTION(TPM_PCR_SELECTION *select, Unpack_Context *ctx,
                                 SHA1_Context *sctx) {
  unmarshal_UINT16(&select->sizeOfSelect, ctx, sctx);
  unmarshal_ptr(&select->pcrSelect, select->sizeOfSelect, ctx, sctx);
}

void marshal_TPM_PCR_INFO_LONG(const TPM_PCR_INFO_LONG *pcrInfo,
                               Pack_Context *ctx, SHA1_Context *sctx) {
  marshal_UINT16(pcrInfo->tag, ctx, sctx);
  marshal_BYTE(pcrInfo->localityAtCreation, ctx, sctx);
  marshal_BYTE(pcrInfo->localityAtRelease, ctx, sctx);
  marshal_TPM_PCR_SELECTION(&pcrInfo->creationPCRSelection, ctx, sctx);
  marshal_TPM_PCR_SELECTION(&pcrInfo->releasePCRSelection, ctx, sctx);
  marshal_array(pcrInfo->digestAtCreation.digest, sizeof(TPM_COMPOSITE_HASH),
                ctx, sctx);
  marshal_array(pcrInfo->digestAtRelease.digest, sizeof(TPM_COMPOSITE_HASH),
                ctx, sctx);
}
void unmarshal_TPM_PCR_INFO_LONG(TPM_PCR_INFO_LONG *pcrInfo,
                                 Unpack_Context *ctx, SHA1_Context *sctx) {
  unmarshal_UINT16(&pcrInfo->tag, ctx, sctx);
  unmarshal_BYTE(&pcrInfo->localityAtCreation, ctx, sctx);
  unmarshal_BYTE(&pcrInfo->localityAtRelease, ctx, sctx);
  unmarshal_TPM_PCR_SELECTION(&pcrInfo->creationPCRSelection, ctx, sctx);
  unmarshal_TPM_PCR_SELECTION(&pcrInfo->releasePCRSelection, ctx, sctx);
  unmarshal_array(&pcrInfo->digestAtCreation.digest, sizeof(TPM_COMPOSITE_HASH),
                  ctx, sctx);
  unmarshal_array(&pcrInfo->digestAtRelease.digest, sizeof(TPM_COMPOSITE_HASH),
                  ctx, sctx);
}

void marshal_TPM_STORED_DATA12(const TPM_STORED_DATA12 *data, Pack_Context *ctx,
                               SHA1_Context *sctx) {
  marshal_UINT16(data->tag, ctx, sctx);
  marshal_UINT16(data->et, ctx, sctx);
  marshal_UINT32(data->sealInfoSize, ctx, sctx);
  marshal_array(data->sealInfo, data->sealInfoSize, ctx, sctx);
  marshal_UINT32(data->encDataSize, ctx, sctx);
  marshal_array(data->encData, data->encDataSize, ctx, sctx);
}
void unmarshal_TPM_STORED_DATA12(TPM_STORED_DATA12 *data, Unpack_Context *ctx,
                                 SHA1_Context *sctx) {
  unmarshal_UINT16(&data->tag, ctx, sctx);
  unmarshal_UINT16(&data->et, ctx, sctx);
  unmarshal_UINT32(&data->sealInfoSize, ctx, sctx);
  unmarshal_ptr(&data->sealInfo, data->sealInfoSize, ctx, sctx);
  unmarshal_UINT32(&data->encDataSize, ctx, sctx);
  unmarshal_ptr(&data->encData, data->encDataSize, ctx, sctx);
}

UINT32 sizeof_TPM_PCR_SELECTION(const TPM_PCR_SELECTION *select) {
  UINT32 ret = 0;
  ret += sizeof(select->sizeOfSelect);
  ret += select->sizeOfSelect;
  return ret;
}

UINT32 sizeof_TPM_PCR_INFO_LONG(const TPM_PCR_INFO_LONG *pcrInfo) {
  UINT32 ret = 0;
  ret += sizeof(TPM_STRUCTURE_TAG);
  ret += 2 * sizeof(TPM_LOCALITY_SELECTION);
  ret += sizeof_TPM_PCR_SELECTION(&pcrInfo->creationPCRSelection);
  ret += sizeof_TPM_PCR_SELECTION(&pcrInfo->releasePCRSelection);
  ret += 2 * sizeof(TPM_COMPOSITE_HASH);
  return ret;
}

UINT32 sizeof_TPM_STORED_DATA12(const TPM_STORED_DATA12 *storedData) {
  UINT32 ret = 0;
  ret += sizeof(TPM_STRUCTURE_TAG);
  ret += sizeof(TPM_ENTITY_TYPE);
  ret += sizeof(UINT32);
  ret += storedData->sealInfoSize;
  ret += sizeof(UINT32);
  ret += storedData->encDataSize;
  return ret;
}

// ret = xor(entityAuthData, sha1(sharedSecret ++ authLastNonceEven))
TPM_ENCAUTH encAuth_gen(TPM_AUTHDATA entityAuthData, TPM_SECRET sharedSecret,
                        TPM_NONCE authLastNonceEven) {
  TPM_ENCAUTH encAuth;
  SHA1_Context sctx;
  sha1_init(&sctx);
  sha1(&sctx, &sharedSecret, sizeof(TPM_SECRET));
  sha1(&sctx, &authLastNonceEven, sizeof(TPM_NONCE));
  sha1_finish(&sctx);
  do_xor(entityAuthData.authdata, sctx.hash.digest, encAuth.authdata,
         sizeof(TPM_AUTHDATA));
  return encAuth;
}

TPM_SECRET sharedSecret_gen(TPM_AUTHDATA auth, TPM_NONCE nonceEvenOSAP,
                            TPM_NONCE nonceOddOSAP) {
  HMAC_Context hctx;
  hmac_init(&hctx, auth.authdata, sizeof(TPM_AUTHDATA));
  hmac(&hctx, &nonceEvenOSAP, sizeof(TPM_NONCE));
  hmac(&hctx, &nonceOddOSAP, sizeof(TPM_NONCE));
  hmac_finish(&hctx);
  return *(TPM_SECRET *)&hctx.sctx.hash;
}

TPM_COMPOSITE_HASH get_TPM_COMPOSITE_HASH(TPM_PCR_COMPOSITE comp) {
  SHA1_Context sctx;
  sha1_init(&sctx);
  marshal_TPM_PCR_SELECTION(&comp.select, NULL, &sctx);
  marshal_UINT32(comp.valueSize, NULL, &sctx);
  marshal_array(comp.pcrValue, comp.valueSize, NULL, &sctx);
  sha1_finish(&sctx);
  return sctx.hash;
}

UINT32 pack_TPM_PCR_INFO_LONG(BYTE *data /* out */, UINT32 dataSize,
                              const TPM_PCR_INFO_LONG *pcrInfo /* in */) {
  Pack_Context pctx;
  pack_init(&pctx, data, dataSize);
  marshal_TPM_PCR_INFO_LONG(pcrInfo, &pctx, NULL);
  return pack_finish(&pctx);
}

UINT32 pack_TPM_STORED_DATA12(BYTE *data /* out */, UINT32 dataSize,
                              const TPM_STORED_DATA12 *storedData) {
  Pack_Context pctx;
  pack_init(&pctx, data, dataSize);
  marshal_TPM_STORED_DATA12(storedData, &pctx, NULL);
  return pack_finish(&pctx);
}

TPM_STORED_DATA12 unpack_TPM_STORED_DATA12(const BYTE *data /* in */,
                                           UINT32 dataSize) {
  TPM_STORED_DATA12 ret;
  Unpack_Context uctx;
  unpack_init(&uctx, data, dataSize);
  unmarshal_TPM_STORED_DATA12(&ret, &uctx, NULL);
  unpack_finish(&uctx);
  return ret;
}

struct extracted_TPM_STORED_DATA12
extract_TPM_STORED_DATA12(TPM_STORED_DATA12 storedData) {
  UINT32 size = sizeof_TPM_STORED_DATA12(&storedData);
  struct extracted_TPM_STORED_DATA12 ret = {.dataSize = size,
                                            .data = alloc(heap, size)};
  pack_TPM_STORED_DATA12(ret.data, ret.dataSize, &storedData);
  return ret;
}
#endif
