#include "tpm_struct.h"
#include "hmac.h"
#include "util.h"

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

static void check_pack_overflow(Pack_Context *ctx, UINT32 sizeOfPack) {
  ERROR(-1, !(ctx->bytes_packed + sizeOfPack <= ctx->size),
        "Buffer overflow during pack");
}
static void check_unpack_overflow(Unpack_Context *ctx, UINT32 sizeOfUnpack) {
  ERROR(-1, !(ctx->bytes_unpacked + sizeOfUnpack <= ctx->size),
        "Unpacking beyond buffer's end");
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
  assert(val);
  assert(ctx || sctx);
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
  assert(val);
  assert(ctx || sctx);
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
  assert(val);
  assert(ctx || sctx);
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

void marshal_array(const void *data, UINT32 size, Pack_Context *ctx,
                SHA1_Context *sctx) {
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
  assert(data);
  assert(ctx || sctx);
  if (sctx && !ctx) {
    sha1(sctx, data, size);
    return;
  }
  void *tmp = (void *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  check_unpack_overflow(ctx, size);
  memcpy(data, tmp, size);
  ctx->bytes_unpacked += size;
  if (sctx) {
    sha1(sctx, data, size);
  }
}
void unmarshal_ptr(void *ptr, UINT32 size, Unpack_Context *ctx,
                  SHA1_Context *sctx) {
  assert(ptr);
  assert(ctx);
  void **tmp = (void **)ptr;
  *tmp = (void *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  check_unpack_overflow(ctx, size);
  ctx->bytes_unpacked += size;
  if (sctx) {
    sha1(sctx, *tmp, size);
  }
}

void marshal_TPM_PCR_SELECTION(const TPM_PCR_SELECTION *select, Pack_Context *ctx,
                            SHA1_Context *sctx) {
  marshal_UINT16(select->sizeOfSelect, ctx, sctx);
  marshal_array(select->pcrSelect, (UINT32)select->sizeOfSelect, ctx, sctx);
}
void unmarshal_TPM_PCR_SELECTION(TPM_PCR_SELECTION *select, Unpack_Context *ctx,
                              SHA1_Context *sctx) {
  unmarshal_UINT16(&select->sizeOfSelect, ctx, sctx);
  unmarshal_ptr(&select->pcrSelect, select->sizeOfSelect, ctx, sctx);
}

void marshal_TPM_PCR_INFO_LONG(const TPM_PCR_INFO_LONG *pcrInfo, Pack_Context *ctx,
                            SHA1_Context *sctx) {
  marshal_UINT16(pcrInfo->tag, ctx, sctx);
  marshal_BYTE(pcrInfo->localityAtCreation, ctx, sctx);
  marshal_BYTE(pcrInfo->localityAtRelease, ctx, sctx);
  marshal_TPM_PCR_SELECTION(&pcrInfo->creationPCRSelection, ctx, sctx);
  marshal_TPM_PCR_SELECTION(&pcrInfo->releasePCRSelection, ctx, sctx);
  marshal_array(pcrInfo->digestAtCreation.digest, sizeof(TPM_COMPOSITE_HASH), ctx,
             sctx);
  marshal_array(pcrInfo->digestAtRelease.digest, sizeof(TPM_COMPOSITE_HASH), ctx,
             sctx);
}
void unmarshal_TPM_PCR_INFO_LONG(TPM_PCR_INFO_LONG *pcrInfo, Unpack_Context *ctx,
                              SHA1_Context *sctx) {
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

UINT32 sizeof_TPM_PCR_SELECTION(TPM_PCR_SELECTION select) {
  UINT32 ret = 0;
  ret += sizeof(select.sizeOfSelect);
  ret += select.sizeOfSelect;
  return ret;
}

UINT32 sizeof_TPM_PCR_INFO_LONG(TPM_PCR_INFO_LONG pcrInfo) {
  UINT32 ret = 0;
  ret += sizeof(TPM_STRUCTURE_TAG);
  ret += 2 * sizeof(TPM_LOCALITY_SELECTION);
  ret += sizeof_TPM_PCR_SELECTION(pcrInfo.creationPCRSelection);
  ret += sizeof_TPM_PCR_SELECTION(pcrInfo.releasePCRSelection);
  ret += 2 * sizeof(TPM_COMPOSITE_HASH);
  return ret;
}

// ret = xor(authData, sha1(sharedSecret ++ nonceEven))
TPM_ENCAUTH encAuth_gen(const TPM_AUTHDATA *auth,
                        const TPM_SECRET *sharedSecret,
                        const TPM_NONCE *nonceEven) {
  TPM_ENCAUTH encAuth;
  SHA1_Context sctx;
  sha1_init(&sctx);
  sha1(&sctx, sharedSecret, sizeof(TPM_SECRET));
  sha1(&sctx, nonceEven->nonce, sizeof(TPM_NONCE));
  sha1_finish(&sctx);

  do_xor(auth->authdata, sctx.hash.digest, encAuth.authdata,
         sizeof(TPM_DIGEST));
  return encAuth;
}

TPM_COMPOSITE_HASH get_TPM_COMPOSITE_HASH(TPM_PCR_COMPOSITE comp) {
  SHA1_Context sctx;
  sha1_init(&sctx);
  sha1(&sctx, &comp.select.sizeOfSelect, sizeof(comp.select.sizeOfSelect));
  sha1(&sctx, comp.select.pcrSelect, comp.select.sizeOfSelect);
  sha1(&sctx, &comp.valueSize, sizeof(comp.valueSize));
  sha1(&sctx, comp.pcrValue, comp.valueSize);
  sha1_finish(&sctx);
  return sctx.hash;
}
