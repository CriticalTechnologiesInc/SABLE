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

void pack_BYTE(Pack_Context *ctx, BYTE val, SHA1_Context *sctx) {
  check_pack_overflow(ctx, sizeof(BYTE));
  if (sctx)
    sha1(sctx, &val, sizeof(BYTE));
  BYTE *tmp = (BYTE *)(ctx->pack_buffer + ctx->bytes_packed);
  *tmp = val;
  ctx->bytes_packed += sizeof(BYTE);
}
BYTE unpack_BYTE(Unpack_Context *ctx, SHA1_Context *sctx) {
  BYTE ret;
  check_unpack_overflow(ctx, sizeof(BYTE));
  const BYTE *tmp =
      (const BYTE *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  ret = *tmp;
  if (sctx)
    sha1(sctx, &ret, sizeof(BYTE));
  ctx->bytes_unpacked += sizeof(BYTE);
  return ret;
}

void pack_UINT16(Pack_Context *ctx, UINT16 val, SHA1_Context *sctx) {
  check_pack_overflow(ctx, sizeof(UINT16));
  val = htons(val);
  if (sctx)
    sha1(sctx, &val, sizeof(UINT16));
  UINT16 *tmp = (UINT16 *)(ctx->pack_buffer + ctx->bytes_packed);
  *tmp = val;
  ctx->bytes_packed += sizeof(UINT16);
}
UINT16 unpack_UINT16(Unpack_Context *ctx, SHA1_Context *sctx) {
  UINT16 ret;
  check_unpack_overflow(ctx, sizeof(UINT16));
  const UINT16 *tmp =
      (const UINT16 *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  ret = *tmp;
  if (sctx)
    sha1(sctx, &ret, sizeof(UINT16));
  ret = ntohs(ret);
  ctx->bytes_unpacked += sizeof(UINT16);
  return ret;
}

void pack_UINT32(Pack_Context *ctx, UINT32 val, SHA1_Context *sctx) {
  check_pack_overflow(ctx, sizeof(UINT32));
  val = htonl(val);
  if (sctx)
    sha1(sctx, &val, sizeof(UINT32));
  UINT32 *tmp = (UINT32 *)(ctx->pack_buffer + ctx->bytes_packed);
  *tmp = val;
  ctx->bytes_packed += sizeof(UINT32);
}
UINT32 unpack_UINT32(Unpack_Context *ctx, SHA1_Context *sctx) {
  UINT32 ret;
  check_unpack_overflow(ctx, sizeof(UINT32));
  const UINT32 *tmp =
      (const UINT32 *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  ret = *tmp;
  if (sctx)
    sha1(sctx, &ret, sizeof(UINT32));
  ret = ntohl(ret);
  ctx->bytes_unpacked += sizeof(UINT32);
  return ret;
}

void pack_array(Pack_Context *ctx, const void *data, UINT32 size, SHA1_Context *sctx) {
  check_pack_overflow(ctx, size);
  if (sctx)
    sha1(sctx, data, size);
  memcpy(ctx->pack_buffer + ctx->bytes_packed, data, size);
  ctx->bytes_packed += size;
}
void *unpack_array(Unpack_Context *ctx, UINT32 size, SHA1_Context *sctx) {
  void *ret;
  check_unpack_overflow(ctx, size);
  ret = (void *)(ctx->unpack_buffer + ctx->bytes_unpacked);
  if (sctx)
    sha1(sctx, ret, size);
  ctx->bytes_unpacked += size;
  return ret;
}

void pack_TPM_PCR_SELECTION(Pack_Context *ctx, TPM_PCR_SELECTION select, SHA1_Context *sctx) {
  pack_UINT16(ctx, select.sizeOfSelect, sctx);
  pack_array(ctx, select.pcrSelect, (UINT32)select.sizeOfSelect, sctx);
}
TPM_PCR_SELECTION unpack_TPM_PCR_SELECTION(Unpack_Context *ctx, SHA1_Context *sctx) {
  TPM_PCR_SELECTION ret;
  ret.sizeOfSelect = unpack_UINT16(ctx, sctx);
  ret.pcrSelect = unpack_array(ctx, ret.sizeOfSelect, sctx);
  return ret;
}

void pack_TPM_PCR_INFO_LONG(Pack_Context *ctx, TPM_PCR_INFO_LONG pcrInfo, SHA1_Context *sctx) {
  pack_UINT16(ctx, pcrInfo.tag, sctx);
  pack_BYTE(ctx, pcrInfo.localityAtCreation, sctx);
  pack_BYTE(ctx, pcrInfo.localityAtRelease, sctx);
  pack_TPM_PCR_SELECTION(ctx, pcrInfo.creationPCRSelection, sctx);
  pack_TPM_PCR_SELECTION(ctx, pcrInfo.releasePCRSelection, sctx);
  pack_array(ctx, pcrInfo.digestAtCreation.digest, sizeof(TPM_COMPOSITE_HASH), sctx);
  pack_array(ctx, pcrInfo.digestAtRelease.digest, sizeof(TPM_COMPOSITE_HASH), sctx);
}
TPM_PCR_INFO_LONG unpack_TPM_PCR_INFO_LONG(Unpack_Context *ctx, SHA1_Context *sctx) {
  TPM_PCR_INFO_LONG ret;
  ret.tag = unpack_UINT16(ctx, sctx);
  ret.localityAtCreation = unpack_BYTE(ctx, sctx);
  ret.localityAtRelease = unpack_BYTE(ctx, sctx);
  ret.creationPCRSelection = unpack_TPM_PCR_SELECTION(ctx, sctx);
  ret.releasePCRSelection = unpack_TPM_PCR_SELECTION(ctx, sctx);
  ret.digestAtCreation =
      *(TPM_COMPOSITE_HASH *)unpack_array(ctx, sizeof(TPM_COMPOSITE_HASH), sctx);
  ret.digestAtRelease =
      *(TPM_COMPOSITE_HASH *)unpack_array(ctx, sizeof(TPM_COMPOSITE_HASH), sctx);
  return ret;
}

void pack_TPM_STORED_DATA12(Pack_Context *ctx, TPM_STORED_DATA12 data, SHA1_Context *sctx) {
  pack_UINT16(ctx, data.tag, sctx);
  pack_UINT16(ctx, data.et, sctx);
  pack_UINT32(ctx, data.sealInfoSize, sctx);
  pack_array(ctx, data.sealInfo, data.sealInfoSize, sctx);
  pack_UINT32(ctx, data.encDataSize, sctx);
  pack_array(ctx, data.encData, data.encDataSize, sctx);
}
TPM_STORED_DATA12 unpack_TPM_STORED_DATA12(Unpack_Context *ctx, SHA1_Context *sctx) {
  TPM_STORED_DATA12 ret;
  ret.tag = unpack_UINT16(ctx, sctx);
  ret.et = unpack_UINT16(ctx, sctx);
  ret.sealInfoSize = unpack_UINT32(ctx, sctx);
  ret.sealInfo = unpack_array(ctx, ret.sealInfoSize, sctx);
  ret.encDataSize = unpack_UINT32(ctx, sctx);
  ret.encData = unpack_array(ctx, ret.encDataSize, sctx);
  return ret;
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

  do_xor(auth->authdata, sctx.hash.digest, encAuth.authdata, sizeof(TPM_DIGEST));
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
