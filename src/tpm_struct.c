#include "tpm_struct.h"
#include "hmac.h"
#include "util.h"

static struct {
  BYTE *pack_buffer;
  UINT32 bytes_packed;
  UINT32 size;
} pack_ctx;
static struct {
  const BYTE *unpack_buffer;
  UINT32 bytes_unpacked;
  UINT32 size;
} unpack_ctx;

void pack_init(BYTE *buffer, UINT32 bufferSize) {
  pack_ctx.pack_buffer = buffer;
  pack_ctx.bytes_packed = 0;
  pack_ctx.size = bufferSize;
}
void unpack_init(const BYTE *buffer, UINT32 bufferSize) {
  unpack_ctx.unpack_buffer = buffer;
  unpack_ctx.bytes_unpacked = 0;
  unpack_ctx.size = bufferSize;
}

UINT32 pack_finish(void) { return pack_ctx.bytes_packed; }
UINT32 unpack_finish(void) { return unpack_ctx.bytes_unpacked; }

static void check_pack_overflow(UINT32 sizeOfPack) {
  ERROR(-1, !(pack_ctx.bytes_packed + sizeOfPack <= pack_ctx.size),
        "Buffer overflow during pack");
}
static void check_unpack_overflow(UINT32 sizeOfUnpack) {
  ERROR(-1, !(unpack_ctx.bytes_unpacked + sizeOfUnpack <= unpack_ctx.size),
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

void pack_BYTE(BYTE val, bool hash) {
  check_pack_overflow(sizeof(BYTE));
  if (hash)
    sha1(&val, sizeof(BYTE));
  BYTE *tmp = (BYTE *)(pack_ctx.pack_buffer + pack_ctx.bytes_packed);
  *tmp = val;
  pack_ctx.bytes_packed += sizeof(BYTE);
}
BYTE unpack_BYTE(bool hash) {
  BYTE ret;
  check_unpack_overflow(sizeof(BYTE));
  const BYTE *tmp =
      (const BYTE *)(unpack_ctx.unpack_buffer + unpack_ctx.bytes_unpacked);
  ret = *tmp;
  if (hash)
    sha1(&ret, sizeof(BYTE));
  unpack_ctx.bytes_unpacked += sizeof(BYTE);
  return ret;
}

void pack_UINT16(UINT16 val, bool hash) {
  check_pack_overflow(sizeof(UINT16));
  val = htons(val);
  if (hash)
    sha1(&val, sizeof(UINT16));
  UINT16 *tmp = (UINT16 *)(pack_ctx.pack_buffer + pack_ctx.bytes_packed);
  *tmp = val;
  pack_ctx.bytes_packed += sizeof(UINT16);
}
UINT16 unpack_UINT16(bool hash) {
  UINT16 ret;
  check_unpack_overflow(sizeof(UINT16));
  const UINT16 *tmp =
      (const UINT16 *)(unpack_ctx.unpack_buffer + unpack_ctx.bytes_unpacked);
  ret = *tmp;
  if (hash)
    sha1(&ret, sizeof(UINT16));
  ret = ntohs(ret);
  unpack_ctx.bytes_unpacked += sizeof(UINT16);
  return ret;
}

void pack_UINT32(UINT32 val, bool hash) {
  check_pack_overflow(sizeof(UINT32));
  val = htonl(val);
  if (hash)
    sha1(&val, sizeof(UINT32));
  UINT32 *tmp = (UINT32 *)(pack_ctx.pack_buffer + pack_ctx.bytes_packed);
  *tmp = val;
  pack_ctx.bytes_packed += sizeof(UINT32);
}
UINT32 unpack_UINT32(bool hash) {
  UINT32 ret;
  check_unpack_overflow(sizeof(UINT32));
  const UINT32 *tmp =
      (const UINT32 *)(unpack_ctx.unpack_buffer + unpack_ctx.bytes_unpacked);
  ret = *tmp;
  if (hash)
    sha1(&ret, sizeof(UINT32));
  ret = ntohl(ret);
  unpack_ctx.bytes_unpacked += sizeof(UINT32);
  return ret;
}

void pack_ptr(const void *data, UINT32 size, bool hash) {
  check_pack_overflow(size);
  if (hash)
    sha1(data, size);
  memcpy(pack_ctx.pack_buffer + pack_ctx.bytes_packed, data, size);
  pack_ctx.bytes_packed += size;
}
void *unpack_ptr(UINT32 size, bool hash) {
  void *ret;
  check_unpack_overflow(size);
  ret = (void *)(unpack_ctx.unpack_buffer + unpack_ctx.bytes_unpacked);
  if (hash)
    sha1(ret, size);
  unpack_ctx.bytes_unpacked += size;
  return ret;
}

void pack_TPM_PCR_SELECTION(TPM_PCR_SELECTION select, bool hash) {
  pack_UINT16(select.sizeOfSelect, hash);
  pack_ptr(select.pcrSelect, (UINT32)select.sizeOfSelect, hash);
}
TPM_PCR_SELECTION unpack_TPM_PCR_SELECTION(bool hash) {
  TPM_PCR_SELECTION ret;
  ret.sizeOfSelect = unpack_UINT16(hash);
  ret.pcrSelect = unpack_ptr(ret.sizeOfSelect, hash);
  return ret;
}

void pack_TPM_PCR_INFO_LONG(TPM_PCR_INFO_LONG pcrInfo, bool hash) {
  pack_UINT16(pcrInfo.tag, hash);
  pack_BYTE(pcrInfo.localityAtCreation, hash);
  pack_BYTE(pcrInfo.localityAtRelease, hash);
  pack_TPM_PCR_SELECTION(pcrInfo.creationPCRSelection, hash);
  pack_TPM_PCR_SELECTION(pcrInfo.releasePCRSelection, hash);
  pack_ptr(pcrInfo.digestAtCreation.digest, sizeof(TPM_COMPOSITE_HASH), hash);
  pack_ptr(pcrInfo.digestAtRelease.digest, sizeof(TPM_COMPOSITE_HASH), hash);
}
TPM_PCR_INFO_LONG unpack_TPM_PCR_INFO_LONG(bool hash) {
  TPM_PCR_INFO_LONG ret;
  ret.tag = unpack_UINT16(hash);
  ret.localityAtCreation = unpack_BYTE(hash);
  ret.localityAtRelease = unpack_BYTE(hash);
  ret.creationPCRSelection = unpack_TPM_PCR_SELECTION(hash);
  ret.releasePCRSelection = unpack_TPM_PCR_SELECTION(hash);
  ret.digestAtCreation =
      *(TPM_COMPOSITE_HASH *)unpack_ptr(sizeof(TPM_COMPOSITE_HASH), hash);
  ret.digestAtRelease =
      *(TPM_COMPOSITE_HASH *)unpack_ptr(sizeof(TPM_COMPOSITE_HASH), hash);
  return ret;
}

void pack_TPM_STORED_DATA12(TPM_STORED_DATA12 data, bool hash) {
  pack_UINT16(data.tag, hash);
  pack_UINT16(data.et, hash);
  pack_UINT32(data.sealInfoSize, hash);
  pack_ptr(data.sealInfo, data.sealInfoSize, hash);
  pack_UINT32(data.encDataSize, hash);
  pack_ptr(data.encData, data.encDataSize, hash);
}
TPM_STORED_DATA12 unpack_TPM_STORED_DATA12(bool hash) {
  TPM_STORED_DATA12 ret;
  ret.tag = unpack_UINT16(hash);
  ret.et = unpack_UINT16(hash);
  ret.sealInfoSize = unpack_UINT32(hash);
  ret.sealInfo = unpack_ptr(ret.sealInfoSize, hash);
  ret.encDataSize = unpack_UINT32(hash);
  ret.encData = unpack_ptr(ret.encDataSize, hash);
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
  sha1_init();
  sha1(sharedSecret, sizeof(TPM_SECRET));
  sha1(nonceEven->nonce, sizeof(TPM_NONCE));
  TPM_DIGEST hash = sha1_finish();

  do_xor(auth->authdata, hash.digest, encAuth.authdata, sizeof(TPM_DIGEST));
  return encAuth;
}

TPM_COMPOSITE_HASH get_TPM_COMPOSITE_HASH(TPM_PCR_COMPOSITE comp) {
  sha1_init();
  sha1(&comp.select.sizeOfSelect, sizeof(comp.select.sizeOfSelect));
  sha1(comp.select.pcrSelect, comp.select.sizeOfSelect);
  sha1(&comp.valueSize, sizeof(comp.valueSize));
  sha1(comp.pcrValue, comp.valueSize);
  return sha1_finish();
}
