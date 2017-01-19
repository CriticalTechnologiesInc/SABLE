#include "tpm_struct.h"
#include "util.h"
#include "hmac.h"

// FIXME add buffer overflow checks!

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

void pack_BYTE(BYTE val, bool hash) {
  if (hash)
    sha1_BYTE(val);
  BYTE *tmp = (BYTE *)(pack_ctx.pack_buffer + pack_ctx.bytes_packed);
  *tmp = val;
  pack_ctx.bytes_packed += sizeof(BYTE);
}
BYTE unpack_BYTE(bool hash) {
  BYTE ret;
  const BYTE *tmp =
      (const BYTE *)(unpack_ctx.unpack_buffer + unpack_ctx.bytes_unpacked);
  unpack_ctx.bytes_unpacked += sizeof(BYTE);
  ret = *tmp;
  if (hash)
    sha1_BYTE(ret);
  return ret;
}

void pack_UINT16(UINT16 val, bool hash) {
  UINT16 *tmp = (UINT16 *)(pack_ctx.pack_buffer + pack_ctx.bytes_packed);
  *tmp = htons(val);
  pack_ctx.bytes_packed += sizeof(UINT16);
}
UINT16 unpack_UINT16(bool hash) {
  const UINT16 *tmp =
      (const UINT16 *)(unpack_ctx.unpack_buffer + unpack_ctx.bytes_unpacked);
  unpack_ctx.bytes_unpacked += sizeof(UINT16);
  return ntohs(*tmp);
}

void pack_UINT32(UINT32 val, bool hash) {
  UINT32 *tmp = (UINT32 *)(pack_ctx.pack_buffer + pack_ctx.bytes_packed);
  *tmp = htonl(val);
  pack_ctx.bytes_packed += sizeof(UINT32);
}
UINT32 unpack_UINT32(bool hash) {
  const UINT32 *tmp =
      (const UINT32 *)(unpack_ctx.unpack_buffer + unpack_ctx.bytes_unpacked);
  unpack_ctx.bytes_unpacked += sizeof(UINT32);
  return ntohl(*tmp);
}

void pack_ptr(const void *data, UINT32 size, bool hash) {
  memcpy(pack_ctx.pack_buffer + pack_ctx.bytes_packed, data, size);
  pack_ctx.bytes_packed += size;
}
void *unpack_ptr(UINT32 size, bool hash) {
  void *tmp = (void *)(unpack_ctx.unpack_buffer + unpack_ctx.bytes_unpacked);
  unpack_ctx.bytes_unpacked += size;
  return tmp;
}

void pack_TPM_DIGEST(TPM_DIGEST val, bool hash) {
  TPM_DIGEST *tmp = (TPM_DIGEST *)(pack_ctx.pack_buffer + pack_ctx.bytes_packed);
  *tmp = val;
  pack_ctx.bytes_packed += sizeof(TPM_DIGEST);
}
TPM_DIGEST unpack_TPM_DIGEST(bool hash) {
  const TPM_DIGEST *tmp =
      (const TPM_DIGEST *)(unpack_ctx.unpack_buffer + unpack_ctx.bytes_unpacked);
  unpack_ctx.bytes_unpacked += sizeof(TPM_DIGEST);
  return *tmp;
}

void pack_TPM_PCR_SELECTION(TPM_PCR_SELECTION select, bool hash) {
  pack_UINT16(select.sizeOfSelect);
  pack_ptr(select.pcrSelect, (UINT32)select.sizeOfSelect);
}
TPM_PCR_SELECTION unpack_TPM_PCR_SELECTION(bool hash) {
  TPM_PCR_SELECTION ret;
  ret.sizeOfSelect = unpack_UINT16();
  ret.pcrSelect = unpack_ptr(ret.sizeOfSelect);
  return ret;
}

void pack_TPM_STORED_DATA12(TPM_STORED_DATA12 data, bool hash) {
  pack_UINT16(data.tag);
  pack_UINT16(data.et);
  pack_UINT32(data.sealInfoSize);
  pack_ptr(data.sealInfo, data.sealInfoSize);
  pack_UINT32(data.encDataSize);
  pack_ptr(data.encData, data.encDataSize);
}

TPM_STORED_DATA12 unpack_TPM_STORED_DATA12(bool hash) {
  TPM_STORED_DATA12 ret;
  ret.tag = unpack_UINT16();
  ret.et = unpack_UINT16();
  ret.sealInfoSize = unpack_UINT32();
  ret.sealInfo = unpack_ptr(ret.sealInfoSize);
  ret.encDataSize = unpack_UINT32();
  ret.encData = unpack_ptr(ret.encDataSize);
  return ret;
}
