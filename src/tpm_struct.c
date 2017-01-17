#include "tpm_struct.h"
#include "util.h"

#define PACK_VALUE_GEN(Type)                                                   \
  static UINT32 pack_##Type(BYTE *buffer, Type val) {                   \
    Type *tmp = (Type *)buffer;                                                \
    *tmp = val;                                                                \
    return sizeof(Type);                                                       \
  }

PACK_VALUE_GEN(UINT16)

UINT32 pack_array(BYTE *buffer, const BYTE *data, UINT32 size) {
  memcpy(buffer, data, size);
  return size;
}

UINT32 pack_TPM_PCR_SELECTION(BYTE *buffer, const TPM_PCR_SELECTION *select) {
  UINT32 bytes_packed = 0;
  bytes_packed += pack_UINT16(buffer, select->sizeOfSelect);
  bytes_packed += pack_array(buffer, select->pcrSelect, (UINT32)select->sizeOfSelect);
  return bytes_packed;
}

OPTION(TPM_PCR_SELECTION) unpack_TPM_PCR_SELECTION(BYTE *buffer) {
  UINT32 bytes_unpacked = 0;

}
