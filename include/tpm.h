/*
 * \brief   macros, enums and headers for tpm.c
 * \date    2006-03-28
 * \author  Bernhard Kauer <kauer@tudos.org>
 */
/*
 * Copyright (C) 2006,2007,2010  Bernhard Kauer <kauer@tudos.org>
 * Technische Universitaet Dresden, Operating Systems Research Group
 *
 * This file is part of the OSLO package, which is distributed under
 * the  terms  of the  GNU General Public Licence 2.  Please see the
 * COPYING file for details.
 */

#pragma once

#ifndef __TPM_H__
#define __TPM_H__

#ifdef __midl
#define SIZEIS(x) [size_is(x)]
#else
#define SIZEIS(x)
#endif

#include "platform.h"
#include "tcg.h"
#include "tis.h"
#include "tpm_command.h"

#define TPM_TRANSMIT_FAIL 0xFFFF0000

#define TCG_HASH_SIZE 20
#define TCG_DATA_OFFSET 10
#define TCG_BUFFER_SIZE 1024
#define PCR_SELECT_SIZE 3

#define NORESET_PCR_ORD 15
#define SLB_PCR_ORD 17
#define MODULE_PCR_ORD 19

/**
 * Use AND to separate the items in a array construction.
 */
#define AND ,

/**
 * Defines a simple transmit function, which is used several times in
 * the lib, e.g. TPM_PcrRead
 */
#define TPM_TRANSMIT_FUNC(NAME, PARAMS, PRECOND, POSTCOND)                     \
  int TPM_##NAME PARAMS {                                                      \
    int ret;                                                                   \
    int size = 6;                                                              \
    PRECOND;                                                                   \
    buffer[0] = 0x00;                                                          \
    buffer[1] = 0xc1;                                                          \
    size += sizeof(send_buffer);                                               \
    *(unsigned long *)(buffer + 2) = ntohl(size);                              \
    assert(TCG_BUFFER_SIZE >= size);                                           \
    for (unsigned i = 0; i < sizeof(send_buffer) / sizeof(*send_buffer); i++)  \
      *((unsigned long *)(buffer + 6) + i) = ntohl(send_buffer[i]);            \
    ret = tis_transmit(buffer, size, buffer, TCG_BUFFER_SIZE);                 \
    if (ret < 0)                                                               \
      return ret;                                                              \
    POSTCOND;                                                                  \
    return ntohl(*(unsigned long *)(buffer + 6));                              \
  }

/**
 * Copy values from the buffer.
 */
#define TPM_COPY_FROM(DEST, OFFSET, SIZE)                                      \
  assert(TCG_BUFFER_SIZE >= TCG_DATA_OFFSET + OFFSET + SIZE)                   \
      memcpy(DEST, &in_buffer[TCG_DATA_OFFSET + OFFSET], SIZE)

/**
 * Extract long values from the buffer.
 */
#define TPM_EXTRACT_LONG(OFFSET)                                               \
  ntohl(*(unsigned long *)(buffer + TCG_DATA_OFFSET + OFFSET))

/**
 * Copy values to SHA1 buffer
 */
#define SHA_COPY_TO(SRC, SIZE)                                                 \
  assert(sha_size >= sha_offset + SIZE)                                        \
      memcpy(sha_buf + sha_offset, SRC, SIZE);                                 \
  sha_offset += SIZE

/**
 * Copy values to HMAC buffer
 */
#define HMAC_COPY_TO(SRC, SIZE)                                                \
  assert(hmac_size >= hmac_offset + SIZE)                                      \
      memcpy(hmac_buf + hmac_offset, SRC, SIZE);                               \
  hmac_offset += SIZE

/**
 * Copy values to the TPM-in buffer
 */
#define SABLE_TPM_COPY_TO(SRC, SIZE)                                           \
  assert(TCG_BUFFER_SIZE >= tpm_offset_out + SIZE)                             \
      memcpy(out_buffer + tpm_offset_out, SRC, SIZE);                          \
  tpm_offset_out += SIZE

/**
 * Copy values from the TPM-in buffer
 */
#define SABLE_TPM_COPY_FROM(SRC, SIZE)                                         \
  assert(TCG_BUFFER_SIZE >= tpm_offset_in + SIZE)                              \
      memcpy(in_buffer + tpm_offset_in, SRC, SIZE);                            \
  tpm_offset_in += SIZE

/**
 * Transmit command to the TPM
 */
#define TPM_TRANSMIT(FUNCTION_NAME)                                            \
  res = tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE)

/**
 * Copy values from the buffer.
 */
#define TPM_COPY_TO(DEST, OFFSET, SIZE)                                        \
  assert(TCG_BUFFER_SIZE >= TCG_DATA_OFFSET + OFFSET + SIZE)                   \
      memcpy(&buffer[TCG_DATA_OFFSET + OFFSET], DEST, SIZE)

//---------------------------------------------------
// Custom TPM command structures for SABLE
//---------------------------------------------------

// generic command header
typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
} TPM_COMMAND;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  TPM_STARTUP_TYPE startupType;
} stTPM_STARTUP;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  TPM_KEY_HANDLE parentHandle;
  // TPM_STORED_DATA inData; we can't include this in struct because
  // it's variable size, but remember it's here for command parsing
} stTPM_UNSEAL;

///////////////////////////////////////////////////////////////////////////
TPM_RESULT TPM_GetRandom(BYTE *randomBytes_out /* out */,
                         UINT32 bytesRequested_in);
TPM_RESULT TPM_PCRRead(TPM_PCRINDEX pcrIndex_in,
                       TPM_PCRVALUE *outDigest_out /* out */);
TPM_RESULT TPM_OIAP(TPM_SESSION *session /* out */);
TPM_RESULT TPM_OSAP(TPM_ENTITY_TYPE entityType_in, UINT32 entityValue_in,
                    TPM_OSAP_SESSION *osap_session /* out */);
TPM_RESULT TPM_NV_WriteValueAuth(const BYTE *data_in, UINT32 dataSize_in,
                                 TPM_NV_INDEX nvIndex_in, UINT32 offset_in,
                                 const TPM_AUTHDATA *nv_auth,
                                 TPM_SESSION *session);
TPM_RESULT TPM_NV_ReadValue(BYTE *data /* out */, UINT32 dataSize,
                            TPM_NV_INDEX nvIndex, UINT32 offset);
TPM_RESULT TPM_Startup_Clear(BYTE *buffer);
TPM_EXTEND_RET TPM_Extend(TPM_PCRINDEX pcr_index, TPM_DIGEST hash);
TPM_RESULT TPM_Unseal(BYTE *data /* in */, BYTE *secretData /* out */,
                      UINT32 secretDataSize, TPM_AUTHDATA parent_auth,
                      TPM_SESSION parent_session, TPM_AUTHDATA data_auth,
                      TPM_SESSION data_session);
TPM_RESULT TPM_Seal(TPM_STORED_DATA12 *sealed_data /* out */,
                    TPM_KEY_HANDLE keyHandle_in, TPM_ENCAUTH encAuth_in,
                    const void *pcrInfo_in, UINT32 pcrInfoSize_in,
                    const BYTE *inData_in, UINT32 inDataSize_in,
                    TPM_SESSION *session, const TPM_SECRET *sharedSecret);

#endif
