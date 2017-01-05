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

#ifndef __SABLE_TPM_H__
#define __SABLE_TPM_H__

#ifdef __midl
#define SIZEIS(x) [size_is(x)]
#else
#define SIZEIS(x)
#endif

#include "platform.h"
#include "tis.h"
#include "tcg.h"
#include "tpm_command.h"

#define TPM_TRANSMIT_FAIL 0xFFFF0000

#define TCG_HASH_SIZE 20
#define TCG_DATA_OFFSET 10
#define TCG_BUFFER_SIZE 1024
#define PCR_SELECT_SIZE 3

#define NORESET_PCR_ORD 15
#define SLB_PCR_ORD 17
#define MODULE_PCR_ORD 19

#define NV_DATA_OFFSET 0x00010000
#define NV_DATA_SIZE 500

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
// Custom TPM data structures for SABLE
//---------------------------------------------------

enum tpm_subcaps_size {
  TPM_NO_SUBCAP = 0,
  TPM_SUBCAP = 4,
};

typedef struct {
  UINT16 sizeOfSelect;
  BYTE pcrSelect[PCR_SELECT_SIZE];
} sdTPM_PCR_SELECTION;

typedef struct {
  TPM_AUTHHANDLE authHandle;
  BYTE sharedSecret[20];
  TPM_NONCE nonceEven;
  TPM_NONCE nonceOdd;
  TPM_AUTHDATA pubAuth;
} SessionCtx;

typedef struct {
  TPM_AUTHHANDLE authHandle;
  TPM_NONCE nonceOdd;
  TPM_BOOL continueAuthSession;
  TPM_AUTHDATA pubAuth;
} SessionEnd;

typedef struct {
  TPM_STRUCTURE_TAG tag;
  TPM_LOCALITY_SELECTION localityAtCreation;
  TPM_LOCALITY_SELECTION localityAtRelease;
  sdTPM_PCR_SELECTION creationPCRSelection;
  sdTPM_PCR_SELECTION releasePCRSelection;
  TPM_COMPOSITE_HASH digestAtCreation;
  TPM_COMPOSITE_HASH digestAtRelease;
} sdTPM_PCR_INFO_LONG;

typedef struct {
  sdTPM_PCR_SELECTION pcrSelection;
  TPM_LOCALITY_SELECTION localityAtRelease;
  TPM_COMPOSITE_HASH digestAtRelease;
} sdTPM_PCR_INFO_SHORT;

typedef struct {
  sdTPM_PCR_SELECTION select;
  UINT32 valueSize;
  // only supports 2 PCR values
  TPM_COMPOSITE_HASH hash1;
  TPM_COMPOSITE_HASH hash2;
} sdTPM_PCR_COMPOSITE;

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
  TPM_HANDLE handle;
  TPM_RESOURCE_TYPE resourceType;
} stTPM_FLUSH_SPECIFIC;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  UINT32 bytesRequested;
} stTPM_GETRANDOM;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  TPM_PCRINDEX pcrIndex;
} stTPM_PCRREAD;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  TPM_ENTITY_TYPE entityType;
  UINT32 entityValue;
  TPM_NONCE nonceOddOSAP;
} TPM_OSAP;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  TPM_KEY_HANDLE keyHandle;
  TPM_ENCAUTH encAuth;
  UINT32 pcrInfoSize;
  sdTPM_PCR_INFO_LONG pcrInfo;
  UINT32 inDataSize;
} stTPM_SEAL;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  TPM_KEY_HANDLE parentHandle;
  // TPM_STORED_DATA inData; we can't include this in struct because
  // it's variable size, but remember it's here for command parsing
} stTPM_UNSEAL;

typedef struct {
  TPM_STRUCTURE_TAG tag;
  TPM_NV_INDEX nvIndex;
  sdTPM_PCR_INFO_SHORT pcrInfoRead;
  sdTPM_PCR_INFO_SHORT pcrInfoWrite;
  TPM_NV_ATTRIBUTES permission;
  TPM_BOOL bReadSTClear;
  TPM_BOOL bWriteSTClear;
  TPM_BOOL bWriteDefine;
  UINT32 dataSize;
} sdTPM_NV_DATA_PUBLIC;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  sdTPM_NV_DATA_PUBLIC pubInfo;
  TPM_ENCAUTH encAuth;
} stTPM_NV_DEFINESPACE;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  TPM_NV_INDEX nvIndex;
  UINT32 offset;
  UINT32 dataSize;
} stTPM_NV_WRITEVALUE;

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
  TPM_COMMAND_CODE ordinal;
  TPM_NV_INDEX nvIndex;
  UINT32 offset;
  UINT32 dataSize;
} stTPM_NV_READVALUE;

///////////////////////////////////////////////////////////////////////////
TPM_RESULT TPM_Flush(BYTE *in_buffer, SessionCtx *sctx);
TPM_RESULT TPM_NV_WriteValueAuth(BYTE *buffer, BYTE *data, UINT32 dataSize,
                                 SessionCtx *sctx);
TPM_RESULT TPM_NV_ReadValueAuth(BYTE *in_buffer, BYTE *data, UINT32 dataSize,
                                SessionCtx *sctx);
TPM_RESULT TPM_NV_DefineSpace(BYTE *buffer, sdTPM_PCR_SELECTION select,
                              SessionCtx *sctx);
TPM_RESULT TPM_PcrRead(BYTE *in_buffer, TPM_DIGEST *hash,
                       TPM_PCRINDEX pcrindex);
TPM_RESULT TPM_GetRandom(BYTE *in_buffer, BYTE *dest, UINT32 size);
TPM_RESULT TPM_Start_OIAP(BYTE *in_buffer, SessionCtx *sctx);
TPM_RESULT TPM_Start_OSAP(BYTE *in_buffer, BYTE *usageAuth, UINT32 entityType,
                          UINT32 entityValue, SessionCtx *sctx);
TPM_RESULT TPM_Startup_Clear(BYTE *buffer);
TPM_EXTEND_RET TPM_Extend(TPM_PCRINDEX pcr_index, TPM_DIGEST hash);
TPM_RESULT TPM_Unseal(BYTE *buffer, BYTE *inData, BYTE *secretData,
                      UINT32 secretDataBufSize, UINT32 *secretDataSize,
                      SessionCtx *sctxParent, SessionCtx *sctxEntity);
TPM_RESULT TPM_Seal(BYTE *in_buffer, sdTPM_PCR_SELECTION select, BYTE *data,
                    UINT32 dataSize, BYTE *stored_data, SessionCtx *sctx,
                    BYTE *passPhraseAuthData);
int TPM_GetCapability_Pcrs(BYTE buffer[TCG_BUFFER_SIZE], TPM_PCRINDEX *pcrs);
void dump_pcrs(unsigned char *buffer);

#endif
