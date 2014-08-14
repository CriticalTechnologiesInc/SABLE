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

#ifdef __midl
#define SIZEIS(x)  [size_is(x)]
#else
#define SIZEIS(x)
#endif

#include "platform.h"
#include "tis.h"

#define TPM_TRANSMIT_FAIL              0xFFFF0000

#define TCG_HASH_SIZE                  20
#define TCG_DATA_OFFSET                10
#define TCG_BUFFER_SIZE                1024
#define PCR_SELECT_SIZE                3

#define NORESET_PCR_ORD                15
#define SLB_PCR_ORD                    17
#define MODULE_PCR_ORD                 19

#define NV_DATA_OFFSET                 0x00010000
#define NV_DATA_SIZE                   500

/**
 * Use AND to separate the items in a array construction.
 */
#define AND ,


/**
 * Defines a simple transmit function, which is used several times in
 * the lib, e.g. TPM_PcrRead
 */
#define TPM_TRANSMIT_FUNC(NAME,PARAMS,PRECOND,POSTCOND)			\
  int TPM_##NAME PARAMS {						\
    int ret;								\
    int size = 6;							\
    PRECOND;								\
    buffer[0] = 0x00;							\
    buffer[1] = 0xc1;							\
    size+=sizeof(send_buffer);						\
    *(unsigned long *)(buffer+2) = ntohl(size);				\
    assert(TCG_BUFFER_SIZE>=size);					\
    for (unsigned i=0; i<sizeof(send_buffer)/sizeof(*send_buffer); i++)	\
      *((unsigned long *)(buffer+6)+i) = ntohl(send_buffer[i]);		\
    ret = tis_transmit(buffer, size, buffer, TCG_BUFFER_SIZE);		\
    if (ret < 0)							\
      return ret;							\
    POSTCOND;								\
    return ntohl(*(unsigned long *)(buffer+6));				\
  }

/**
 * Copy values from the buffer.
 */
#define TPM_COPY_FROM(DEST,OFFSET,SIZE)				\
  assert(TCG_BUFFER_SIZE>=TCG_DATA_OFFSET + OFFSET + SIZE)	\
  memcpy(DEST, &in_buffer[TCG_DATA_OFFSET + OFFSET], SIZE)

/**
 * Extract long values from the buffer.
 */
#define TPM_EXTRACT_LONG(OFFSET)			\
  ntohl(*(unsigned long *)(buffer+TCG_DATA_OFFSET+OFFSET))

/**
 * Copy values to SHA1 buffer
 */
#define SHA_COPY_TO(SRC, SIZE)				\
  assert(sha_size >= sha_offset + SIZE)	\
  memcpy(sha_buf + sha_offset, SRC, SIZE);      \
  sha_offset += SIZE

/**
 * Copy values to HMAC buffer
 */
#define HMAC_COPY_TO(SRC, SIZE)				\
  assert(hmac_size >= hmac_offset + SIZE)	\
  memcpy(hmac_buf + hmac_offset, SRC, SIZE);      \
  hmac_offset += SIZE

/**
 * Copy values to the TPM-in buffer
 */
#define SABLE_TPM_COPY_TO(SRC, SIZE)				\
  assert(TCG_BUFFER_SIZE >= tpm_offset_out + SIZE)	\
  memcpy(out_buffer + tpm_offset_out, SRC, SIZE);    \
  tpm_offset_out += SIZE

/**
 * Copy values from the TPM-in buffer
 */
#define SABLE_TPM_COPY_FROM(SRC, SIZE)				\
  assert(TCG_BUFFER_SIZE >= tpm_offset_in + SIZE)	\
  memcpy(in_buffer + tpm_offset_in, SRC, SIZE);    \
  tpm_offset_in += SIZE

/**
 * Transmit command to the TPM
 */
#define TPM_TRANSMIT(FUNCTION_NAME)				\
    res = tis_transmit(out_buffer, paramSize, in_buffer, TCG_BUFFER_SIZE)

/**
 * Copy values from the buffer.
 */
#define TPM_COPY_TO(DEST,OFFSET,SIZE)				\
  assert(TCG_BUFFER_SIZE>=TCG_DATA_OFFSET + OFFSET + SIZE)	\
  memcpy(&buffer[TCG_DATA_OFFSET + OFFSET], DEST, SIZE)

///////////////////////////////////////////////////////////////////////////

//---------------------------------------------------
// Official TCG Structures and Definitions
//---------------------------------------------------

/*
 * TPM Ordinal definitions extracted from the TPM 1.2 specification, rev 85.
 */

#define TPM_ORD_OIAP                              ((UINT32)0x0000000A)
#define TPM_ORD_OSAP                              ((UINT32)0x0000000B)
#define TPM_ORD_Extend                            ((UINT32)0x00000014)
#define TPM_ORD_PcrRead                           ((UINT32)0x00000015)
#define TPM_ORD_Seal                              ((UINT32)0x00000017)
#define TPM_ORD_Unseal                            ((UINT32)0x00000018)
#define TPM_ORD_GetRandom                         ((UINT32)0x00000046)
#define TPM_ORD_GetCapability                     ((UINT32)0x00000065)
#define TPM_ORD_SHA1CompleteExtend                ((UINT32)0x000000A3)
#define TPM_ORD_FlushSpecific                     ((UINT32)0x000000BA)
#define TPM_ORD_NV_DefineSpace                    ((UINT32)0x000000CC)
#define TPM_ORD_NV_WriteValueAuth                 ((UINT32)0x000000CE)
#define TPM_ORD_NV_ReadValueAuth                  ((UINT32)0x000000D0)

//-------------------------------------------------------------------
// Part 2, section 2.1: Basic data types
typedef BYTE   TPM_BOOL;
#ifndef FALSE
#define FALSE  0x00
#define TRUE   0x01
#endif /* ifndef FALSE */

//-------------------------------------------------------------------
// Part 2, section 2.3: Helper Redefinitions
//   Many of the helper redefinitions appear later in this file
//   so that they are declared next to the list of valid values
//   they may hold.
typedef UINT32 TPM_COMMAND_CODE;                            /* 1.1b */
typedef UINT32 TPM_AUTHHANDLE;
typedef UINT32 TPM_PCRINDEX;
typedef UINT32 TPM_RESULT;
typedef UINT32 TPM_HANDLE;

//-------------------------------------------------------------------
// Part 2, section 3: Structure Tags
typedef UINT16  TPM_STRUCTURE_TAG;
#define TPM_TAG_PCR_INFO_LONG          ((UINT16)0x0006)
#define TPM_TAG_NV_ATTRIBUTES          ((UINT16)0x0017)
#define TPM_TAG_NV_DATA_PUBLIC         ((UINT16)0x0018)

//-------------------------------------------------------------------
// Part 2, section 4: Types

typedef UINT32 TPM_RESOURCE_TYPE;
#define TPM_RT_AUTH                    ((UINT32)0x00000002)

typedef UINT16 TPM_ENTITY_TYPE;                             /* 1.1b */
#define TPM_ET_KEYHANDLE               ((UINT16)0x0001)     /* 1.1b */
#define TPM_ET_OWNER                   ((UINT16)0x0002)     /* 1.1b */

typedef UINT32 TPM_KEY_HANDLE;                              /* 1.1b */
#define TPM_KH_SRK                     ((UINT32)0x40000000)

//-------------------------------------------------------------------
// Part 2, section 5: Basic Structures

#define TPM_SHA1_160_HASH_LEN    0x14
#define TPM_SHA1BASED_NONCE_LEN  TPM_SHA1_160_HASH_LEN

typedef struct tdTPM_NONCE                                  /* 1.1b */
{
    BYTE  nonce[TPM_SHA1BASED_NONCE_LEN];
} TPM_NONCE;

typedef struct tdTPM_AUTHDATA                               /* 1.1b */
{
    BYTE  authdata[TPM_SHA1_160_HASH_LEN];
} TPM_AUTHDATA;

typedef TPM_AUTHDATA TPM_ENCAUTH;

typedef struct tdTPM_DIGEST
{
    BYTE  digest[TPM_SHA1_160_HASH_LEN];
} TPM_DIGEST;

typedef TPM_DIGEST TPM_COMPOSITE_HASH;

//-------------------------------------------------------------------
// Part 2, section 6: Command Tags

typedef UINT16 TPM_TAG;                                     /* 1.1b */
#define TPM_TAG_RQU_COMMAND            ((UINT16)0x00c1)
#define TPM_TAG_RQU_AUTH1_COMMAND      ((UINT16)0x00c2)
#define TPM_TAG_RQU_AUTH2_COMMAND      ((UINT16)0x00c3)

//-------------------------------------------------------------------
// Part 2, section 8: PCR Structures

typedef BYTE  TPM_LOCALITY_SELECTION;
#define TPM_LOC_FOUR                   (((UINT32)1)<<4)
#define TPM_LOC_THREE                  (((UINT32)1)<<3)
#define TPM_LOC_TWO                    (((UINT32)1)<<2)
#define TPM_LOC_ONE                    (((UINT32)1)<<1)
#define TPM_LOC_ZERO                   (((UINT32)1)<<0)

//-------------------------------------------------------------------
// Part 2, section 19: NV Structures

typedef UINT32 TPM_NV_INDEX;
typedef UINT32 TPM_NV_PER_ATTRIBUTES;
#define TPM_NV_PER_AUTHREAD            (((UINT32)1)<<18)
#define TPM_NV_PER_AUTHWRITE           (((UINT32)1)<<2)

typedef struct tdTPM_NV_ATTRIBUTES
{
    TPM_STRUCTURE_TAG     tag;
    TPM_NV_PER_ATTRIBUTES attributes;
} TPM_NV_ATTRIBUTES;

//-------------------------------------------------------------------
// Part 2, section 21.1: TPM_CAPABILITY_AREA

typedef UINT32 TPM_CAPABILITY_AREA;                         /* 1.1b */
#define TPM_CAP_PROPERTY               ((UINT32)0x00000005) /* 1.1b */

//-------------------------------------------------------------------
// Part 2, section 21.2: Subcap values for CAP_PROPERTY

#define TPM_CAP_PROP_PCR               ((UINT32)0x00000101) /* 1.1b */

//---------------------------------------------------
// Custom TPM data structures for SABLE
//---------------------------------------------------

enum tpm_subcaps_size {
  TPM_NO_SUBCAP=0,
  TPM_SUBCAP=4,
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
    //only supports 2 PCR values
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
    TPM_PCRINDEX pcrNum;
    TPM_DIGEST inDigest;
} stTPM_Extend;

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
    //TPM_STORED_DATA inData; we can't include this in struct because 
    //it's variable size, but remember it's here for command parsing
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
TPM_RESULT TPM_NV_WriteValueAuth(BYTE *buffer, BYTE *data, UINT32 dataSize, SessionCtx *sctx);
TPM_RESULT TPM_NV_ReadValueAuth(BYTE *in_buffer, BYTE *data, UINT32 dataSize, SessionCtx *sctx);
TPM_RESULT TPM_NV_DefineSpace(BYTE *buffer, sdTPM_PCR_SELECTION select, SessionCtx *sctx);
TPM_RESULT TPM_PcrRead(BYTE *in_buffer, TPM_DIGEST *hash, TPM_PCRINDEX pcrindex);
TPM_RESULT TPM_GetRandom(BYTE *in_buffer, BYTE *dest, UINT32 size);
TPM_RESULT TPM_Start_OIAP(BYTE *in_buffer, SessionCtx *sctx);
TPM_RESULT TPM_Start_OSAP(BYTE *in_buffer, BYTE *usageAuth, UINT32 entityType, UINT32 entityValue, SessionCtx * sctx);
int TPM_Startup_Clear(unsigned char buffer[TCG_BUFFER_SIZE]);
TPM_RESULT TPM_Extend (BYTE *in_buffer, TPM_PCRINDEX pcr_index, TPM_DIGEST *hash);
TPM_RESULT TPM_Unseal( BYTE *buffer, BYTE *inData, BYTE *secretData, UINT32 secretDataBufSize, UINT32 *secretDataSize, SessionCtx * sctxParent, SessionCtx * sctxEntity);
int TPM_Seal(BYTE *in_buffer, sdTPM_PCR_SELECTION select, BYTE * data, UINT32 dataSize, BYTE *stored_data, SessionCtx * sctx);
int TPM_GetCapability_Pcrs(unsigned char buffer[TCG_BUFFER_SIZE], unsigned int *pcrs);
void dump_pcrs(unsigned char *buffer);
