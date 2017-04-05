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

#include "tis.h"

#define TCG_HASH_SIZE                  20
#define TCG_DATA_OFFSET                10
#define TCG_BUFFER_SIZE                TCG_DATA_OFFSET+4+TCG_HASH_SIZE


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
  memcpy(DEST, &buffer[TCG_DATA_OFFSET + OFFSET], SIZE)

/**
 * Extract long values from the buffer.
 */
#define TPM_EXTRACT_LONG(OFFSET)			\
  ntohl(*(unsigned long *)(buffer+TCG_DATA_OFFSET+OFFSET))


/**
 * Copy values from the buffer.
 */
#define TPM_COPY_TO(DEST,OFFSET,SIZE)				\
  assert(TCG_BUFFER_SIZE>=TCG_DATA_OFFSET + OFFSET + SIZE)	\
  memcpy(&buffer[TCG_DATA_OFFSET + OFFSET], DEST, SIZE)

///////////////////////////////////////////////////////////////////////////

/**
 *
 */
enum tpm_ords {
	TPM_ORD_Extend=20,
	TPM_ORD_PcrRead = 21,
	TPM_ORD_GetCapability=101,
	TPM_ORD_Startup = 153,
};

enum tpm_caps {
	TPM_CAP_PROPERTY=5,
};

enum tpm_subcaps {
	TPM_CAP_PROP_PCR   = 257,
};

enum tpm_subcaps_size {
  TPM_NO_SUBCAP=0,
  TPM_SUBCAP=4,
};


///////////////////////////////////////////////////////////////////////////

int TPM_Startup_Clear(unsigned char buffer[TCG_BUFFER_SIZE]);
int TPM_Extend(unsigned char buffer[TCG_BUFFER_SIZE], unsigned long pcrindex, unsigned char *hash);
int TPM_GetCapability_Pcrs(unsigned char buffer[TCG_BUFFER_SIZE], unsigned int *pcrs);
int TPM_PcrRead(unsigned char buffer[TCG_BUFFER_SIZE], unsigned long pcrindex, unsigned char *pcrvalue);
void dump_pcrs(unsigned char *buffer);
