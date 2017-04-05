/*
 * \brief   TPM commands compiled with the TCG TPM Spec v1.2.
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


#include "tpm.h"
#include "util.h"


/**
 * Send a startup to the TPM.
 *
 * Note: We could use the TPM_TRANSMIT_FUNC macro, but this generates smaller code.
 */
int
TPM_Startup_Clear(unsigned char *buffer)
{
  ((unsigned int *)buffer)[0] = 0x0000c100;
  ((unsigned int *)buffer)[1] = 0x00000c00;
  ((unsigned int *)buffer)[2] = 0x01009900;
  int res = tis_transmit(buffer, 12, buffer, TCG_BUFFER_SIZE);
  return res < 0 ? res : (int) ntohl(*((unsigned int *) (buffer+6)));
}

/**
 * Extend a PCR with a hash.
 *
 * Note: We could use the TPM_TRANSMIT_FUNC macro, but this generates smaller code.
 */
int
TPM_Extend(unsigned char *buffer, unsigned long pcrindex, unsigned char *hash)
{
  ((unsigned int *)buffer)[0] = 0x0000c100;
  ((unsigned int *)buffer)[1] = 0x00002200;
  ((unsigned int *)buffer)[2] = 0x00001400;
  *((unsigned int *) (buffer+10))=ntohl(pcrindex);
  TPM_COPY_TO(hash, 4, TCG_HASH_SIZE);
  int res = tis_transmit(buffer, 34, buffer, TCG_BUFFER_SIZE);
  TPM_COPY_FROM(hash, 0, TCG_HASH_SIZE);
  return res < 0 ? res : (int) ntohl(*((unsigned int *) (buffer+6)));
}

#ifndef NDEBUG
/*
 * Get the number of suported pcrs.
 */
TPM_TRANSMIT_FUNC(GetCapability_Pcrs, (unsigned char *buffer, unsigned int *value),
		  unsigned long send_buffer[] = { TPM_ORD_GetCapability
		      AND TPM_CAP_PROPERTY
		      AND TPM_SUBCAP AND TPM_CAP_PROP_PCR };,
		  if (TPM_EXTRACT_LONG(0)!=4)
		    return -2;
		  *value=TPM_EXTRACT_LONG(4);)


/**
 * Read a pcr value.
 * Returns the value of the pcr in pcrvalue.
 */
TPM_TRANSMIT_FUNC(PcrRead,
		  (unsigned char *buffer, unsigned long index, unsigned char *value),
		  unsigned long send_buffer[] = {TPM_ORD_PcrRead AND index};
		  if (value==0) return -1;,
		  TPM_COPY_FROM(value, 0, TCG_HASH_SIZE);)



void
dump_pcrs(unsigned char *buffer)
{
  unsigned int pcrs;
  if (TPM_GetCapability_Pcrs(buffer, &pcrs))
    out_info("TPM_GetCapability_Pcrs() failed");
  else
    out_description("PCRs:", pcrs);

  unsigned char hash[20];
  for (unsigned pcr=0; pcr < pcrs; pcr++)
    {
      int res;
      if ((res = TPM_PcrRead(buffer, pcr, hash)))
	{
	  out_description("\nTPM_PcrRead() failed with",res);
	  break;
	}
      else
	{
	  out_string(" [");
	  out_hex(pcr, 0);
	  out_string("]: ");
	  for (unsigned i=0; i<4; i++)
	    out_hex(hash[i], 7);
	}
      out_char(pcr% 4==3 ? '\n' : ' ');

    }
}
#endif
