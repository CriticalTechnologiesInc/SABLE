/*
 * \brief   TIS access routines
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

#include "macro.h"
#include "asm.h"
#include "platform.h"
#include "exception.h"
#include "tcg.h"
#include "util.h"
#include "tis.h"

EXCEPTION_GEN(int);

struct TIS_BUFFERS tis_buffers = {.in = {0}, .out = {0}};

typedef struct {
  TPM_TAG tag;
  UINT32 paramSize;
} TPM_COMMAND_HEADER;

/**
 * Address of the TIS locality.
 */
static int tis_locality;

/**
 * Init the TIS driver.
 * Returns a TIS_INIT_* value.
 */
enum TIS_TPM_VENDOR tis_init() {
  volatile struct TIS_ID *id;
  volatile struct TIS_MMAP *mmap;

  id = (struct TIS_ID *)(TIS_BASE + TPM_DID_VID_0);
  mmap = (struct TIS_MMAP *)(TIS_BASE);

  /**
   * There are these buggy ATMEL TPMs that return -1 as did_vid if the
   * locality0 is not accessed!
   */
  if ((id->did_vid == -1) && ((mmap->intf_capability & ~0x1fa) == 5) &&
      ((mmap->access & 0xe8) == 0x80)) {
    out_info("Fix DID/VID bug...");
    tis_access(TIS_LOCALITY_0, 0);
  }

  switch (id->did_vid) {
  case 0x2e4d5453: /* "STM." */
  case 0x4a100000:
    out_description("STM rev:", id->rid);
    return TIS_INIT_STM;
  case 0xb15d1:
    out_description("Infineon rev:", id->rid);
    return TIS_INIT_INFINEON;
  case 0x32021114:
  case 0x32031114:
    out_description("Atmel rev:", id->rid);
    return TIS_INIT_ATMEL;
  case 0x100214E4:
    out_description("Broadcom rev:", id->rid);
    return TIS_INIT_BROADCOM;
  case 0x10001:
    out_description("Qemu TPM rev:", id->rid);
    return TIS_INIT_QEMU;
  case 0x11014:
    out_description("IBM TPM rev:", id->rid);
    return TIS_INIT_IBM;
  case 0:
  case -1:
    out_info("TPM not found!");
    return TIS_INIT_NO_TPM;
  default:
    out_description("TPM unknown! ID:", id->did_vid);
    return TIS_INIT_NO_TPM;
  }
}

/**
 * Deactivate all localities.
 * Returns zero if no locality is active.
 */
int tis_deactivate_all(void) {
  int res = 0;
  unsigned i;
  for (i = 0; i < 4; i++) {
    volatile struct TIS_MMAP *mmap = (struct TIS_MMAP *)(TIS_BASE + (i << 12));
    if (mmap->access != 0xff) {
      mmap->access = TIS_ACCESS_ACTIVE;
      res |= mmap->access & TIS_ACCESS_ACTIVE;
    }
  }
  return res;
}

/**
 * Request access for a given locality.
 * @param locality: address of the locality e.g. TIS_LOCALITY_2
 * Returns 0 if we could not gain access.
 */
int tis_access(enum TIS_LOCALITY locality, int force) {
  volatile struct TIS_MMAP *mmap;

  // a force on locality0 is unnecessary
  ASSERT(locality != TIS_LOCALITY_0 || !force);
  ASSERT(locality >= TIS_LOCALITY_0 && locality <= TIS_LOCALITY_4);

  tis_locality = TIS_BASE + locality;
  mmap = (struct TIS_MMAP *)tis_locality;

  CHECK3(0, !(mmap->access & TIS_ACCESS_VALID), "access register not valid");
  CHECK3(0, mmap->access == 0xff, "access register invalid")
  CHECK3(2, mmap->access & TIS_ACCESS_ACTIVE, "locality already active");

  // first try it the normal way
  mmap->access = TIS_ACCESS_REQUEST;

  wait(10);

  // make the tpm ready -> abort a command
  mmap->sts_base = TIS_STS_CMD_READY;

  if (force && !(mmap->access & TIS_ACCESS_ACTIVE)) {
    // now force it
    mmap->access = TIS_ACCESS_TO_SEIZE;
    wait(10);
    // make the tpm ready -> abort a command
    mmap->sts_base = TIS_STS_CMD_READY;
  }
  return mmap->access & TIS_ACCESS_ACTIVE;
}

static void wait_state(volatile struct TIS_MMAP *mmap, unsigned char state) {
  unsigned i;
  for (i = 0; i < 4000 && (mmap->sts_base & state) != state; i++)
    wait(1);
}

/**
 * EXCEPT: ERROR_TIS_TRANSMIT
 *
 * Write the given buffer to the TPM.
 * Returns the numbers of bytes transfered or an value < 0 on errors.
 */
static EXCEPTION(int) tis_write(void) {
  EXCEPTION(int) ret = { .exception.error = NONE };
  volatile struct TIS_MMAP *mmap = (struct TIS_MMAP *)tis_locality;
  const unsigned char *in = tis_buffers.in;
  const TPM_COMMAND_HEADER *header = (const TPM_COMMAND_HEADER *)tis_buffers.in;

  if (!(mmap->sts_base & TIS_STS_CMD_READY)) {
    // make the tpm ready -> wakeup from idle state
    mmap->sts_base = TIS_STS_CMD_READY;
    wait_state(mmap, TIS_STS_CMD_READY);
  }
  ERROR(!(mmap->sts_base & TIS_STS_CMD_READY), ERROR_TIS_TRANSMIT, "tis_write() not ready");

  int size = htonl(header->paramSize);
  for (ret.value = 0; ret.value < size; ret.value++) {
    mmap->data_fifo = *in;
    in++;
  }

  wait_state(mmap, TIS_STS_VALID);
  ERROR(mmap->sts_base & TIS_STS_EXPECT, ERROR_TIS_TRANSMIT, "TPM expects more data");

  // execute the command
  mmap->sts_base = TIS_STS_TPM_GO;

  return ret;
}

/**
 * EXCEPT: ERROR_TIS_TRANSMIT
 *
 * Read into the given buffer from the TPM.
 * Returns the numbers of bytes received or an value < 0 on errors.
 */
static EXCEPTION(int) tis_read(void) {
  EXCEPTION(int) ret = { .exception.error = NONE };
  volatile struct TIS_MMAP *mmap = (struct TIS_MMAP *)tis_locality;
  unsigned char *out = tis_buffers.out;
  TPM_COMMAND_HEADER *header = (TPM_COMMAND_HEADER *)tis_buffers.out;

  wait_state(mmap, TIS_STS_VALID | TIS_STS_DATA_AVAIL);
  ERROR(!(mmap->sts_base & TIS_STS_VALID), ERROR_TIS_TRANSMIT, "sts not valid");

  for (ret.value = 0;
       ret.value < sizeof(TPM_COMMAND_HEADER) && mmap->sts_base & TIS_STS_DATA_AVAIL;
       ret.value++) {
    *out = mmap->data_fifo;
    out++;
  }
  int size = htonl(header->paramSize);
  for (; ret.value < size && mmap->sts_base & TIS_STS_DATA_AVAIL; ret.value++) {
    *out = mmap->data_fifo;
    out++;
  }

  ERROR(mmap->sts_base & TIS_STS_DATA_AVAIL, ERROR_TIS_TRANSMIT, "more data available");

  // make the tpm ready again -> this allows tpm background jobs to complete
  mmap->sts_base = TIS_STS_CMD_READY;
  return ret;
}

/**
 * Transmit a command to the TPM and wait for the response.
 * This is our high level TIS function used by all TPM commands.
 */
RESULT tis_transmit(void) {
  RESULT ret = { .exception.error = NONE };
  EXCEPTION(int) res;

  THROW(res, tis_write());
  THROW(res, tis_read());
  return ret;
}
