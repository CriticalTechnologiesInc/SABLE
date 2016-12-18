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

#include "tis.h"
#include "tpm_command.h"
#include "util.h"

struct tis_buffers_s tis_buffers = {.in = {0}, .out = {0}};

/**
 * TIS base address.
 */
static int tis_base;

/**
 * Address of the TIS locality.
 */
static int tis_locality;

/**
 * Init the TIS driver.
 * Returns a TIS_INIT_* value.
 */
enum tis_init tis_init(int base) {
  volatile struct tis_id *id;
  volatile struct tis_mmap *mmap;

  tis_base = base;
  id = (struct tis_id *)(tis_base + TPM_DID_VID_0);
  mmap = (struct tis_mmap *)(tis_base);

  /**
   * There are these buggy ATMEL TPMs that return -1 as did_vid if the
   * locality0 is not accessed!
   */
  if ((id->did_vid == -1) && ((mmap->intf_capability & ~0x1fa) == 5) &&
      ((mmap->access & 0xe8) == 0x80)) {
#ifdef EXEC
    out_info("Fix DID/VID bug...");
#else
    out_info(&string_literal);
#endif
    tis_access(TIS_LOCALITY_0, 0);
  }

  switch (id->did_vid) {
  case 0x2e4d5453: /* "STM." */
  case 0x4a100000:
#ifdef EXEC
    out_description("STM rev:", id->rid);
#else
    out_description(&string_literal, id->rid);
#endif
    return TIS_INIT_STM;
  case 0xb15d1:
#ifdef EXEC
    out_description("Infineon rev:", id->rid);
#else
    out_description(&string_literal, id->rid);
#endif
    return TIS_INIT_INFINEON;
  case 0x32021114:
  case 0x32031114:
#ifdef EXEC
    out_description("Atmel rev:", id->rid);
#else
    out_description(&string_literal, id->rid);
#endif
    return TIS_INIT_ATMEL;
  case 0x100214E4:
#ifdef EXEC
    out_description("Broadcom rev:", id->rid);
#else
    out_description(&string_literal, id->rid);
#endif
    return TIS_INIT_BROADCOM;
  case 0x10001:
#ifdef EXEC
    out_description("Qemu TPM rev:", id->rid);
#else
    out_description(&string_literal, id->rid);
#endif
    return TIS_INIT_QEMU;
  case 0x11014:
#ifdef EXEC
    out_description("IBM TPM rev:", id->rid);
#else
    out_description(&string_literal, id->rid);
#endif
    return TIS_INIT_IBM;
  case 0:
  case -1:
#ifdef EXEC
    out_info("TPM not found!");
#else
    out_info(&string_literal);
#endif
    return TIS_INIT_NO_TPM;
  default:
#ifdef EXEC
    out_description("TPM unknown! ID:", id->did_vid);
#else
    out_description(&string_literal, id->did_vid);
#endif
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
    volatile struct tis_mmap *mmap = (struct tis_mmap *)(tis_base + (i << 12));
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
int tis_access(int locality, int force) {
  volatile struct tis_mmap *mmap;

  // a force on locality0 is unnecessary
  assert(locality != TIS_LOCALITY_0 || !force);
  assert(locality >= TIS_LOCALITY_0 && locality <= TIS_LOCALITY_4);

  tis_locality = tis_base + locality;
  mmap = (struct tis_mmap *)tis_locality;

#ifdef EXEC
  CHECK3(0, !(mmap->access & TIS_ACCESS_VALID), "access register not valid");
#else
  CHECK3(0, !(mmap->access & TIS_ACCESS_VALID), &string_literal);
#endif
#ifdef EXEC
  CHECK3(0, mmap->access == 0xff, "access register invalid")
#else
  CHECK3(0, mmap->access == 0xff, &string_literal)
#endif
#ifdef EXEC
  CHECK3(2, mmap->access & TIS_ACCESS_ACTIVE, "locality already active");
#else
  CHECK3(2, mmap->access & TIS_ACCESS_ACTIVE, &string_literal);
#endif

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

static void wait_state(volatile struct tis_mmap *mmap, unsigned char state) {
  unsigned i;
  for (i = 0; i < 4000 && (mmap->sts_base & state) != state; i++)
    wait(1);
}

/**
 * Write the given buffer to the TPM.
 * Returns the numbers of bytes transfered or an value < 0 on errors.
 */
static int tis_write(void) {
  volatile struct tis_mmap *mmap = (struct tis_mmap *)tis_locality;
  const unsigned char *in = tis_buffers.in;
  const TPM_COMMAND_HEADER *header = (const TPM_COMMAND_HEADER *)tis_buffers.in;
  unsigned res;

  if (!(mmap->sts_base & TIS_STS_CMD_READY)) {
    // make the tpm ready -> wakeup from idle state
    mmap->sts_base = TIS_STS_CMD_READY;
    wait_state(mmap, TIS_STS_CMD_READY);
  }
#ifdef EXEC
  CHECK3(-1, !(mmap->sts_base & TIS_STS_CMD_READY), "tis_write() not ready");
#else
  CHECK3(-1, !(mmap->sts_base & TIS_STS_CMD_READY), &string_literal);
#endif

  for (res = 0; res < header->paramSize; res++) {
    mmap->data_fifo = *in;
    in++;
  }

  wait_state(mmap, TIS_STS_VALID);
#ifdef EXEC
  CHECK3(-2, mmap->sts_base & TIS_STS_EXPECT, "TPM expects more data");
#else
  CHECK3(-2, mmap->sts_base & TIS_STS_EXPECT, &string_literal);
#endif

  // execute the command
  mmap->sts_base = TIS_STS_TPM_GO;

  return res;
}

/**
 * Read into the given buffer from the TPM.
 * Returns the numbers of bytes received or an value < 0 on errors.
 */
static int tis_read(void) {
  volatile struct tis_mmap *mmap = (struct tis_mmap *)tis_locality;
  unsigned char *out = tis_buffers.out;
  TPM_COMMAND_HEADER *header = (TPM_COMMAND_HEADER *)tis_buffers.out;
  unsigned res = 0;

  wait_state(mmap, TIS_STS_VALID | TIS_STS_DATA_AVAIL);
#ifdef EXEC
  CHECK4(-2, !(mmap->sts_base & TIS_STS_VALID), "sts not valid",
         mmap->sts_base);
#else
  CHECK4(-2, !(mmap->sts_base & TIS_STS_VALID), &string_literal,
         mmap->sts_base);
#endif

  for (res = 0;
       res < sizeof(TPM_COMMAND_HEADER) && mmap->sts_base & TIS_STS_DATA_AVAIL;
       res++) {
    *out = mmap->data_fifo;
    out++;
  }
  for (; res < header->paramSize && mmap->sts_base & TIS_STS_DATA_AVAIL;
       res++) {
    *out = mmap->data_fifo;
    out++;
  }

#ifdef EXEC
  CHECK3(-3, mmap->sts_base & TIS_STS_DATA_AVAIL, "more data available");
#else
  CHECK3(-3, mmap->sts_base & TIS_STS_DATA_AVAIL, &string_literal);
#endif

  // make the tpm ready again -> this allows tpm background jobs to complete
  mmap->sts_base = TIS_STS_CMD_READY;
  return res;
}

/**
 * Transmit a command to the TPM and wait for the response.
 * This is our high level TIS function used by all TPM commands.
 */
int tis_transmit(void) {
  unsigned int res;

  res = tis_write();
#ifdef EXEC
  CHECK4(-1, res <= 0, "  TIS write error:", res);
#else
  CHECK4(-1, res <= 0, &string_literal, res);
#endif

  res = tis_read();
#ifdef EXEC
  CHECK4(-2, res <= 0, "  TIS read error:", res);
#else
  CHECK4(-2, res <= 0, &string_literal, res);
#endif
  return res;
}
