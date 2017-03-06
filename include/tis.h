#ifndef __TIS_H__
#define __TIS_H__

/*
 * \brief   TIS data structures and header of tis.c
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

#define TIS_BUFFER_SIZE 1024
struct TIS_BUFFERS {
  unsigned char in[TIS_BUFFER_SIZE];
  unsigned char out[TIS_BUFFER_SIZE];
};

extern struct TIS_BUFFERS tis_buffers;

enum TIS_TPM_VENDOR {
  TIS_INIT_NO_TPM = 0,
  TIS_INIT_STM = 1,
  TIS_INIT_INFINEON = 2,
  TIS_INIT_ATMEL = 3,
  TIS_INIT_BROADCOM = 4,
  TIS_INIT_QEMU = 5,
  TIS_INIT_IBM = 6,
};

#define TIS_BASE 0xfed40000
#define TPM_DID_VID_0 0xf00

enum TIS_LOCALITY {
  TIS_LOCALITY_0 = 0x0000,
  TIS_LOCALITY_1 = 0x1000,
  TIS_LOCALITY_2 = 0x2000,
  TIS_LOCALITY_3 = 0x3000,
  TIS_LOCALITY_4 = 0x4000
};

struct TIS_ID {
  int did_vid;
  unsigned char rid;
};

struct TIS_MMAP {
  unsigned char access;
  unsigned char dummy1[7];
  unsigned int int_enable;
  unsigned char int_vector;
  unsigned char dummy2[3];
  unsigned int int_status;
  unsigned int intf_capability;
  unsigned char sts_base;
  unsigned short sts_burst_count;
  unsigned char dummy3[9];
  unsigned char data_fifo;
};

enum TIS_ACCESS_BITS {
  TIS_ACCESS_VALID = 1 << 7,
  TIS_ACCESS_RESERVED = 1 << 6,
  TIS_ACCESS_ACTIVE = 1 << 5,
  TIS_ACCESS_SEIZED = 1 << 4,
  TIS_ACCESS_TO_SEIZE = 1 << 3,
  TIS_ACCESS_PENDING = 1 << 2,
  TIS_ACCESS_REQUEST = 1 << 1,
  TIS_ACCESS_TOS = 1 << 0
};

enum TIS_STS_BITS {
  TIS_STS_VALID = 1 << 7,
  TIS_STS_CMD_READY = 1 << 6,
  TIS_STS_TPM_GO = 1 << 5,
  TIS_STS_DATA_AVAIL = 1 << 4,
  TIS_STS_EXPECT = 1 << 3,
  TIS_STS_RESERVED_2 = 1 << 2,
  TIS_STS_RETRY = 1 << 1,
  TIS_STS_RESERVED_0 = 1 << 0
};

void tis_dump(void);
enum TIS_TPM_VENDOR tis_init(void);
/* EXCEPT: ERROR_TIS_LOCALITY_DEACTIVATE */
RESULT tis_deactivate_all(void);
/* EXCEPT:
 * ERROR_TIS_LOCALITY_REGISTER_INVALID
 * ERROR_TIS_LOCALITY_ACCESS_TIMEOUT
 * ERROR_TIS_LOCALITY_ALREADY_ACCESSED
 */
RESULT tis_access(enum TIS_LOCALITY locality, int force);
/* EXCEPT: ERROR_TIS_TRANSMIT */
RESULT tis_transmit(void);

#endif
