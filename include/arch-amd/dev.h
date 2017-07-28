#ifndef __DEV_H__
#define __DEV_H__

/*
 * \brief header used for DEV protection
 * \date    2006-10-25
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

#include "exception.h"

enum pci_constants {
  PCI_ADDR_PORT = 0xcf8,
  PCI_DATA_PORT = 0xcfc,
  PCI_CONF_HDR_CMD = 4,
  PCI_CONF_HDR_CAP = 52,
  PCI_CAP_OFFSET = 1,
};

enum dev_constants {
  DEV_PCI_DEVICE_ID_OLD = 0x11031022,
  DEV_PCI_DEVICE_ID_K10 = 0x12031022,
  DEV_PCI_DEVICE_ID_BLD = 0x14031022,
  DEV_PCI_DEVICE_ID_LEN = 0x141d1022,
  DEV_PCI_CAP_ID = 0x0f,
  DEV_OFFSET_OP = 4,
  DEV_OFFSET_DATA = 8,
};

enum dev_registers {
  DEV_REG_BASE_LO,
  DEV_REG_BASE_HI,
  DEV_REG_MAP,
  DEV_REG_CAP,
  DEV_REG_CR,
  DEV_REG_ERR_STATUS,
  DEV_REG_ERR_ADDR_LO,
  DEV_REG_ERR_ADDR_HI,
};

enum dev_cr {
  DEV_CR_EN = 1 << 0,
  DEV_CR_CLEAR = 1 << 1,
  DEV_CR_IOSPEN = 1 << 2,
  DEV_CR_MCE = 1 << 3,
  DEV_CR_INVD = 1 << 4,
  DEV_CR_SLDEV = 1 << 5,
  DEV_CR_PROBE = 1 << 6,
};

/* EXCEPT:
 * ERROR_PCI
 * ERROR_DEV */
RESULT disable_dev_protection(void);
int pci_iterate_devices(void);
unsigned pci_read_long(unsigned addr);
void pci_write_long(unsigned addr, unsigned value);
unsigned pci_find_device_per_class(unsigned short class);
/* EXCEPT:
 * ERROR_PCI
 * ERROR_DEV
 * ERROR_APIC
 * ERROR_SVM
 * ERROR_NO_EXT
 * ERROR_NO_APIC
 * ERROR_NO_SVM
 */
RESULT revert_skinit(void);

#endif
