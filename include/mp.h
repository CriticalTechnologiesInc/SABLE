#ifndef __MP_H__
#define __MP_H__

/*
 * \brief header used for MP initialization
 * \date    2006-07-14
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

enum APIC_DEFS {
  MSR_APIC_BASE = 0x1B,
  APIC_BASE_ENABLE = 0x800,
  APIC_BASE_BSP = 0x100,

  APIC_ICR_LOW_OFFSET = 0x300,

  APIC_ICR_DST_ALL_EX = 0x3 << 18,
  APIC_ICR_LEVEL_EDGE = 0x0 << 15,
  APIC_ICR_ASSERT = 0x1 << 14,
  APIC_ICR_PENDING = 0x1 << 12,
  APIC_ICR_INIT = 0x5 << 8,
  APIC_ICR_STARTUP = 0x6 << 8,
};

/* EXCEPT:
 * ERROR_APIC
 *
 * Send an IPI to all APs.
 */
RESULT send_ipi(unsigned param);

/* EXCEPT:
 * ERROR_APIC
 *
 * Stop all application processors by sending them an INIT IPI.
 */
RESULT stop_processors(void);

/* EXCEPT:
 * ERROR_APIC
 *
 * Sending all APs a Startup IPI and let them execute real mode code
 * at address.
 */
RESULT start_processors(unsigned address);

#endif
