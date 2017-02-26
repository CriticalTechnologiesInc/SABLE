/*
 * \brief   Functions to support SMP.
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

#include "asm.h"
#include "platform.h"
#include "alloc.h"
#include "exception.h"
#include "mp.h"
#include "tcg.h"
#include "util.h"

/* EXCEPT:
 * ERROR_APIC
 */
RESULT stop_processors(void) { return send_ipi(APIC_ICR_INIT); }

/* EXCEPT:
 * ERROR_APIC
 */
RESULT start_processors(unsigned address) {
  ASSERT(!(address & 0xfff00fff) && "address not aligned or larger than 1MB");
  return send_ipi(APIC_ICR_STARTUP | address >> 12);
}

/* EXCEPT:
 * ERROR_APIC
 *
 * Send an IPI to all APs.
 */
RESULT send_ipi(unsigned param) {
  RESULT ret = { .exception.error = NONE };
  unsigned long long value;

  value = rdmsr(MSR_APIC_BASE);
  ERROR(!(value & (APIC_BASE_ENABLE | APIC_BASE_BSP)), ERROR_APIC,
         "not BSP or APIC disabled");
  ERROR((value >> 32) & 0xf, ERROR_APIC, "APIC out of range");

  unsigned long *apic_icr_low =
      (unsigned long *)(((unsigned long)value & 0xfffff000) +
                        APIC_ICR_LOW_OFFSET);

  ERROR(*apic_icr_low & APIC_ICR_PENDING, ERROR_APIC, "Interrupt pending");
  *apic_icr_low =
      APIC_ICR_DST_ALL_EX | APIC_ICR_LEVEL_EDGE | APIC_ICR_ASSERT | param;

  while (*apic_icr_low & APIC_ICR_PENDING)
    wait(1);

  return ret;
}
