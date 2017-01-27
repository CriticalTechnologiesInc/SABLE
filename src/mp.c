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

#include "macro.h"
#include "mp.h"
#include "asm.h"
#include "platform.h"
#include "tcg.h"
#include "util.h"

int stop_processors(void) { return send_ipi(APIC_ICR_INIT); }

int start_processors(unsigned address) {
  CHECK4(-50, address & 0xfff00fff, "address not aligned or larger than 1MB",
         address);
  return send_ipi(APIC_ICR_STARTUP | address >> 12);
}

/**
 * Send an IPI to all APs.
 */
int send_ipi(unsigned param) {

  unsigned long long value;
  value = rdmsr(MSR_APIC_BASE);
  CHECK3(-51, !(value & (APIC_BASE_ENABLE | APIC_BASE_BSP)),
         "not BSP or APIC disabled");
  CHECK3(-52, (value >> 32) & 0xf, "APIC out of range");

  unsigned long *apic_icr_low =
      (unsigned long *)(((unsigned long)value & 0xfffff000) +
                        APIC_ICR_LOW_OFFSET);

  CHECK3(-53, *apic_icr_low & APIC_ICR_PENDING, "Interrupt pending");
  *apic_icr_low =
      APIC_ICR_DST_ALL_EX | APIC_ICR_LEVEL_EDGE | APIC_ICR_ASSERT | param;

  while (*apic_icr_low & APIC_ICR_PENDING)
    wait(1);

  return 0;
}
