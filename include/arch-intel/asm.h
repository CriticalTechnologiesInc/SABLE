#ifndef __ASM_H__
#define __ASM_H__

/*
 * \brief   ASM inline helper routines.
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

#include "processor.h"
#include "types.h"
#include "msr.h"		// Bhushan : msr will contain most of intel specific funtions. keeping asm.h just not to break build

void reboot(void) __attribute__((noreturn));
void do_skinit(void) __attribute__((noreturn));
void jmp_multiboot(void *mbi, unsigned int entry) __attribute__((noreturn));

static inline unsigned int ntohl(unsigned int v) {
  unsigned int res;
  asm volatile("bswap %%eax" : "=a"(res) : "a"(v));
  return res;
}

static inline unsigned int htonl(unsigned int v) {
  unsigned int res;
  asm volatile("bswap %%eax" : "=a"(res) : "a"(v));
  return res;
}

/*

Bhushan: remove this are its copy is there in msr.h

static inline unsigned long long rdtsc(void) {
  unsigned long long res;

  // =A does not work in 64 bit mode
  asm volatile("rdtsc" : "=A"(res));
  return res;
}


static inline unsigned long long rdmsr(unsigned int addr) {
  unsigned long long res;

  // =A does not work in 64 bit mode
  asm volatile("rdmsr" : "=A"(res) : "c"(addr));
  return res;
}

static inline void wrmsr(unsigned int addr, unsigned long long value) {
  // =A does not work in 64 bit mode
  asm volatile("wrmsr" ::"c"(addr), "A"(value));
}

*/

static inline unsigned char inb(const unsigned short port) {
  unsigned char res;
  asm volatile("inb %1, %0" : "=a"(res) : "Nd"(port));
  return res;
}

static inline unsigned short inw(unsigned short port) {
  unsigned short res;
  asm volatile("inw  %1, %0" : "=a"(res) : "Nd"(port));
  return res;
}

static inline unsigned inl(const unsigned short port) {
  unsigned res;
  asm volatile("in %1, %0" : "=a"(res) : "Nd"(port));
  return res;
}

static inline void outb(const unsigned short port, unsigned char value) {
  asm volatile("outb %0,%1" ::"a"(value), "Nd"(port));
}

static inline void outw(const unsigned short port, unsigned short value) {
  asm volatile("outw %0,%1" ::"a"(value), "Nd"(port));
}

static inline void outl(const unsigned short port, unsigned value) {
  asm volatile("outl %0,%1" ::"a"(value), "Nd"(port));
}

static inline unsigned bsr(unsigned int value) {
  unsigned res;
  asm volatile("bsr %1,%0" : "=r"(res) : "r"(value));
  return res;
}

static inline unsigned bsf(unsigned int value) {
  unsigned res;
  asm volatile("bsf %1,%0" : "=r"(res) : "r"(value));
  return res;
}

#endif
