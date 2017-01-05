/*
 * \brief   Utility functions for a bootloader
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

#include "util.h"
#include "string.h"

void memcpy(void *dest, const void *src, UINT32 len) {
  BYTE *dp = dest;
  const BYTE *sp = src;
  for (UINT32 i = 0; i < len; i++) {
    *dp = *sp;
    dp++;
    sp++;
  }
}

void memset(void *s, BYTE c, UINT32 len) {
  BYTE *p = s;
  for (UINT32 i = 0; i < len; i++) {
    *p = c;
    p++;
  }
}

/**
 * Swaps bytes in a short, like ntohl()
 */
UINT16
ntohs(UINT16 v) { return (v >> 8) | (v << 8); }

// like strlen
UINT32
strnlen_sable(BYTE *value, UINT32 size) {
  unsigned long i;
  for (i = 0; i < size; i++)
    if (*(value + i) == 0)
      break;
  return i;
}

// compares two buffers for a certain length
UINT32
bufcmp(const void *buf1, const void *buf2, UINT32 size) {
  UINT32 i;
  for (i = 0; i < size; i++)
    if (*((unsigned char *)buf1 + i) != *((unsigned char *)buf2 + i))
      break;
  return (i < size);
}

// make mptr point to the next line in an ascii module.
// return the amount of bytes in the current line.
// return -1 if mptr goes off the boundary
UINT32
nextln(BYTE **mptr, UINT32 mod_end) {
  UINT32 i = 0;
  while (**mptr != 0x0a) {
    if ((UINT32)*mptr > mod_end)
      return -1;
    i++;
    (*mptr)++;
  }
  (*mptr)++;
  return i;
}

/**
 * Wait roughly a given number of milliseconds.
 *
 * We use the PIT for this.
 */
void wait(int ms) {
  /* the PIT counts with 1.193 Mhz */
  ms *= 1193;

  /* initalize the PIT, let counter0 count from 256 backwards */
  outb(0x43, 0x34);
  outb(0x40, 0);
  outb(0x40, 0);

  unsigned short state;
  unsigned short old = 0;
  while (ms > 0) {
    outb(0x43, 0);
    state = inb(0x40);
    state |= inb(0x40) << 8;
    ms -= (unsigned short)(old - state);
    old = state;
  }
}

/**
 * Print the exit status and reboot the machine.
 */
void exit(unsigned status) {
  out_char('\n');
  out_description(s_exit, status);
  for (unsigned i = 0; i < 1000; i++) {
    wait(1000);
    // out_char('.');
  }
  out_string(s_reboot_now);
  reboot();
}

/**
 * Checks whether we have SVM support and a local APIC.
 *
 * @return: the SVM revision of the processor or a negative value, if
 * not supported.
 */
int check_cpuid(void) {
  int res;
  CHECK3(-31, 0x8000000A > cpuid_eax(0x80000000), s_no_ext_cpuid);
  CHECK3(-32, !(0x4 & cpuid_ecx(0x80000001)), s_no_SVM_support);
  CHECK3(-33, !(0x200 & cpuid_edx(0x80000001)), s_no_APIC_support);
  res = cpuid_eax(0x8000000A) & 0xff;
  return res;
}

/**
 * Enables SVM support.
 *
 */
int enable_svm(void) {
  unsigned long long value;
  value = rdmsr(MSR_EFER);
  wrmsr(MSR_EFER, value | EFER_SVME);
  CHECK3(-40, !(rdmsr(MSR_EFER) & EFER_SVME), s_could_not_enable_SVM);
  return 0;
}

/**
 * Output a single char.
 * Note: We allow only to put a char on the last line.
 */
int out_char(unsigned value) {
#define BASE(ROW) ((unsigned short *)(0xb8000 + ROW * 160))
  static unsigned int col;
  if (value != '\n') {
    unsigned short *p = BASE(24) + col;
    *p = 0x0f00 | value;
    col++;
  }

  if (col >= 80 || value == '\n') {
    col = 0;
    unsigned short *p = BASE(0);
    memcpy(p, p + 80, 24 * 160);
    memset(BASE(24), 0, 160);
  }

  return value;
}

/**
 * Output a string.
 */
void out_string(const char *value) {
  for (; *value; value++)
    out_char(*value);
}

/**
 * Output many hex values
 */
void hex_dump(unsigned char *bytestring, unsigned len) {
  for (unsigned i = 0; i < len; i++) {
    if (i % 16 == 0)
      out_char('\n');
    else if (i % 4 == 0)
      out_char(' ');
    out_hex(*(bytestring + i), 7);
  }
  out_char('\n');
}

/**
 * Output a single hex value.
 */
void out_hex(unsigned value, unsigned bitlen) {
  int i;
  for (i = bsr(value | 1 << bitlen) & 0xfc; i >= 0; i -= 4) {
    unsigned a = (value >> i) & 0xf;
    if (a >= 10)
      a += 7;
    a += 0x30;

    out_char(a);
  }
}

/**
 * Output a string followed by a single hex value, prefixed with a
 * message label.
 */
void out_description(const char *prefix, unsigned int value) {
  out_string(s_message_label);
  out_string(prefix);
  out_char(' ');
  out_hex(value, 0);
  out_char('\n');
}

/**
 * Output a string, prefixed with a message label.
 */
void out_info(const char *msg) {
  out_string(s_message_label);
  out_string(msg);
  out_char('\n');
}