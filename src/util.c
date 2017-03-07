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

#ifndef ISABELLE
#include "asm.h"
#include "alloc.h"
#include "util.h"

static const char *const message_label = "SABLE:   ";

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
 * Output a single hex value.
 */
void str_hex(char *str, unsigned value, unsigned bitlen) {
  int i;
  for (i = bsr(value | 1 << bitlen) & 0xfc; i >= 0; i -= 4) {
    unsigned a = (value >> i) & 0xf;
    if (a >= 10)
      a += 7;
    a += 0x30;

    *(str++) = a;
  }
}

#ifndef NDEBUG
void dump_exception(EXCEPTION e) {
  out_string(message_label);
  out_string("EXCEPTION: ");
  out_string(e.msg);
  out_char('\n');
  out_info("Call Stack:");
  for (SOURCE_LOCATION_LIST *l = e.loc; l; l = l->next) {
    out_string(message_label);
    out_string(l->l.function);
    out_string("():");
    out_string(l->l.file);
    out_char(':');
    out_string(l->l.line);
    out_char('\n');
  }
}
#else
void dump_exception(EXCEPTION e) {}
#endif

void *memcpy(void *dest, const void *src, UINT32 len) {
  BYTE *dp = dest;
  const BYTE *sp = src;
  while (len--)
    *(dp++) = *(sp++);
  return dest;
}

char *strncpy(char *dest, const char *src, UINT32 num) {
  while (num-- && *src != '\0')
    *(dest++) = *(src++);
  while (num--)
    *(dest++) = '\0';
  return dest;
}

UINT32 strlen(const char *str) {
  UINT32 size = 0;
  while (*(str + size) != '\0') {
    ++size;
  }
  return size;
}

void do_xor(const BYTE *in1, const BYTE *in2, BYTE *out, UINT32 size) {
  for (UINT32 i = 0; i < size; i++)
    out[i] = in1[i] ^ in2[i];
}

void pad(BYTE *in, BYTE val, BYTE insize, BYTE outsize) {
  memset(in + insize, val, outsize - insize);
}

void memset(void *s, BYTE c, UINT32 len) {
  BYTE *p = s;
  for (UINT32 i = 0; i < len; i++) {
    *p = c;
    p++;
  }
}

// compares two buffers for a certain length
UINT32
memcmp(const void *buf1, const void *buf2, UINT32 size) {
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
  out_description("ERROR", status);
  for (unsigned i = 0; i < 1000; i++) {
    wait(1000);
  }
  out_string("-> OK, reboot now!\n");
  reboot();
}

/**
 * EXCEPT:
 * ERROR_NO_EXT
 * ERROR_NO_SVM
 * ERROR_NO_APIC
 *
 * Checks whether we have SVM support and a local APIC.
 *
 * @return: the SVM revision of the processor or a negative value, if
 * not supported.
 */
RESULT_(UINT32) check_cpuid(void) {
  RESULT_(UINT32) ret = {.exception.error = NONE};
  ERROR(0x8000000A > cpuid_eax(0x80000000), ERROR_NO_EXT, "no ext cpuid");
  ERROR(!(0x4 & cpuid_ecx(0x80000001)), ERROR_NO_SVM, "no SVM support");
  ERROR(!(0x200 & cpuid_edx(0x80000001)), ERROR_NO_APIC, "no APIC support");
  ret.value = cpuid_eax(0x8000000A) & 0xff;
  return ret;
}

/* EXCEPT:
 * ERROR_SVM_ENABLE
 *
 * Enables SVM support.
 */
RESULT enable_svm(void) {
  RESULT ret = {.exception.error = NONE};
  unsigned long long value;
  value = rdmsr(MSR_EFER);
  wrmsr(MSR_EFER, value | EFER_SVME);
  ERROR(!(rdmsr(MSR_EFER) & EFER_SVME), ERROR_SVM_ENABLE,
        "could not enable SVM");
  return ret;
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
 * Output a string followed by a single hex value, prefixed with a
 * message label.
 */
void out_description(const char *prefix, unsigned int value) {
  out_string(message_label);
  out_string(prefix);
  out_string(": 0x");
  out_hex(value, 0);
  out_char('\n');
}

/**
 * Output a string, prefixed with a message label.
 */
void out_info(const char *msg) {
  out_string(message_label);
  out_string(msg);
  out_char('\n');
}

/**
 * Function to output a hash.
 */
void show_hash(const char *s, TPM_DIGEST hash) {
  out_string(message_label);
  out_string(s);
  for (UINT32 i = 0; i < 20; i++)
    out_hex(hash.digest[i], 7);
  out_char('\n');
}

void fail(void) { exit(-1); }
#endif
