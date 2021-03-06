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

typedef int word; /* "word" used for optimal copy speed */

#define wsize sizeof(word)
#define wmask (wsize - 1)

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

void out_hex64(unsigned long long value) {
  int i;
  for (i = 60; i >= 0; i -= 4) {
    unsigned a = (value >> i) & 0xf;
    if (a >= 10)
      a += 7;
    a += 0x30;

    out_char(a);
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

#ifdef __ARCH_AMD__
void *memcpy(void *dest, const void *src, UINT32 len) {
  BYTE *dp = dest;
  const BYTE *sp = src;
  while (len--)
    *(dp++) = *(sp++);
  return dest;
}
#endif
#ifdef __ARCH_INTEL__
void *memcpy(void *dst0, const void *src0, size_t length) {
  char *dst;
  const char *src;
  size_t t;

  dst = dst0;
  src = src0;

  if (length == 0 || dst == src) { /* nothing to do */
    goto done;
  }

/*
 * Macros: loop-t-times; and loop-t-times, t>0
 */
#define TLOOP(s)                                                               \
  if (t)                                                                       \
  TLOOP1(s)
#define TLOOP1(s)                                                              \
  do {                                                                         \
    s;                                                                         \
  } while (--t)

  if ((unsigned long)dst < (unsigned long)src) {
    /*
     * Copy forward.
     */
    t = (int)src; /* only need low bits */

    if ((t | (int)dst) & wmask) {
      /*
       * Try to align operands.  This cannot be done
       * unless the low bits match.
       */
      if ((t ^ (int)dst) & wmask || length < wsize) {
        t = length;
      } else {
        t = wsize - (t & wmask);
      }

      length -= t;
      TLOOP1(*dst++ = *src++);
    }
    /*
     * Copy whole words, then mop up any trailing bytes.
     */
    t = length / wsize;
    TLOOP(*(word *)dst = *(const word *)src; src += wsize; dst += wsize);
    t = length & wmask;
    TLOOP(*dst++ = *src++);
  } else {
    /*
     * Copy backwards.  Otherwise essentially the same.
     * Alignment works as before, except that it takes
     * (t&wmask) bytes to align, not wsize-(t&wmask).
     */
    src += length;
    dst += length;
    t = (int)src;

    if ((t | (int)dst) & wmask) {
      if ((t ^ (int)dst) & wmask || length <= wsize) {
        t = length;
      } else {
        t &= wmask;
      }

      length -= t;
      TLOOP1(*--dst = *--src);
    }
    t = length / wsize;
    TLOOP(src -= wsize; dst -= wsize; *(word *)dst = *(const word *)src);
    t = length & wmask;
    TLOOP(*--dst = *--src);
  }
done:
  return (dst0);
}
#endif

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
 * Output a single char.
 * Note: We allow only to put a char on the last line.
 */
int out_char(unsigned value) {
#define BASE(ROW) ((unsigned short *)(0xb8000 + ROW * 160))
  static unsigned int col;

  if (value != '\n') {

    if (value == 0x08) {
      col--;
      unsigned short *p = BASE(24) + col;
      *p = 0x0f00 | ' ';
    } else {
      unsigned short *p = BASE(24) + col;
      *p = 0x0f00 | value;
      col++;
    }
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

/*
 * Output a string followed by a 64 bit hex value
 */

void out_description64(const char *prefix, unsigned long long value) {
  out_string(message_label);
  out_string(prefix);
  out_string(": 0x");
  out_hex64(value);
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

/* Find substring in string */
int indexOf(char *sub, char *str) {

  int i = -1;

  while (i++, str[i] != '\0') {
    for (int index = i, j = 0; str[i] != '\0'; j++, i++) {
      if (sub[j] == str[i] && sub[j + 1] == '\0')
        return index;
      if (sub[j] != str[i])
        break;
    }
  }

  return -1;
}

int strLen(char *str) {

  int len = 0;

  while (str[len] != '\0') {
    len++;
  }

  return len;
}

/* Find command line argument value */
char *cmdlineArgVal(char *cmdline, char *cmdlineArg) {

  char *val = cmdline;
  int index = indexOf(cmdlineArg, cmdline);
  ASSERT(index != -1);
  val += index;
  val += strLen(cmdlineArg);
  return val;
}

int aToI(char *str) {
  int ret = 0;
  while (str[0] != '\0' && str[0] != ' ') {
    //    out_char(str[0]);
    ret *= 10;
    ret += (str[0] - '0');
    str++;
  }
  return ret;
}
#endif
